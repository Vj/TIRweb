import hashlib
import json
from dataclasses import dataclass
from typing import Any
import httpx
import base64
import re
from datetime import datetime, timezone
from .models import AuthContext, ChecklistItem


INSECURE_JWT_ALGS = {"none", "hs1", "rs1", "es1", "rsa1_5"}
SYMMETRIC_JWT_ALGS = {"hs256", "hs384", "hs512"}
RISKY_HEADER_PARAMS = {"jku", "x5u", "jwk"}

SENSITIVE_CLAIM_KEYS = {
    "password",
    "passwd",
    "secret",
    "ssn",
    "aadhaar",
    "aadhar",
    "pan",
    "pan_number",
    "passport",
    "dob",
    "date_of_birth",
    "credit_card",
    "card_number",
    "cvv",
    "mobile",
    "phone",
    "phone_number",
    "address",
}

PII_VALUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Email address", re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")),
    ("Indian PAN-like identifier", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("12-digit Aadhaar-like number", re.compile(r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b")),
    ("Indian mobile number", re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")),
]

MAX_RECOMMENDED_TTL_SECONDS = 86400  # 24 hours


def _b64url_decode_json(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Decoded JWT segment is not a JSON object.")
    return data


def _scan_claims_for_pii(claims: dict[str, Any], prefix: str = "") -> list[str]:
    """Recursively check claim names and string values for sensitive PII without logging raw secrets."""
    findings: list[str] = []
    for key, value in claims.items():
        full_key = f"{prefix}.{key}" if prefix else key
        lower_key = key.lower()

        if lower_key in SENSITIVE_CLAIM_KEYS:
            findings.append(f"Sensitive claim key present: '{full_key}'")

        if isinstance(value, str):
            for label, pattern in PII_VALUE_PATTERNS:
                if pattern.search(value):
                    findings.append(f"{label} detected inside claim '{full_key}'")
        elif isinstance(value, dict):
            findings.extend(_scan_claims_for_pii(value, prefix=full_key))
    return findings


def _extract_candidate_tokens(ctx: ScanContext) -> list[tuple[str, str]]:
    """Collect bearer tokens from primary/secondary AuthContext instances."""
    candidates: list[tuple[str, str]] = []
    if ctx.primary_auth.bearer_token:
        candidates.append(("primary_auth", ctx.primary_auth.bearer_token))
    if ctx.secondary_auth and ctx.secondary_auth.bearer_token:
        candidates.append(("secondary_auth", ctx.secondary_auth.bearer_token))
    return candidates


async def probe_jwt_security(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Inspect configured JWT bearer tokens for RFC 8725 & DPDP Rules 2025 hygiene."""
    candidates = _extract_candidate_tokens(ctx)
    if not candidates:
        return True, "SKIPPED_NO_JWT: No bearer_token configured in AuthContext."

    all_issues: list[str] = []
    inspected_count = 0

    for label, token in candidates:
        parts = token.strip().split(".")
        if len(parts) == 5:
            # Encrypted JWE token (5 segments) — payload is confidential
            continue
        if len(parts) != 3:
            all_issues.append(f"[{label}] Token is not a standard 3-segment JWS or 5-segment JWE.")
            continue

        try:
            header = _b64url_decode_json(parts[0])
            payload = _b64url_decode_json(parts[1])
        except Exception as exc:
            all_issues.append(f"[{label}] Failed to decode JWT structure: {exc}")
            continue

        inspected_count += 1
        alg = str(header.get("alg", "")).strip()
        alg_lower = alg.lower()

        # 1. Algorithm checks (RFC 8725 Section 3.1 / 3.2)
        if not alg or alg_lower in INSECURE_JWT_ALGS:
            all_issues.append(f"[{label}] Insecure or missing signing algorithm: alg='{alg or 'MISSING'}'.")
        elif alg_lower in SYMMETRIC_JWT_ALGS:
            all_issues.append(
                f"[{label}] Symmetric algorithm '{alg}' used; prefer asymmetric RS256/ES256/EdDSA for distributed verification."
            )

        # 2. Risky header parameters (jku, x5u, embedded jwk)
        present_risky_headers = RISKY_HEADER_PARAMS.intersection({k.lower() for k in header})
        if present_risky_headers:
            all_issues.append(
                f"[{label}] Untrusted key-location header parameter(s) present: {', '.join(sorted(present_risky_headers))}."
            )

        # 3. Expiration & lifetime checks
        exp = payload.get("exp")
        iat = payload.get("iat")
        if exp is None:
            all_issues.append(f"[{label}] Missing 'exp' (expiration) claim — token never expires.")
        elif isinstance(exp, (int, float)):
            now_ts = datetime.now(timezone.utc).timestamp()
            if exp <= now_ts:
                all_issues.append(f"[{label}] Token is already expired (exp={int(exp)}).")
            if isinstance(iat, (int, float)) and (exp - iat) > MAX_RECOMMENDED_TTL_SECONDS:
                ttl_hours = round((exp - iat) / 3600, 1)
                all_issues.append(
                    f"[{label}] Excessive token lifetime ({ttl_hours}h > 24h recommended maximum)."
                )

        # 4. Audience & Issuer context checks
        if "aud" not in payload:
            all_issues.append(f"[{label}] Missing 'aud' (audience) claim (cross-service token confusion risk).")
        if "iss" not in payload:
            all_issues.append(f"[{label}] Missing 'iss' (issuer) claim.")

        # 5. Unencrypted PII / Secret exposure check (DPDP Rules 2025 Rule 6(1)(a))
        pii_findings = _scan_claims_for_pii(payload)
        for finding in pii_findings:
            all_issues.append(f"[{label}] {finding} in unencrypted JWS payload.")

    if all_issues:
        return False, "JWT security findings:\n- " + "\n- ".join(all_issues)
    return True, f"JWT inspection passed ({inspected_count} JWS token(s) verified clean)."


REQUIRED_SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS missing (enforce max-age >= 31536000)",
    "content-security-policy": "Content-Security-Policy (CSP) header missing",
    "x-content-type-options": "X-Content-Type-Options: nosniff missing",
    "x-frame-options": "X-Frame-Options (or CSP frame-ancestors) missing",
    "referrer-policy": "Referrer-Policy header missing",
    "permissions-policy": "Permissions-Policy header missing",
}

SENSITIVE_HEADER_LEAKS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


@dataclass
class ScanContext:
    primary_auth: AuthContext
    secondary_auth: AuthContext | None = None
    probe_endpoints: list[str] | None = None
    timeout: float = 15.0
    verify_tls: bool = True


async def probe_security_headers(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Verify presence of defensive HTTP response headers and absence of stack version leaks."""
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        resp = await client.get(target)

    headers = {k.lower(): v for k, v in resp.headers.items()}
    issues: list[str] = []

    for header_name, failure_msg in REQUIRED_SECURITY_HEADERS.items():
        if header_name == "x-frame-options" and "frame-ancestors" in headers.get(
            "content-security-policy", ""
        ):
            continue
        if header_name not in headers:
            issues.append(failure_msg)

    if headers.get("x-content-type-options", "").lower() != "nosniff" and "x-content-type-options" in headers:
        issues.append(f"X-Content-Type-Options misconfigured: {headers['x-content-type-options']}")

    for leak_hdr in SENSITIVE_HEADER_LEAKS:
        if leak_hdr in headers:
            issues.append(f"Version/stack disclosure header present: {leak_hdr}={headers[leak_hdr]}")

    if issues:
        return False, "Header audit findings:\n- " + "\n- ".join(issues)
    return True, f"All baseline security headers verified on {resp.url} (HTTP {resp.status_code})."


async def probe_cors_policy(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Test whether the endpoint reflects untrusted Origin headers with credentials enabled."""
    canary_origin = "https://untrusted-origin-audit.example.invalid"
    req_headers = ctx.primary_auth.to_http_headers()
    req_headers["Origin"] = canary_origin

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=req_headers,
    ) as client:
        resp = await client.options(target)
        if resp.status_code >= 400:
            resp = await client.get(target)

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()

    issues: list[str] = []
    if acao == canary_origin:
        severity_note = "with Access-Control-Allow-Credentials: true" if acac == "true" else "(uncredentialed)"
        issues.append(f"Arbitrary Origin reflected in Access-Control-Allow-Origin {severity_note}.")
    elif acao == "*" and ctx.primary_auth.is_authenticated:
        issues.append("Wildcard Access-Control-Allow-Origin: * returned on authenticated endpoint.")

    if issues:
        return False, "CORS misconfiguration detected:\n- " + "\n- ".join(issues)
    return True, f"CORS policy safe (ACAO='{acao or 'none'}', ACAC='{acac or 'none'}')."


def _extract_structural_shape(payload: Any) -> Any:
    """Reduce JSON payloads to schema key structures (stripping PII/values) for safe comparison."""
    if isinstance(payload, dict):
        return {k: _extract_structural_shape(v) for k, v in sorted(payload.items())}
    if isinstance(payload, list):
        return [_extract_structural_shape(payload[0])] if payload else []
    return type(payload).__name__


async def probe_differential_idor(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Compare HTTP status and structural JSON response shapes across two AuthContext sessions."""
    if not ctx.secondary_auth or not ctx.secondary_auth.is_authenticated:
        return True, "SKIPPED_SECONDARY_AUTH: Provide --secondary-auth-file to run differential IDOR comparison."

    endpoints = ctx.probe_endpoints or [target]
    flagged: list[str] = []

    async with httpx.AsyncClient(timeout=ctx.timeout, verify=ctx.verify_tls, follow_redirects=False) as client:
        for endpoint in endpoints:
            url = endpoint if endpoint.startswith("http") else f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
            resp_a = await client.get(url, headers=ctx.primary_auth.to_http_headers())
            resp_b = await client.get(url, headers=ctx.secondary_auth.to_http_headers())

            # If User A receives 200 OK and User B (different principal) also receives 200 OK
            # with an identical structural schema/digest on a user-scoped resource, flag for review
            if resp_a.status_code == 200 and resp_b.status_code == 200:
                digest_a = hashlib.sha256(resp_a.content).hexdigest()
                digest_b = hashlib.sha256(resp_b.content).hexdigest()

                try:
                    shape_a = _extract_structural_shape(resp_a.json())
                    shape_b = _extract_structural_shape(resp_b.json())
                    same_schema = json.dumps(shape_a) == json.dumps(shape_b)
                except ValueError:
                    same_schema = False

                if digest_a == digest_b or same_schema:
                    flagged.append(
                        f"{url}: Both Token A and Token B received HTTP 200 with matching "
                        f"{'byte digest' if digest_a == digest_b else 'JSON schema'}."
                    )

    if flagged:
        return False, "Potential cross-user access control parity detected:\n- " + "\n- ".join(flagged)
    return True, f"Differential access check passed across {len(endpoints)} endpoint(s) (Token B properly isolated)."