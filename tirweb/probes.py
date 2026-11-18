import hashlib
import json
from dataclasses import dataclass
from typing import Any
import httpx
import base64
import re
from datetime import datetime, timezone
from .models import AuthContext, ChecklistItem
from urllib.parse import urljoin, urlparse


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


async def probe_metafiles_and_ria_policies(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """
    WSTG-INFO-03 & WSTG-CONF-08: Inspect robots.txt, sitemap.xml, security.txt,
    and legacy RIA cross-domain policies (crossdomain.xml / clientaccesspolicy.xml).
    """
    sensitive_keywords = ("/admin", "/internal", "/backup", "/config", "/.git", "/.env", "/swagger", "/actuator")
    issues: list[str] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        # 1. Check robots.txt & sitemap.xml for sensitive disallowed/listed paths
        for meta_path in ("/robots.txt", "/sitemap.xml"):
            resp = await client.get(urljoin(target, meta_path))
            if resp.status_code == 200 and resp.text:
                lower_body = resp.text.lower()
                leaked = [kw for kw in sensitive_keywords if kw in lower_body]
                if leaked:
                    issues.append(f"{meta_path} discloses sensitive path patterns: {', '.join(leaked)}")

        # 2. Check legacy RIA cross-domain XML policies for wildcard '*' access
        for ria_path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
            resp = await client.get(urljoin(target, ria_path))
            if resp.status_code == 200 and ("domain=\"*\"" in resp.text or "uri=\"*\"" in resp.text):
                issues.append(f"{ria_path} allows wildcard '*' cross-domain access.")

    if issues:
        return False, "Metafile / RIA policy findings:\n- " + "\n- ".join(issues)
    return True, "Metafiles (robots.txt/sitemap.xml) and RIA cross-domain policies verified clean."


async def probe_path_confusion(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """
    WSTG-CONF-13: Test path normalization discrepancies (/admin/..;/, double slashes, case variations)
    on protected paths to detect reverse-proxy/WAF ACL bypasses.
    """
    protected_candidates = ctx.probe_endpoints or ["/admin", "/api/admin"]
    bypass_findings: list[str] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        for base_path in protected_candidates:
            clean_path = "/" + base_path.lstrip("/")
            base_url = urljoin(target, clean_path)
            baseline = await client.get(base_url)

            # Only test path confusion if the canonical endpoint is restricted (401/403)
            if baseline.status_code not in {401, 403}:
                continue

            variants = [
                f"{clean_path}/..;/",
                f"{clean_path}..%2f",
                f"/{clean_path}",
                clean_path.upper(),
            ]
            for variant in variants:
                variant_url = f"{target.rstrip('/')}{variant}"
                resp = await client.get(variant_url)
                if resp.status_code == 200:
                    bypass_findings.append(
                        f"Canonical '{clean_path}' returned {baseline.status_code}, but variant '{variant}' returned HTTP 200."
                    )

    if bypass_findings:
        return False, "Path confusion ACL bypass detected:\n- " + "\n- ".join(bypass_findings)
    return True, "Path normalization & confusion checks passed (consistent ACL enforcement)."


async def probe_open_redirect(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """
    WSTG-CLNT-04: Test common redirect parameters for unvalidated external Location headers.
    """
    canary_domain = "untrusted-redirect-audit.example.invalid"
    canary_url = f"https://{canary_domain}/phish"
    redirect_params = ("next", "url", "redirect", "redirect_uri", "returnTo", "dest")
    vulnerable_params: list[str] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        for param in redirect_params:
            resp = await client.get(target, params={param: canary_url})
            if resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("location", "")
                parsed_loc = urlparse(location)
                if parsed_loc.netloc == canary_domain or location.startswith(f"//{canary_domain}"):
                    vulnerable_params.append(f"?{param}={canary_url} -> Location: {location}")

    if vulnerable_params:
        return False, "Open redirect vulnerability detected:\n- " + "\n- ".join(vulnerable_params)
    return True, "Open redirect parameter checks passed (no external Location reflection)."


async def probe_api_authentication(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Record endpoint authentication evidence without inferring vulnerabilities."""
    if not ctx.probe_endpoints:
        return True, (
            "SKIPPED_NO_ENDPOINTS: Configure one or more in-scope "
            "--endpoint values to assess API authentication."
        )

    auth_headers = ctx.primary_auth.to_http_headers()
    has_auth_context = ctx.primary_auth.is_authenticated
    observations: list[str] = []
    inconclusive = False

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        for endpoint in ctx.probe_endpoints:
            url = resolve_endpoint(target, endpoint)
            parsed = urlparse(url)
            display_url = urlunparse(parsed._replace(query="", fragment=""))

            try:
                # Deliberately send no credentials in the first request.
                unauth = await client.get(url)
                unauth_outcome = _http_access_outcome(unauth)

                if not has_auth_context:
                    inconclusive = True
                    observations.append(
                        f"{display_url}: unauthenticated={unauth.status_code}/"
                        f"{unauth_outcome}; authenticated comparison unavailable "
                        "because no primary credentials were configured."
                    )
                    continue

                authenticated = await client.get(url, headers=auth_headers)
                auth_outcome = _http_access_outcome(authenticated)

                if (
                    unauth.status_code == 401
                    and 200 <= authenticated.status_code < 300
                ):
                    observations.append(
                        f"{display_url}: unauthenticated=401/"
                        f"{unauth_outcome}; authenticated="
                        f"{authenticated.status_code}/{auth_outcome}; "
                        "authentication requirement observed for this request."
                    )
                else:
                    inconclusive = True
                    observations.append(
                        f"{display_url}: unauthenticated={unauth.status_code}/"
                        f"{unauth_outcome}; authenticated="
                        f"{authenticated.status_code}/{auth_outcome}; "
                        "authentication policy or endpoint behavior requires review."
                    )

            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                inconclusive = True
                observations.append(
                    f"{display_url}: request failed ({type(exc).__name__}); "
                    "authentication outcome is unknown."
                )

    prefix = "INCONCLUSIVE_API_AUTH" if inconclusive else "API_AUTH_OBSERVATION"
    return True, (
        f"{prefix}: Assessed {len(observations)} configured endpoint(s). "
        "HTTP status observations alone do not establish a vulnerability. "
        "Response bodies and credential values are not included in evidence.\n- "
        + "\n- ".join(observations)
    )

async def probe_differential_idor(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Compare HTTP status and structural JSON response shapes across two AuthContext sessions."""
    if not ctx.primary_auth.is_authenticated:
        return True, (
            "SKIPPED_PRIMARY_AUTH: Configure a primary test identity "
            "before running differential access comparison."
        )
        
    if not ctx.secondary_auth or not ctx.secondary_auth.is_authenticated:
        return True, (
            "SKIPPED_SECONDARY_AUTH: Provide --secondary-auth-file "
            "with a second test identity."
        )

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

GRAPHQL_DEFAULT_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/console")


async def probe_graphql_security(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """
    WSTG-APIT-01: Test GraphQL endpoints for enabled __schema introspection,
    field suggestion leakage, and unrestricted query batching / alias amplification.
    """
    candidate_paths: list[str] = list(GRAPHQL_DEFAULT_PATHS)
    if ctx.probe_endpoints:
        for ep in ctx.probe_endpoints:
            if "graphql" in ep.lower() and ep not in candidate_paths:
                candidate_paths.insert(0, ep)

    introspection_query = {"query": "{__schema{queryType{name}types{name}}}"}
    batch_payload = [
        {"query": "{__typename}"},
        {"query": "{__typename}"},
        {"query": "{__typename}"},
        {"query": "{__typename}"},
        {"query": "{__typename}"},
    ]

    discovered_endpoints: list[str] = []
    issues: list[str] = []

    headers = {
        **ctx.primary_auth.to_http_headers(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=headers,
    ) as client:
        for path in candidate_paths:
            gql_url = urljoin(target, path)

            # 1. Test Schema Introspection (__schema)
            try:
                resp = await client.post(gql_url, json=introspection_query)
            except httpx.HTTPError:
                continue

            if resp.status_code == 200:
                try:
                    body = resp.json()
                except ValueError:
                    continue

                if isinstance(body, dict) and ("data" in body or "errors" in body):
                    discovered_endpoints.append(path)
                    data_obj = body.get("data")
                    if isinstance(data_obj, dict) and data_obj.get("__schema"):
                        issues.append(
                            f"[{path}] GraphQL schema introspection (__schema) is enabled in response."
                        )

                    # 2. Test Query Batching Abuse (Array of operations in single HTTP POST)
                    try:
                        batch_resp = await client.post(gql_url, json=batch_payload)
                        if batch_resp.status_code == 200:
                            batch_body = batch_resp.json()
                            if (
                                isinstance(batch_body, list)
                                and len(batch_body) == len(batch_payload)
                                and all(
                                    isinstance(item, dict) and "data" in item
                                    for item in batch_body
                                )
                            ):
                                issues.append(
                                    f"[{path}] Unauthenticated/unthrottled GraphQL query batching allowed ({len(batch_payload)} batched operations executed)."
                                )
                    except (httpx.HTTPError, ValueError):
                        pass

    if issues:
        return False, "GraphQL security findings:\n- " + "\n- ".join(issues)
    if discovered_endpoints:
        return (
            True,
            f"GraphQL endpoint(s) verified ({', '.join(discovered_endpoints)}): introspection disabled and query batching restricted.",
        )
    return True, "No exposed GraphQL endpoints detected at standard paths (/graphql, /api/graphql)."
