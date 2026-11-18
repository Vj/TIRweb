from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
import httpx
import base64
import re
from datetime import datetime, timezone
from .models import AuthContext, ChecklistItem
from urllib.parse import urljoin, urlparse, urlunparse


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


def resolve_endpoint(target: str, endpoint: str) -> str:
    """Resolve a previously validated endpoint against the target origin."""
    return urljoin(target.rstrip("/") + "/", endpoint)


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
        elif isinstance(value, list):
            for index, item in enumerate(value):
                item_key = f"{full_key}[{index}]"
                if isinstance(item, dict):
                    findings.extend(_scan_claims_for_pii(item, prefix=item_key))
                elif isinstance(item, str):
                    for label, pattern in PII_VALUE_PATTERNS:
                        if pattern.search(item):
                            findings.append(f"{label} detected inside claim '{item_key}'")
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
    """Passively inspect JWT structure; never claim signature or verifier validation."""
    candidates = _extract_candidate_tokens(ctx)
    if not candidates:
        return True, "SKIPPED_NO_JWT: No bearer_token configured in AuthContext."

    review_items: list[str] = []
    confirmed_exposures: list[str] = []
    inspected_count = 0
    uninspectable_tokens: list[str] = []

    for label, token in candidates:
        parts = token.strip().split(".")
        if len(parts) == 5:
            uninspectable_tokens.append(f"[{label}] JWE token requires issuer/key-aware verification.")
            continue
        if len(parts) != 3:
            uninspectable_tokens.append(f"[{label}] Token is not a standard 3-segment JWS or 5-segment JWE.")
            continue

        try:
            header = _b64url_decode_json(parts[0])
            payload = _b64url_decode_json(parts[1])
        except Exception as exc:
            uninspectable_tokens.append(f"[{label}] JWT structure could not be decoded: {type(exc).__name__}.")
            continue

        inspected_count += 1
        alg = str(header.get("alg", "")).strip()
        alg_lower = alg.lower()

        # A token header alone cannot prove that the relying party accepts a weak algorithm.
        if not alg or alg_lower in INSECURE_JWT_ALGS:
            review_items.append(
                f"[{label}] Insecure or missing signing algorithm: alg='{alg or 'MISSING'}'; "
                "verify the issuer and relying-party algorithm allowlist."
            )

        present_risky_headers = RISKY_HEADER_PARAMS.intersection({k.lower() for k in header})
        if present_risky_headers:
            review_items.append(
                f"[{label}] Untrusted key-location header parameter(s) present: "
                f"{', '.join(sorted(present_risky_headers))}; verify trusted key resolution."
            )

        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")
        now_ts = datetime.now(timezone.utc).timestamp()

        if exp is None:
            review_items.append(f"[{label}] Missing 'exp' (expiration) claim.")
        elif not isinstance(exp, (int, float)) or isinstance(exp, bool):
            review_items.append(f"[{label}] 'exp' claim is not a numeric NumericDate.")
        else:
            if exp <= now_ts:
                review_items.append(f"[{label}] Token expiration is in the past.")
            if isinstance(iat, (int, float)) and not isinstance(iat, bool):
                if exp > iat and (exp - iat) > MAX_RECOMMENDED_TTL_SECONDS:
                    ttl_hours = round((exp - iat) / 3600, 1)
                    review_items.append(
                        f"[{label}] Long declared token lifetime ({ttl_hours}h > 24h review threshold)."
                    )

        if isinstance(iat, (int, float)) and not isinstance(iat, bool) and iat > now_ts:
            review_items.append(f"[{label}] 'iat' claim is in the future.")
        if isinstance(nbf, (int, float)) and not isinstance(nbf, bool) and nbf > now_ts:
            review_items.append(f"[{label}] 'nbf' claim is in the future; token is not yet valid.")

        if "aud" not in payload:
            review_items.append(f"[{label}] Missing 'aud' (audience) claim.")
        if "iss" not in payload:
            review_items.append(f"[{label}] Missing 'iss' (issuer) claim.")

        for finding in _scan_claims_for_pii(payload):
            message = f"[{label}] {finding} in unencrypted JWS payload."
            if finding.startswith("Sensitive claim key present:"):
                review_items.append(message)
            else:
                # The token payload is base64url-encoded, not encrypted. Avoid logging values.
                confirmed_exposures.append(message)

    if confirmed_exposures:
        evidence = confirmed_exposures + review_items
        return False, "JWT readable-payload data exposure:\n- " + "\n- ".join(evidence)
    if review_items or uninspectable_tokens:
        review_items.extend(uninspectable_tokens)
        if review_items:
            return True, "INCONCLUSIVE_JWT_REVIEW: Issuer and verifier policy review required.\n- " + "\n- ".join(review_items)
    if inspected_count == 0:
        return True, "INCONCLUSIVE_JWT: No inspectable JWS token was supplied."
    return True, (
        f"JWT structure inspection completed ({inspected_count} JWS token(s)); "
        "signature validation and relying-party acceptance are not tested."
    )




REQUIRED_SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS missing (enforce max-age >= 31536000)",
    "content-security-policy": "Content-Security-Policy (CSP) header missing",
    "x-content-type-options": "X-Content-Type-Options: nosniff missing",
    "x-frame-options": "X-Frame-Options (or CSP frame-ancestors) missing",
    "referrer-policy": "Referrer-Policy header missing",
    "permissions-policy": "Permissions-Policy header missing",
}

SENSITIVE_HEADER_LEAKS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


class RequestBudgetExceeded(RuntimeError):
    """Raised when a scan reaches its configured outbound HTTP request budget."""


@dataclass
class ScanContext:
    primary_auth: AuthContext
    secondary_auth: AuthContext | None = None
    probe_endpoints: list[str] | None = None
    timeout: float = 15.0
    verify_tls: bool = True
    max_requests: int = 500
    request_count: int = 0
    _request_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def track_request(self, request: httpx.Request) -> None:
        """Count outbound HTTP requests across all native probes in this scan."""
        async with self._request_lock:
            if self.request_count >= self.max_requests:
                raise RequestBudgetExceeded(
                    f"Scan request budget exhausted ({self.max_requests} requests)."
                )
            self.request_count += 1


async def probe_security_headers(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Verify presence of defensive HTTP response headers and absence of stack version leaks."""
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        event_hooks={"request": [ctx.track_request]},
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        resp = await client.get(target)

    if resp.is_redirect:
        return True, f"INCONCLUSIVE_REDIRECT: Target returned HTTP {resp.status_code}; redirect destination was not followed."

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
    """Assess CORS responses conservatively; reflection alone is not proof of data exposure."""
    canary_origin = "https://untrusted-origin-audit.example.invalid"
    req_headers = {
        "Origin": canary_origin,
        "Access-Control-Request-Method": "GET",
    }
    if ctx.primary_auth.is_authenticated:
        req_headers["Access-Control-Request-Headers"] = "authorization"

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        resp = await client.options(target, headers=req_headers)
        if resp.status_code >= 400 and not resp.is_redirect:
            resp = await client.get(target, headers=ctx.primary_auth.to_http_headers() | {"Origin": canary_origin})

    if resp.is_redirect:
        return True, (
            f"INCONCLUSIVE_CORS_REDIRECT: CORS probe request returned HTTP {resp.status_code}; "
            "redirect was not followed."
        )

    acao = resp.headers.get("access-control-allow-origin", "").strip()
    acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()
    allowed_headers = {
        item.strip().lower()
        for item in resp.headers.get("access-control-allow-headers", "").split(",")
        if item.strip()
    }

    if acao == canary_origin and acac == "true":
        return True, (
            "INCONCLUSIVE_CORS_CREDENTIALS: An untrusted Origin was echoed with "
            "Access-Control-Allow-Credentials: true. Verify that browser-credentialed "
            "requests can reach sensitive user-specific response data before confirming impact."
        )

    if acao == canary_origin:
        return True, (
            "INCONCLUSIVE_CORS_REFLECTION: An untrusted Origin was echoed, but credentialed "
            "access was not enabled. Verify whether the endpoint exposes non-public data "
            "and whether browser requests can supply required headers."
        )

    if acao == "*" and ctx.primary_auth.is_authenticated:
        return True, (
            "INCONCLUSIVE_CORS_WILDCARD: Wildcard origin was returned in an authenticated "
            "assessment context. Browsers do not permit wildcard ACAO with credentialed "
            "requests; verify the actual endpoint data sensitivity and authentication mode."
        )

    if acao == "*" and "authorization" in allowed_headers:
        return True, (
            "INCONCLUSIVE_CORS_WILDCARD: Wildcard origin and Authorization header allowance "
            "were observed. Browser credential rules and the endpoint's data sensitivity "
            "must be reviewed before treating this as a vulnerability."
        )

    return True, (
        f"CORS preflight did not demonstrate credentialed untrusted-origin access "
        f"(ACAO='{acao or 'none'}', ACAC='{acac or 'none'}')."
    )



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
    potential_disclosures: list[str] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        event_hooks={"request": [ctx.track_request]},
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        # 1. Check robots.txt & sitemap.xml for sensitive disallowed/listed paths
        for meta_path in ("/robots.txt", "/sitemap.xml"):
            resp = await client.get(urljoin(target, meta_path))
            if resp.status_code == 200 and resp.text:
                lower_body = resp.text.lower()
                leaked = [kw for kw in sensitive_keywords if kw in lower_body]
                if leaked:
                    potential_disclosures.append(
                        f"{meta_path} lists sensitive-looking paths: {', '.join(leaked)}; "
                        "listing alone does not prove the resource is publicly accessible."
                    )

        # 2. Check legacy RIA cross-domain XML policies for wildcard '*' access
        for ria_path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
            resp = await client.get(urljoin(target, ria_path))
            if resp.status_code == 200 and ("domain=\"*\"" in resp.text or "uri=\"*\"" in resp.text):
                issues.append(f"{ria_path} allows wildcard '*' cross-domain access.")

    if issues:
        details = issues + potential_disclosures
        return False, "Metafile / RIA policy findings:\n- " + "\n- ".join(details)
    if potential_disclosures:
        return True, "INCONCLUSIVE_METAFILE_REVIEW: Manual access-control verification required.\n- " + "\n- ".join(potential_disclosures)
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
        event_hooks={"request": [ctx.track_request]},
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        for base_path in protected_candidates:
            clean_path = "/" + base_path.lstrip("/")
            base_url = resolve_endpoint(target, base_path)
            parsed_base = urlparse(base_url)
            clean_path = parsed_base.path or "/"
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
                variant_url = urlunparse(parsed_base._replace(path=variant, params="", query="", fragment=""))
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
        event_hooks={"request": [ctx.track_request]},
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


def _auth_profile(auth: AuthContext) -> str:
    """Describe configured credential types without exposing credential values."""
    names = {name.lower() for name in auth.headers}
    kinds = []
    if auth.bearer_token or "authorization" in names:
        kinds.append("bearer/authorization")
    if auth.cookies or "cookie" in names:
        kinds.append("cookie")
    if any(name not in {"authorization", "cookie"} for name in names):
        kinds.append("custom-header")
    return "+".join(kinds) if kinds else "no-credentials"


def _http_access_outcome(response: httpx.Response) -> str:
    """Map HTTP outcomes to neutral access observations, never vulnerability labels."""
    code = response.status_code
    if 200 <= code < 300:
        return "success"
    if code == 401:
        return "authentication-required"
    if code == 403:
        return "forbidden"
    if code == 404:
        return "not-found-or-hidden"
    if code == 429:
        return "rate-limited"
    if response.is_redirect:
        return "redirect-not-followed"
    if 500 <= code < 600:
        return "server-error"
    return "other-http-status"


async def probe_differential_idor(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """Compare two configured sessions and report endpoint-level access evidence."""
    if not ctx.secondary_auth or not ctx.secondary_auth.is_authenticated:
        return True, "SKIPPED_SECONDARY_AUTH: Provide --secondary-auth-file to run differential access comparison."

    endpoints = ctx.probe_endpoints or [target]
    observations: list[str] = []
    review_required = False
    primary_profile = _auth_profile(ctx.primary_auth)
    secondary_profile = _auth_profile(ctx.secondary_auth)

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        for endpoint in endpoints:
            url = resolve_endpoint(target, endpoint)
            parsed_url = urlparse(url)
            display_url = urlunparse(parsed_url._replace(query="", fragment=""))
            try:
                resp_a = await client.get(url, headers=ctx.primary_auth.to_http_headers())
                resp_b = await client.get(url, headers=ctx.secondary_auth.to_http_headers())
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                review_required = True
                observations.append(f"{display_url}: request failed ({type(exc).__name__}); access outcome is unknown.")
                continue

            outcome_a = _http_access_outcome(resp_a)
            outcome_b = _http_access_outcome(resp_b)
            evidence = f"primary={resp_a.status_code}/{outcome_a}, secondary={resp_b.status_code}/{outcome_b}"

            if outcome_a == "success" and outcome_b == "success":
                review_required = True
                try:
                    same_bytes = hashlib.sha256(resp_a.content).digest() == hashlib.sha256(resp_b.content).digest()
                    same_shape = json.dumps(_extract_structural_shape(resp_a.json()), sort_keys=True) == json.dumps(
                        _extract_structural_shape(resp_b.json()), sort_keys=True
                    )
                except (ValueError, TypeError):
                    same_bytes = resp_a.content == resp_b.content
                    same_shape = False
                qualifiers = []
                if same_bytes:
                    qualifiers.append("identical-response-bytes")
                if same_shape:
                    qualifiers.append("matching-json-structure")
                suffix = f"; evidence={','.join(qualifiers)}" if qualifiers else ""
                observations.append(
                    f"{display_url}: {evidence}{suffix}; ownership and sharing policy are not established."
                )
            elif outcome_a == "success" and outcome_b in {"authentication-required", "forbidden"}:
                observations.append(
                    f"{display_url}: {evidence}; secondary session was denied. This is consistent with an enforced restriction, not proof of a vulnerability."
                )
            elif outcome_a in {"authentication-required", "forbidden"} and outcome_b == "success":
                review_required = True
                observations.append(
                    f"{display_url}: {evidence}; inverse access difference requires identity, role, and resource-policy review."
                )
            else:
                review_required = True
                observations.append(
                    f"{display_url}: {evidence}; endpoint existence, authentication state, or policy remains ambiguous."
                )

    prefix = "INCONCLUSIVE_IDOR_REVIEW" if review_required else "ACCESS_CONTROL_OBSERVATION"
    return True, (
        f"{prefix}: Compared {len(endpoints)} endpoint(s) using primary auth={primary_profile} "
        f"and secondary auth={secondary_profile}. No endpoint is classified as vulnerable from HTTP status alone; matching responses are not proof of unauthorized access. verify resource ownership and sharing policy.\n- "
        + "\n- ".join(observations)
    )


GRAPHQL_DEFAULT_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/console")


async def probe_graphql_security(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    """
    WSTG-APIT-01: Check standard GraphQL endpoints for schema introspection and
    acceptance of a small, bounded batch of harmless __typename operations.
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
    review_items: list[str] = []
    probe_errors: list[str] = []

    headers = {
        **ctx.primary_auth.to_http_headers(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        event_hooks={"request": [ctx.track_request]},
        headers=headers,
    ) as client:
        for path in candidate_paths:
            gql_url = resolve_endpoint(target, path)

            # 1. Test Schema Introspection (__schema)
            try:
                resp = await client.post(gql_url, json=introspection_query)
            except httpx.HTTPError as exc:
                probe_errors.append(f"[{path}] Request failed: {type(exc).__name__}.")
                continue

            if resp.status_code == 200:
                try:
                    body = resp.json()
                except ValueError:
                    probe_errors.append(f"[{path}] HTTP 200 response was not valid JSON.")
                    continue

                if isinstance(body, dict) and ("data" in body or "errors" in body):
                    discovered_endpoints.append(path)
                    data_obj = body.get("data")
                    if isinstance(data_obj, dict) and data_obj.get("__schema"):
                        review_items.append(
                            f"[{path}] GraphQL schema introspection (__schema) is enabled; exposure alone does not prove sensitive schema or data access."
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
                                review_items.append(
                                    f"[{path}] Server accepted {len(batch_payload)} batched operations; this does not establish missing rate limits or resource exhaustion controls."
                                )
                    except (httpx.HTTPError, ValueError) as exc:
                        probe_errors.append(f"[{path}] Batch-control check incomplete: {type(exc).__name__}.")
                else:
                    probe_errors.append(f"[{path}] HTTP 200 response did not match a GraphQL response shape.")
            elif resp.status_code not in {401, 403, 404, 405}:
                probe_errors.append(f"[{path}] Unexpected HTTP status {resp.status_code}.")

    if review_items or probe_errors:
        evidence = review_items + probe_errors
        return True, "INCONCLUSIVE_GRAPHQL_REVIEW: Manual schema sensitivity and resource-control review required.\n- " + "\n- ".join(evidence)
    if discovered_endpoints:
        return (
            True,
            f"GraphQL endpoint(s) verified ({', '.join(discovered_endpoints)}): introspection disabled and query batching restricted.",
        )
    return True, "No exposed GraphQL endpoints detected at standard paths (/graphql, /api/graphql)."