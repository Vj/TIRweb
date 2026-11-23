import asyncio
import base64
import hashlib
import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import httpx
from .models import AuthContext, ChecklistItem, ProbeFinding, ProbeOutcome


# Add allow_default_creds field to ScanContext:
@dataclass
class ScanContext:
    primary_auth: AuthContext
    secondary_auth: AuthContext | None = None
    probe_endpoints: list[str] | None = None
    timeout: float = 15.0
    verify_tls: bool = True
    max_requests: int = 500
    request_count: int = 0
    allow_default_creds: bool = False
    _listeners: list[Callable[[httpx.Request], Any]] = field(default_factory=list)

    async def track_request(self, request: httpx.Request) -> None:
        self.request_count += 1
        if self.request_count > self.max_requests:
            raise RuntimeError(f"Request budget exhausted ({self.max_requests} max requests).")


def resolve_endpoint(target: str, endpoint: str) -> str:
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    return f"{target.rstrip('/')}/{endpoint.lstrip('/')}"


def _http_access_outcome(resp: httpx.Response) -> str:
    code = resp.status_code
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
    if 300 <= code < 400:
        return "redirect-not-followed"
    if code >= 500:
        return "server-error"
    return "other"


# ==============================================================================
# 1. NATIVE TLS / HTTPS & HSTS PROBE (WSTG-CRYP-01, WSTG-CONF-07)
# ==============================================================================

async def probe_tls_and_https(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Detect cleartext HTTP targets, missing HTTP->HTTPS redirects, legacy TLS, and HSTS."""
    parsed = urlparse(target)
    host = parsed.hostname or ""
    findings: list[ProbeFinding] = []
    notes: list[str] = []

    if parsed.scheme.lower() == "http":
        findings.append(
            ProbeFinding(
                rule_id=f"{check.id}:httpx_tls:cleartext_target",
                title="Target Configured Over Cleartext HTTP (No TLS)",
                severity="High",
                evidence=f"Target URL '{target}' uses unencrypted 'http://' transport.",
                remediation="Enforce HTTPS (TLS 1.2/1.3) across all endpoints and redirect HTTP (port 80) to HTTPS (port 443).",
                cwe="CWE-319",
            )
        )
        # Check whether HTTP redirects to HTTPS
        try:
            async with httpx.AsyncClient(
                timeout=ctx.timeout, verify=False, follow_redirects=False
            ) as client:
                resp = await client.get(target)
                loc = resp.headers.get("location", "")
                if not (resp.status_code in {301, 302, 307, 308} and loc.lower().startswith("https://")):
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_tls:no_https_redirect",
                            title="Missing Automatic HTTP-to-HTTPS Redirect",
                            severity="Medium",
                            evidence=f"GET {target} returned HTTP {resp.status_code} (Location: '{loc or 'none'}').",
                            remediation="Configure a permanent 301/308 redirect from HTTP to HTTPS.",
                            cwe="CWE-319",
                        )
                    )
        except httpx.HTTPError as exc:
            notes.append(f"HTTP probe error: {exc}")

        notes.append("HSTS evaluation skipped: HSTS headers are ignored by browsers over cleartext HTTP.")
        return ProbeOutcome(
            findings=findings,
            summary="Cleartext HTTP transport detected; HSTS skipped over non-TLS origin. " + " ".join(notes),
            conclusive=True,
        )

    # Target uses HTTPS: inspect TLS version, cipher & HSTS
    tls_port = parsed.port or 443
    try:
        ssl_ctx = ssl.create_default_context()
        if not ctx.verify_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, tls_port), timeout=ctx.timeout) as raw_sock:
            with ssl_ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                proto = tls_sock.version() or "unknown"
                cipher_info = tls_sock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "unknown"
                notes.append(f"Negotiated {proto} ({cipher_name}).")
                if proto in {"TLSv1", "TLSv1.1", "SSLv3"}:
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_tls:legacy_protocol",
                            title=f"Deprecated TLS Protocol Negotiated ({proto})",
                            severity="High",
                            evidence=f"{host}:{tls_port} negotiated {proto} with cipher {cipher_name}.",
                            remediation="Disable SSLv3, TLS 1.0, and TLS 1.1; allow only TLS 1.2 and TLS 1.3.",
                            cwe="CWE-326",
                        )
                    )
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            ProbeFinding(
                rule_id=f"{check.id}:httpx_tls:invalid_cert",
                title="Invalid or Untrusted TLS Certificate",
                severity="High",
                evidence=f"TLS certificate verification failed for {host}:{tls_port}: {exc}",
                remediation="Install a valid, trusted CA-signed X.509 certificate matching the target hostname.",
                cwe="CWE-295",
            )
        )
    except OSError as exc:
        return ProbeOutcome(
            findings=[],
            summary=f"INCONCLUSIVE_TLS: Could not complete TLS handshake with {host}:{tls_port} ({exc}).",
            conclusive=False,
        )

    # Check HSTS on HTTPS response
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        resp = await client.get(target)
        hsts = resp.headers.get("strict-transport-security", "")
        if not hsts:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_tls:missing_hsts",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    severity="Medium",
                    evidence=f"HTTPS response from {resp.url} omitted Strict-Transport-Security.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                    cwe="CWE-523",
                )
            )
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            max_age = int(m.group(1)) if m else 0
            if max_age < 15552000:
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_tls:weak_hsts",
                        title="Weak HSTS max-age Policy",
                        severity="Low",
                        evidence=f"Strict-Transport-Security header has max-age={max_age} (< 180 days): '{hsts}'.",
                        remediation="Set HSTS max-age to at least 31536000 (1 year).",
                        cwe="CWE-523",
                    )
                )

    return ProbeOutcome(
        findings=findings,
        summary=" ".join(notes) if notes else "TLS and HSTS configuration verified.",
        conclusive=True,
    )


# ==============================================================================
# 2. ATOMIC HTTP SECURITY HEADERS PROBE (WSTG-CONF-12, CLNT-09, INFO-02/08)
# ==============================================================================

HEADER_SPECS: list[tuple[str, str, str, str, str]] = [
    (
        "content-security-policy",
        "Missing Content-Security-Policy (CSP) Header",
        "Medium",
        "Define a restrictive Content-Security-Policy header to mitigate XSS and unauthorized script execution.",
        "CWE-693",
    ),
    (
        "x-frame-options",
        "Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
        "Medium",
        "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and CSP 'frame-ancestors' directive.",
        "CWE-1021",
    ),
    (
        "x-content-type-options",
        "Missing X-Content-Type-Options: nosniff Header",
        "Low",
        "Set 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
        "CWE-16",
    ),
    (
        "referrer-policy",
        "Missing Referrer-Policy Header",
        "Low",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        "CWE-200",
    ),
    (
        "permissions-policy",
        "Missing Permissions-Policy Header",
        "Low",
        "Restrict powerful browser features via 'Permissions-Policy' header.",
        "CWE-693",
    ),
]

SENSITIVE_HEADER_LEAKS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


async def probe_security_headers(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Emit individual atomic findings for each missing security header or version disclosure."""
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        resp = await client.get(target)

    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[ProbeFinding] = []

    for header_name, title, severity, remediation, cwe in HEADER_SPECS:
        if header_name == "x-frame-options" and "frame-ancestors" in headers.get(
            "content-security-policy", ""
        ):
            continue
        if header_name not in headers:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_headers:missing_{header_name}",
                    title=title,
                    severity=severity,  # type: ignore[arg-type]
                    evidence=f"Response from {resp.url} (HTTP {resp.status_code}) did not include '{header_name}'.",
                    remediation=remediation,
                    cwe=cwe,
                )
            )

    if "x-content-type-options" in headers and headers["x-content-type-options"].lower() != "nosniff":
        findings.append(
            ProbeFinding(
                rule_id=f"{check.id}:httpx_headers:invalid_nosniff",
                title="Misconfigured X-Content-Type-Options Header",
                severity="Low",
                evidence=f"Expected 'nosniff', got '{headers['x-content-type-options']}'.",
                remediation="Set 'X-Content-Type-Options: nosniff'.",
                cwe="CWE-16",
            )
        )

    for leak_hdr in SENSITIVE_HEADER_LEAKS:
        if leak_hdr in headers:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_headers:leak_{leak_hdr}",
                    title=f"Technology Stack Disclosure via '{leak_hdr}' Header",
                    severity="Low",
                    evidence=f"{leak_hdr}: {headers[leak_hdr]}",
                    remediation=f"Strip or obfuscate the '{leak_hdr}' response header on the web server/reverse proxy.",
                    cwe="CWE-200",
                )
            )

    summary = (
        f"Identified {len(findings)} discrete header/banner issue(s) on {resp.url}."
        if findings
        else f"No baseline security header issues detected on {resp.url} (HTTP {resp.status_code})."
    )
    return ProbeOutcome(findings=findings, summary=summary, conclusive=True)


# ==============================================================================
# 3. COOKIE SECURITY FLAGS PROBE (WSTG-SESS-02)
# ==============================================================================

async def probe_cookie_security(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Inspect Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes."""
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        resp = await client.get(target)

    raw_cookies = resp.headers.get_list("set-cookie")
    if not raw_cookies:
        return ProbeOutcome(
            findings=[],
            summary="No Set-Cookie headers issued on initial unauthenticated response (not detected).",
            conclusive=True,
        )

    is_https = str(resp.url).startswith("https://")
    findings: list[ProbeFinding] = []

    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name_val = parts[0]
        cookie_name = name_val.split("=", 1)[0].strip()
        attrs = {p.lower(): p for p in parts[1:]}

        if "secure" not in attrs:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_cookies:{cookie_name}:secure",
                    title=f"Cookie '{cookie_name}' Missing 'Secure' Attribute",
                    severity="High" if is_https else "Medium",
                    evidence=f"Set-Cookie: {cookie_name}=<redacted>; {'; '.join(parts[1:])}",
                    remediation=f"Add the 'Secure' flag to cookie '{cookie_name}' so it is only transmitted over TLS.",
                    cwe="CWE-614",
                )
            )
        if "httponly" not in attrs:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_cookies:{cookie_name}:httponly",
                    title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Attribute",
                    severity="Medium",
                    evidence=f"Set-Cookie: {cookie_name}=<redacted>; {'; '.join(parts[1:])}",
                    remediation=f"Add the 'HttpOnly' flag to cookie '{cookie_name}' to prevent JavaScript document.cookie access.",
                    cwe="CWE-1004",
                )
            )
        if not any(k.startswith("samesite") for k in attrs):
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_cookies:{cookie_name}:samesite",
                    title=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    severity="Low",
                    evidence=f"Set-Cookie: {cookie_name}=<redacted>; {'; '.join(parts[1:])}",
                    remediation=f"Set 'SameSite=Lax' or 'SameSite=Strict' on cookie '{cookie_name}'.",
                    cwe="CWE-1275",
                )
            )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Inspected {len(raw_cookies)} Set-Cookie header(s); found {len(findings)} attribute weakness(es)."
            if findings
            else f"All {len(raw_cookies)} Set-Cookie header(s) enforce Secure, HttpOnly, and SameSite."
        ),
        conclusive=True,
    )


# ==============================================================================
# 4. HTTP METHODS PROBE (WSTG-CONF-06)
# ==============================================================================

async def probe_http_methods(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Check OPTIONS Allow header and safe TRACE echo for risky HTTP methods."""
    findings: list[ProbeFinding] = []
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        opt_resp = await client.options(target)
        allow_hdr = opt_resp.headers.get("allow", "") or opt_resp.headers.get("public", "")
        allowed = {m.strip().upper() for m in allow_hdr.split(",") if m.strip()}
        risky_advertised = allowed.intersection({"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PROPFIND"})
        if risky_advertised:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_methods:allow",
                    title=f"Potentially Dangerous HTTP Methods Advertised ({', '.join(sorted(risky_advertised))})",
                    severity="Medium",
                    evidence=f"OPTIONS {target} returned Allow: {allow_hdr}",
                    remediation="Disable unused HTTP/WebDAV methods (TRACE, PUT, DELETE, PROPFIND) on the web server.",
                    cwe="CWE-749",
                )
            )

        trace_resp = await client.request("TRACE", target)
        if trace_resp.status_code == 200 and "TRACE /" in trace_resp.text:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_methods:trace_enabled",
                    title="HTTP TRACE Method Enabled (Cross-Site Tracing Risk)",
                    severity="Medium",
                    evidence=f"TRACE {target} echoed request headers with HTTP 200.",
                    remediation="Disable HTTP TRACE/TRACK in web server configuration (e.g., 'TraceEnable off').",
                    cwe="CWE-693",
                )
            )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"HTTP method audit identified {len(findings)} issue(s)."
            if findings
            else "No risky HTTP methods (TRACE/PUT/DELETE) detected."
        ),
        conclusive=True,
    )


# ==============================================================================
# 5. DIRECTORY LISTING, DEFAULT CONSOLES & ARTIFACT DISCOVERY (WSTG-CONF-02/04/05)
# ==============================================================================

DEFAULT_EXPOSURE_PATHS: list[tuple[str, str, str, str]] = [
    ("/.git/HEAD", "ref: refs/", "Exposed Git Repository Metadata (/.git/HEAD)", "Critical"),
    ("/.env", "DB_", "Exposed Environment Configuration File (/.env)", "Critical"),
    ("/manager/html", "Tomcat Web Application Manager", "Exposed Apache Tomcat Manager Console", "High"),
    ("/host-manager/html", "Tomcat Virtual Host Manager", "Exposed Apache Tomcat Host Manager Console", "High"),
    ("/phpmyadmin/", "phpMyAdmin", "Exposed phpMyAdmin Database Console", "High"),
    ("/actuator/env", "propertySources", "Exposed Spring Boot Actuator Environment Endpoint", "High"),
    ("/swagger-ui.html", "Swagger UI", "Exposed Public Swagger API Documentation", "Low"),
]


async def probe_directory_and_default_pages(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Detect open directory listings and exposed default admin consoles / build artifacts."""
    findings: list[ProbeFinding] = []
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        # 1. Check root and common asset directories for 'Index of /'
        for dir_path in ("/", "/static/", "/assets/", "/uploads/", "/backup/"):
            resp = await client.get(urljoin(target, dir_path))
            if resp.status_code == 200 and re.search(r"<title>\s*Index of\s+/", resp.text, re.IGNORECASE):
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_discovery:dirlist:{dir_path}",
                        title=f"Directory Listing Enabled at '{dir_path}'",
                        severity="Medium",
                        evidence=f"GET {urljoin(target, dir_path)} returned HTTP 200 with 'Index of /' directory listing.",
                        remediation="Disable directory indexing (e.g., 'Options -Indexes' in Apache or 'autoindex off' in Nginx).",
                        cwe="CWE-548",
                    )
                )

        # 2. Check high-signal default consoles and build artifacts
        for path, marker, title, severity in DEFAULT_EXPOSURE_PATHS:
            resp = await client.get(urljoin(target, path))
            if resp.status_code in {200, 401} and marker.lower() in resp.text.lower():
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_discovery:{path}",
                        title=title,
                        severity=severity,  # type: ignore[arg-type]
                        evidence=f"GET {urljoin(target, path)} returned HTTP {resp.status_code} matching signature '{marker}'.",
                        remediation=f"Remove '{path}' from production or restrict access to internal management networks/VPN.",
                        cwe="CWE-215",
                    )
                )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Discovered {len(findings)} exposed directory listing/default console/artifact issue(s)."
            if findings
            else "No open directory listings or default admin consoles detected at common paths."
        ),
        conclusive=True,
    )


# ==============================================================================
# 6. VERBOSE ERROR PAGES & STACK TRACE PROBE (WSTG-ERRH-01, ERRH-02)
# ==============================================================================

STACK_TRACE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Java / Tomcat Stack Trace", re.compile(r"(java\.lang\.[A-Za-z]+Exception|org\.apache\.catalina|at\s+[a-z0-9_.]+\([A-Za-z]+\.java:\d+\))")),
    (".NET Stack Trace", re.compile(r"(System\.Web\.HttpException|Server Error in '/' Application|Stack Trace:.*\[[A-Za-z]+Exception)")),
    ("Python Traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("PHP Fatal / Warning Error", re.compile(r"(Fatal error:|Parse error:|Warning:.*on line \d+)")),
    ("Database / SQL Exception", re.compile(r"(ORA-\d{4,5}|SQLSyntaxErrorException|PG::SyntaxError|mysql_fetch_|sqlite3\.OperationalError)")),
]


async def probe_verbose_errors(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Trigger malformed requests and inspect responses for stack traces and internal paths."""
    findings: list[ProbeFinding] = []
    probes = [
        ("GET", urljoin(target, "/__tirweb_nonexistent_404_probe__"), None),
        ("GET", f"{target.rstrip('/')}/?id=%27%22%5C", None),
        ("POST", target, "{malformed_json_probe"),
    ]

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        for method, url, body in probes:
            try:
                if method == "POST":
                    resp = await client.post(url, content=body, headers={"Content-Type": "application/json"})
                else:
                    resp = await client.get(url)
            except httpx.HTTPError:
                continue

            for label, pattern in STACK_TRACE_PATTERNS:
                m = pattern.search(resp.text)
                if m:
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_errors:{label.lower().replace(' ', '_')}",
                            title=f"Verbose Error / {label} Disclosed",
                            severity="Medium",
                            evidence=f"{method} {url} (HTTP {resp.status_code}) matched '{m.group(0)[:120]}'.",
                            remediation="Configure custom generic error pages and disable debug/stack-trace output in production.",
                            cwe="CWE-209",
                        )
                    )
                    break

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Detected {len(findings)} verbose error / stack trace disclosure(s)."
            if findings
            else "No stack traces or verbose framework errors detected on malformed probes."
        ),
        conclusive=True,
    )


# ==============================================================================
# 7. LOGIN OVER HTTP & PASSWORD AUTOCOMPLETE PROBE (WSTG-ATHN-01, ATHN-05)
# ==============================================================================

async def probe_auth_surface(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Inspect login pages for cleartext password submission and password autocomplete."""
    findings: list[ProbeFinding] = []
    candidate_urls = [target, urljoin(target, "/login"), urljoin(target, "/login.jsp"), urljoin(target, "/signin")]

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        seen_urls: set[str] = set()
        for url in candidate_urls:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                continue
            final_url = str(resp.url)
            if final_url in seen_urls or resp.status_code != 200:
                continue
            seen_urls.add(final_url)

            pw_inputs = re.findall(r"<input\b[^>]*type=['\"]?password['\"]?[^>]*>", resp.text, re.IGNORECASE)
            if not pw_inputs:
                continue

            if final_url.startswith("http://"):
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_auth_surface:http_login",
                        title="Login Form Served Over Unencrypted HTTP",
                        severity="High",
                        evidence=f"Password input field rendered on cleartext HTTP page: {final_url}",
                        remediation="Serve all authentication forms exclusively over HTTPS.",
                        cwe="CWE-319",
                    )
                )

            for inp in pw_inputs:
                if not re.search(r"autocomplete=['\"]?(off|new-password|current-password)['\"]?", inp, re.IGNORECASE):
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_auth_surface:autocomplete",
                            title="Password Input Missing Explicit 'autocomplete' Attribute",
                            severity="Low",
                            evidence=f"Input element on {final_url}: {inp[:140]}",
                            remediation="Set autocomplete='current-password' or 'off' on sensitive password inputs.",
                            cwe="CWE-522",
                        )
                    )
                    break

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Authentication surface audit found {len(findings)} issue(s)."
            if findings
            else "No insecure login forms detected on probed entry paths."
        ),
        conclusive=True,
    )


# ==============================================================================
# 8. AUTHENTICATED CACHE-CONTROL PROBE (WSTG-ATHN-06)
# ==============================================================================

async def probe_cache_headers(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Verify Cache-Control: no-store on authenticated responses."""
    if not ctx.primary_auth.is_authenticated:
        return ProbeOutcome(
            findings=[],
            summary="SKIPPED_NO_AUTH: Provide --auth-file or --bearer-token to test authenticated cache headers.",
            conclusive=False,
        )

    endpoints = ctx.probe_endpoints or [target]
    findings: list[ProbeFinding] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        for ep in endpoints:
            url = resolve_endpoint(target, ep)
            resp = await client.get(url)
            cc = resp.headers.get("cache-control", "").lower()
            if resp.status_code == 200 and "no-store" not in cc:
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_cache:{ep}",
                        title="Authenticated Response Missing 'Cache-Control: no-store'",
                        severity="Medium",
                        evidence=f"GET {url} returned Cache-Control: '{cc or 'none'}'.",
                        remediation="Set 'Cache-Control: no-store, no-cache, must-revalidate' on authenticated pages.",
                        cwe="CWE-525",
                    )
                )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Detected {len(findings)} cache-control weakness(es) on authenticated endpoints."
            if findings
            else "Authenticated responses enforce Cache-Control: no-store."
        ),
        conclusive=True,
    )


# ==============================================================================
# 9. MISSING CSRF TOKEN PROBE (WSTG-SESS-05)
# ==============================================================================

CSRF_FIELD_NAMES = ("csrf", "_token", "authenticity_token", "__requestverificationtoken", "xsrf")


async def probe_csrf_tokens(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Inspect HTML POST forms for anti-CSRF tokens, correlated with SameSite cookie flags."""
    endpoints = ctx.probe_endpoints or [target]
    findings: list[ProbeFinding] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,  # Follow landing 302s to reach login/dashboard forms
        trust_env=True,
        headers=ctx.primary_auth.to_http_headers(),
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        for ep in endpoints:
            url = resolve_endpoint(target, ep)
            resp = await client.get(url)
            if resp.status_code != 200:
                continue

            cookie_blob = " ".join(resp.headers.get_list("set-cookie")).lower()
            has_samesite = "samesite=strict" in cookie_blob or "samesite=lax" in cookie_blob

            forms = re.findall(
                r"<form\b[^>]*method=['\"]?post['\"]?[^>]*>.*?</form>",
                resp.text,
                re.IGNORECASE | re.DOTALL,
            )
            for idx, form_html in enumerate(forms, start=1):
                if not any(tok in form_html.lower() for tok in CSRF_FIELD_NAMES):
                    action_m = re.search(r"action=['\"]([^'\"]*)['\"]", form_html, re.IGNORECASE)
                    action = action_m.group(1) if action_m else "(self)"
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_csrf:{ep}:{idx}",
                            title=(
                                "HTML POST Form Lacks Anti-CSRF Token (Mitigated by SameSite Cookie)"
                                if has_samesite
                                else "HTML POST Form Lacks Anti-CSRF Token and SameSite Mitigation"
                            ),
                            severity="Low" if has_samesite else "Medium",
                            evidence=f"POST form #{idx} (action='{action}') on {url} has no hidden CSRF token field.",
                            remediation="Include a per-session anti-CSRF token in all state-changing forms.",
                            cwe="CWE-352",
                            confidence="SIGNAL" if has_samesite else "CONFIRMED",
                        )
                    )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Flagged {len(findings)} POST form(s) lacking explicit anti-CSRF tokens."
            if findings
            else "No unprotected HTML POST forms detected."
        ),
        conclusive=True,
    )


# ==============================================================================
# 10. MIXED CONTENT & SUBRESOURCE INTEGRITY (SRI) PROBE (WSTG-CRYP-03, INF-004)
# ==============================================================================

async def probe_client_assets_and_sri(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Check HTTPS pages for cleartext http:// mixed content and external scripts missing SRI hashes."""
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        resp = await client.get(target)

    final_url = str(resp.url)
    page_host = urlparse(final_url).hostname or ""
    findings: list[ProbeFinding] = []

    script_tags = re.findall(r"<script\b[^>]*>", resp.text, re.IGNORECASE)
    for tag in script_tags:
        src_m = re.search(r"\bsrc=['\"]([^'\"]+)['\"]", tag, re.IGNORECASE)
        if not src_m:
            continue
        src = src_m.group(1).strip()

        if final_url.startswith("https://") and src.lower().startswith("http://"):
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_client_assets:mixed_content",
                    title="Active Mixed Content: HTTP Script Loaded on HTTPS Page",
                    severity="Medium",
                    evidence=f"Page {final_url} loads script over cleartext HTTP: {src}",
                    remediation="Load all scripts and subresources exclusively over HTTPS.",
                    cwe="CWE-311",
                )
            )

        parsed_src = urlparse(src)
        if parsed_src.scheme in {"http", "https"} and parsed_src.hostname and parsed_src.hostname != page_host:
            if not re.search(r"\bintegrity=['\"]sha(256|384|512)-", tag, re.IGNORECASE):
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_client_assets:missing_sri:{parsed_src.hostname}",
                        title=f"External Third-Party Script Missing Subresource Integrity (SRI)",
                        severity="Low",
                        evidence=f"External script '{src}' loaded without integrity='sha384-...' attribute.",
                        remediation="Add cryptographic 'integrity' and 'crossorigin=\"anonymous\"' attributes to external CDN scripts.",
                        cwe="CWE-353",
                    )
                )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Client asset audit identified {len(findings)} mixed-content / missing-SRI issue(s)."
            if findings
            else "No active mixed content or unprotected external CDN scripts detected."
        ),
        conclusive=True,
    )


# ==============================================================================
# 11. VERSION FINGERPRINTING -> CVE MAPPING PROBE (WSTG-INFO-02, INFO-08, INFO-09)
# ==============================================================================

KNOWN_BANNER_CVES: list[tuple[re.Pattern[str], str, str, str, str]] = [
    (
        re.compile(r"Apache-Coyote/1\.1", re.IGNORECASE),
        "Legacy Apache Tomcat Connector (Apache-Coyote/1.1) — End-of-Life / RCE Exposure",
        "High",
        "CVE-2017-12617 / CVE-2020-1938",
        "Upgrade Apache Tomcat to a supported 10.1.x / 11.x release and suppress the Server banner.",
    ),
    (
        re.compile(r"Apache/2\.4\.(49|50)\b", re.IGNORECASE),
        "Apache HTTP Server Path Traversal & RCE Version (2.4.49/2.4.50)",
        "Critical",
        "CVE-2021-41773 / CVE-2021-42013",
        "Upgrade Apache HTTP Server immediately to >= 2.4.51.",
    ),
    (
        re.compile(r"PHP/[57]\.", re.IGNORECASE),
        "End-of-Life PHP Runtime Version Disclosed",
        "High",
        "EOL-PHP-5/7",
        "Upgrade PHP to an actively supported 8.2+ / 8.3+ branch and set 'expose_php = Off'.",
    ),
    (
        re.compile(r"nginx/1\.(1[0-8]|[0-9])\.", re.IGNORECASE),
        "Outdated / End-of-Life Nginx Version Disclosed",
        "Medium",
        "CVE-2021-23017",
        "Upgrade Nginx to the latest mainline/stable release and enable 'server_tokens off;'.",
    ),
]


async def probe_cve_fingerprint(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Fingerprint server/framework banners and map legacy versions to known CVEs."""
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        resp = await client.get(target)

    banner_blob = "\n".join(
        f"{k}: {v}"
        for k, v in resp.headers.items()
        if k.lower() in {"server", "x-powered-by", "x-aspnet-version", "via"}
    )
    findings: list[ProbeFinding] = []

    for pattern, title, severity, cve, remediation in KNOWN_BANNER_CVES:
        m = pattern.search(banner_blob)
        if m:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_cve_fingerprint:{cve}",
                    title=title,
                    severity=severity,  # type: ignore[arg-type]
                    evidence=f"Matched banner signature '{m.group(0)}' in response headers.",
                    remediation=remediation,
                    cve=cve,
                    cwe="CWE-1104",
                )
            )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Version fingerprinting matched {len(findings)} known vulnerable/EOL signature(s)."
            if findings
            else "No known vulnerable/EOL server signatures matched in response headers."
        ),
        conclusive=True,
    )


# ==============================================================================
# 12. SAFE CANARY REFLECTED XSS & ERROR-BASED SQLI PROBE (WSTG-INPV-01, INPV-04)
# ==============================================================================

async def probe_canary_injection(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Inject benign reflection canary and single-quote syntax probe on discovered query parameters."""
    parsed = urlparse(target)
    target_urls = [target]
    if not parsed.query:
        target_urls.append(f"{target.rstrip('/')}/search?q=test")

    xss_canary = "tirweb7x9q\"'><"
    findings: list[ProbeFinding] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        for base_url in target_urls:
            p = urlparse(base_url)
            if not p.query:
                continue
            params = dict(pair.split("=", 1) for pair in p.query.split("&") if "=" in pair)
            for param_name in params:
                # 1. Benign Reflected XSS Canary
                xss_params = dict(params)
                xss_params[param_name] = xss_canary
                xss_url = urlunparse(p._replace(query=urlencode(xss_params)))
                try:
                    resp = await client.get(xss_url)
                    if xss_canary in resp.text:
                        findings.append(
                            ProbeFinding(
                                rule_id=f"{check.id}:httpx_canary_inj:xss:{param_name}",
                                title=f"Unencoded Reflected XSS Canary in Parameter '{param_name}'",
                                severity="High",
                                evidence=f"GET {xss_url} reflected unencoded canary '{xss_canary}' in HTML response.",
                                remediation="Apply context-aware HTML/attribute output encoding on all user-controlled parameters.",
                                cwe="CWE-79",
                            )
                        )
                except httpx.HTTPError:
                    pass

                # 2. Error-Based SQLi Single-Quote Probe
                sqli_params = dict(params)
                sqli_params[param_name] = "'"
                sqli_url = urlunparse(p._replace(query=urlencode(sqli_params)))
                try:
                    sqli_resp = await client.get(sqli_url)
                    for label, pattern in STACK_TRACE_PATTERNS:
                        if "Database" in label and pattern.search(sqli_resp.text):
                            findings.append(
                                ProbeFinding(
                                    rule_id=f"{check.id}:httpx_canary_inj:sqli:{param_name}",
                                    title=f"Error-Based SQL Injection Signal in Parameter '{param_name}'",
                                    severity="Critical",
                                    evidence=f"GET {sqli_url} triggered {label} signature.",
                                    remediation="Use parameterized queries / prepared statements for all database access.",
                                    cwe="CWE-89",
                                )
                            )
                except httpx.HTTPError:
                    pass

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Canary injection probe detected {len(findings)} reflection/SQLi issue(s)."
            if findings
            else "No unencoded canary reflection or SQL error signatures detected."
        ),
        conclusive=True,
    )


# ==============================================================================
# 13. EXISTING PROBES UPGRADED TO STRUCTURED ProbeOutcome
# ==============================================================================

INSECURE_JWT_ALGS = {"none", "hs1", "rs1", "es1", "rsa1_5"}
SYMMETRIC_JWT_ALGS = {"hs256", "hs384", "hs512"}
RISKY_HEADER_PARAMS = {"jku", "x5u", "jwk"}

SENSITIVE_CLAIM_KEYS = {
    "password", "passwd", "secret", "ssn", "aadhaar", "aadhar",
    "pan", "pan_number", "passport", "dob", "date_of_birth",
    "credit_card", "card_number", "cvv", "mobile", "phone",
    "phone_number", "address",
}

PII_VALUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Email address", re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")),
    ("Indian PAN-like identifier", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("12-digit Aadhaar-like number", re.compile(r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b")),
    ("Indian mobile number", re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")),
]

MAX_RECOMMENDED_TTL_SECONDS = 86400


def _b64url_decode_json(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Decoded JWT segment is not a JSON object.")
    return data


def _scan_claims_for_pii(claims: dict[str, Any], prefix: str = "") -> list[str]:
    findings: list[str] = []
    for key, value in claims.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if key.lower() in SENSITIVE_CLAIM_KEYS:
            findings.append(f"Sensitive claim key present: '{full_key}'")
        if isinstance(value, str):
            for label, pattern in PII_VALUE_PATTERNS:
                if pattern.search(value):
                    findings.append(f"{label} detected inside claim '{full_key}'")
        elif isinstance(value, dict):
            findings.extend(_scan_claims_for_pii(value, prefix=full_key))
    return findings


def _extract_candidate_tokens(ctx: ScanContext) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if ctx.primary_auth.bearer_token:
        candidates.append(("primary_auth", ctx.primary_auth.bearer_token))
    if ctx.secondary_auth and ctx.secondary_auth.bearer_token:
        candidates.append(("secondary_auth", ctx.secondary_auth.bearer_token))
    return candidates


async def probe_jwt_security(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Inspect configured JWT bearer tokens for RFC 8725 & DPDP Rules 2025 hygiene."""
    candidates = _extract_candidate_tokens(ctx)
    if not candidates:
        return ProbeOutcome(
            findings=[],
            summary="SKIPPED_NO_JWT: No bearer_token configured in AuthContext.",
            conclusive=False,
        )

    findings: list[ProbeFinding] = []
    inspected_count = 0

    for label, token in candidates:
        parts = token.strip().split(".")
        if len(parts) == 5:
            continue
        if len(parts) != 3:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:malformed",
                    title=f"[{label}] Malformed JWT Structure",
                    severity="Medium",
                    evidence="Token is not a 3-segment JWS or 5-segment JWE.",
                    remediation="Issue RFC 7519 compliant JWS/JWE tokens.",
                    confidence="SIGNAL",
                )
            )
            continue

        try:
            header = _b64url_decode_json(parts[0])
            payload = _b64url_decode_json(parts[1])
        except Exception as exc:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:decode_err",
                    title=f"[{label}] Unparseable JWT Base64url Segments",
                    severity="Low",
                    evidence=str(exc),
                    remediation="Ensure valid base64url JSON encoding.",
                    confidence="SIGNAL",
                )
            )
            continue

        inspected_count += 1
        alg = str(header.get("alg", "")).strip()
        alg_lower = alg.lower()

        if not alg or alg_lower in INSECURE_JWT_ALGS:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:insecure_alg",
                    title=f"[{label}] Insecure JWT Signing Algorithm ('{alg or 'MISSING'}')",
                    severity="Critical",
                    evidence=f"JWT header specifies alg='{alg or 'MISSING'}'.",
                    remediation="Enforce asymmetric RS256, ES256, or EdDSA algorithms and reject 'none'.",
                    cwe="CWE-327",
                )
            )
        elif alg_lower in SYMMETRIC_JWT_ALGS:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:symmetric_alg",
                    title=f"[{label}] Symmetric JWT Algorithm ('{alg}') Used",
                    severity="Low",
                    evidence=f"JWT uses symmetric HMAC '{alg}'.",
                    remediation="Prefer asymmetric ES256/RS256 signing for microservice verification.",
                    confidence="SIGNAL",
                )
            )

        present_risky = RISKY_HEADER_PARAMS.intersection({k.lower() for k in header})
        if present_risky:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:risky_headers",
                    title=f"[{label}] Untrusted Key-Location JWT Header(s): {', '.join(sorted(present_risky))}",
                    severity="High",
                    evidence=f"JWT header contains {', '.join(sorted(present_risky))}.",
                    remediation="Strip jku, x5u, and embedded jwk headers; resolve keys from a trusted server-side JWKS store.",
                    cwe="CWE-347",
                )
            )

        exp = payload.get("exp")
        iat = payload.get("iat")
        if exp is None:
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:missing_exp",
                    title=f"[{label}] JWT Missing 'exp' Expiration Claim",
                    severity="Medium",
                    evidence="JWT payload omits 'exp'.",
                    remediation="Include a short-lived 'exp' timestamp on every token.",
                    cwe="CWE-613",
                )
            )
        elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)) and (exp - iat) > MAX_RECOMMENDED_TTL_SECONDS:
            ttl_hours = round((exp - iat) / 3600, 1)
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:excessive_ttl",
                    title=f"[{label}] Excessive JWT Lifetime ({ttl_hours}h > 24h)",
                    severity="Low",
                    evidence=f"Token TTL is {ttl_hours} hours.",
                    remediation="Reduce access token TTL to <= 1 hour and rotate refresh tokens.",
                    confidence="SIGNAL",
                )
            )

        for pii_msg in _scan_claims_for_pii(payload):
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_jwt:{label}:pii_exposure",
                    title=f"[{label}] Unencrypted PII/Sensitive Claim in JWS Payload",
                    severity="High",
                    evidence=pii_msg,
                    remediation="Remove PII from unencrypted JWS claims or encrypt the token with JWE (DPDP Rules 2025 Rule 6(1)(a)).",
                    cwe="CWE-312",
                )
            )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"JWT inspection identified {len(findings)} issue(s) across {inspected_count} token(s)."
            if findings
            else f"No JWT hygiene issues detected across {inspected_count} token(s)."
        ),
        conclusive=True,
    )


async def probe_cors_policy(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
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
    findings: list[ProbeFinding] = []

    if acao == canary_origin:
        is_cred = acac == "true"
        findings.append(
            ProbeFinding(
                rule_id=f"{check.id}:httpx_cors:origin_reflection",
                title=(
                    "Credentialed Arbitrary CORS Origin Reflection"
                    if is_cred
                    else "Arbitrary CORS Origin Reflection (Uncredentialed)"
                ),
                severity="High" if is_cred else "Medium",
                evidence=f"Origin '{canary_origin}' reflected in ACAO='{acao}' with ACAC='{acac or 'none'}'.",
                remediation="Validate Origin against a strict server-side allowlist before setting Access-Control-Allow-Origin.",
                cwe="CWE-942",
                confidence="CONFIRMED" if is_cred else "SIGNAL",
            )
        )
    elif acao == "*" and ctx.primary_auth.is_authenticated:
        findings.append(
            ProbeFinding(
                rule_id=f"{check.id}:httpx_cors:wildcard_auth",
                title="Wildcard CORS Policy (ACAO: *) on Authenticated Endpoint",
                severity="Medium",
                evidence="Authenticated response returned Access-Control-Allow-Origin: *.",
                remediation="Restrict Access-Control-Allow-Origin to explicit trusted origins on authenticated APIs.",
                cwe="CWE-942",
            )
        )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"CORS policy check identified {len(findings)} issue(s)."
            if findings
            else f"No permissive CORS reflection detected (ACAO='{acao or 'none'}', ACAC='{acac or 'none'}')."
        ),
        conclusive=True,
    )


async def probe_metafiles_and_ria_policies(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """WSTG-INFO-03 & WSTG-CONF-08: Inspect robots.txt, sitemap.xml, and RIA cross-domain XML."""
    sensitive_keywords = ("/admin", "/internal", "/backup", "/config", "/.git", "/.env", "/swagger", "/actuator")
    findings: list[ProbeFinding] = []

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        for meta_path in ("/robots.txt", "/sitemap.xml"):
            resp = await client.get(urljoin(target, meta_path))
            if resp.status_code == 200 and resp.text:
                leaked = [kw for kw in sensitive_keywords if kw in resp.text.lower()]
                if leaked:
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_metafiles:{meta_path}",
                            title=f"Sensitive Internal Paths Disclosed in {meta_path}",
                            severity="Low",
                            evidence=f"{meta_path} references sensitive path pattern(s): {', '.join(leaked)}.",
                            remediation=f"Remove sensitive administrative/internal routes from {meta_path}.",
                            cwe="CWE-200",
                        )
                    )

        for ria_path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
            resp = await client.get(urljoin(target, ria_path))
            if resp.status_code == 200 and ('domain="*"' in resp.text or 'uri="*"' in resp.text):
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_metafiles:{ria_path}",
                        title=f"Overly Permissive Wildcard Policy in {ria_path}",
                        severity="Medium",
                        evidence=f"{ria_path} permits wildcard '*' cross-domain access.",
                        remediation=f"Remove {ria_path} or restrict allowed domains to explicit trusted origins.",
                        cwe="CWE-942",
                    )
                )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Metafile/RIA audit identified {len(findings)} issue(s)."
            if findings
            else "No sensitive disclosures in robots.txt/sitemap.xml or wildcard RIA policies detected."
        ),
        conclusive=True,
    )


async def probe_path_confusion(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """WSTG-CONF-13: Baseline-aware path normalization bypass check (/admin/..;/, double slashes)."""
    protected_candidates = ctx.probe_endpoints or ["/admin", "/api/admin"]
    findings: list[ProbeFinding] = []
    tested_restricted = 0

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        headers=ctx.primary_auth.to_http_headers(),
    ) as client:
        # Baseline soft-404 check so custom 200 error pages do not create false positives
        not_found_resp = await client.get(urljoin(target, "/__tirweb_baseline_404_canary__"))
        baseline_404_len = len(not_found_resp.content)

        for base_path in protected_candidates:
            clean_path = "/" + base_path.lstrip("/")
            canonical = await client.get(urljoin(target, clean_path))
            if canonical.status_code not in {401, 403}:
                continue

            tested_restricted += 1
            variants = [f"{clean_path}/..;/", f"{clean_path}..%2f", f"/{clean_path}", clean_path.upper()]
            for variant in variants:
                resp = await client.get(f"{target.rstrip('/')}{variant}")
                if resp.status_code == 200 and abs(len(resp.content) - baseline_404_len) > 64:
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_path_confusion:{variant}",
                            title=f"URL Path Confusion ACL Bypass on '{clean_path}'",
                            severity="High",
                            evidence=f"Canonical '{clean_path}' returned {canonical.status_code}, while '{variant}' returned HTTP 200.",
                            remediation="Normalize URL paths consistently across reverse proxy, WAF, and backend router.",
                            cwe="CWE-284",
                        )
                    )

    if tested_restricted == 0:
        return ProbeOutcome(
            findings=[],
            summary="No HTTP 401/403 restricted baseline endpoints found among candidates (path confusion not applicable).",
            conclusive=True,
        )
    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Path confusion check identified {len(findings)} bypass(es)."
            if findings
            else f"Consistent ACL enforcement verified across {tested_restricted} restricted path(s)."
        ),
        conclusive=True,
    )


async def probe_open_redirect(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """WSTG-CLNT-04: Test common redirect parameters for unvalidated external Location headers."""
    canary_domain = "untrusted-redirect-audit.example.invalid"
    canary_url = f"https://{canary_domain}/phish"
    redirect_params = ("next", "url", "redirect", "redirect_uri", "returnTo", "dest")
    findings: list[ProbeFinding] = []

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
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_open_redirect:{param}",
                            title=f"Unvalidated Open Redirect via '{param}' Parameter",
                            severity="Medium",
                            evidence=f"GET {target}?{param}={canary_url} redirected to Location: {location}",
                            remediation="Restrict redirect targets to relative paths or an explicit domain allowlist.",
                            cwe="CWE-601",
                        )
                    )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Open redirect probe found {len(findings)} vulnerable parameter(s)."
            if findings
            else "No external redirect reflection detected across common redirect parameters."
        ),
        conclusive=True,
    )


def _extract_structural_shape(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {k: _extract_structural_shape(v) for k, v in sorted(payload.items())}
    if isinstance(payload, list):
        return [_extract_structural_shape(payload[0])] if payload else []
    return type(payload).__name__


async def probe_differential_idor(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Compare HTTP status and structural JSON response shapes across two AuthContext sessions."""
    if not ctx.primary_auth.is_authenticated:
        return ProbeOutcome(
            findings=[],
            summary="SKIPPED_PRIMARY_AUTH: Configure --auth-file before running differential access comparison.",
            conclusive=False,
        )
    if not ctx.secondary_auth or not ctx.secondary_auth.is_authenticated:
        return ProbeOutcome(
            findings=[],
            summary="SKIPPED_SECONDARY_AUTH: Provide --secondary-auth-file with a second test identity.",
            conclusive=False,
        )

    endpoints = ctx.probe_endpoints or [target]
    findings: list[ProbeFinding] = []

    async with httpx.AsyncClient(timeout=ctx.timeout, verify=ctx.verify_tls, follow_redirects=False) as client:
        for endpoint in endpoints:
            url = resolve_endpoint(target, endpoint)
            resp_a = await client.get(url, headers=ctx.primary_auth.to_http_headers())
            resp_b = await client.get(url, headers=ctx.secondary_auth.to_http_headers())

            if resp_a.status_code == 200 and resp_b.status_code == 200:
                digest_a = hashlib.sha256(resp_a.content).hexdigest()
                digest_b = hashlib.sha256(resp_b.content).hexdigest()
                try:
                    same_schema = json.dumps(_extract_structural_shape(resp_a.json())) == json.dumps(
                        _extract_structural_shape(resp_b.json())
                    )
                except ValueError:
                    same_schema = False

                if digest_a == digest_b or same_schema:
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_idor_diff:{endpoint}",
                            title=f"Cross-User Access Parity Signal on '{endpoint}'",
                            severity="High",
                            evidence=(
                                f"{url}: Primary and secondary identities both received HTTP 200 with matching "
                                f"{'byte digest' if digest_a == digest_b else 'JSON schema'}."
                            ),
                            remediation="Verify server-side object ownership checks; deny cross-user access with HTTP 403/404.",
                            cwe="CWE-639",
                            confidence="SIGNAL",
                        )
                    )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Differential access check flagged {len(findings)} endpoint(s) for ownership review."
            if findings
            else f"Secondary identity properly isolated across {len(endpoints)} endpoint(s)."
        ),
        conclusive=True,
    )


async def probe_api_authentication(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """Verify API endpoints reject both unauthenticated requests and malformed Bearer tokens."""
    if not ctx.probe_endpoints:
        return ProbeOutcome(
            findings=[],
            summary="SKIPPED_NO_ENDPOINTS: Configure --endpoint values to assess API authentication.",
            conclusive=False,
        )

    auth_headers = ctx.primary_auth.to_http_headers()
    has_auth = ctx.primary_auth.is_authenticated
    observations: list[str] = []
    findings: list[ProbeFinding] = []
    inconclusive = False

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,  # 302 to login is an access-denied signal; never follow
        trust_env=True,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        for endpoint in ctx.probe_endpoints:
            url = resolve_endpoint(target, endpoint)
            unauth = await client.get(url)
            malformed = await client.get(
                url, headers={"Authorization": "Bearer invalid.invalid.invalid"}
            )

            if 200 <= malformed.status_code < 300:
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_api_auth:malformed_jwt:{endpoint}",
                        title=f"API Endpoint Accepted Malformed Bearer Token ('{endpoint}')",
                        severity="Critical",
                        evidence=f"GET {url} with malformed JWT returned HTTP {malformed.status_code}.",
                        remediation="Enforce cryptographic JWT signature verification before granting access.",
                        cwe="CWE-347",
                    )
                )

            if not has_auth:
                inconclusive = True
                observations.append(
                    f"{url}: unauthenticated={unauth.status_code}/{_http_access_outcome(unauth)}, "
                    f"malformed_jwt={malformed.status_code}/{_http_access_outcome(malformed)}."
                )
                continue

            authed = await client.get(url, headers=auth_headers)
            if 200 <= unauth.status_code < 300 and 200 <= authed.status_code < 300:
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_api_auth:unauth_access:{endpoint}",
                        title=f"API Endpoint Accessible Without Authentication ('{endpoint}')",
                        severity="High",
                        evidence=(
                            f"GET {url} returned HTTP {unauth.status_code} unauthenticated and "
                            f"HTTP {authed.status_code} authenticated."
                        ),
                        remediation="Enforce authentication middleware on non-public API endpoints.",
                        cwe="CWE-306",
                        confidence="SIGNAL",
                    )
                )
            observations.append(
                f"{url}: unauthenticated={unauth.status_code}, "
                f"malformed_jwt={malformed.status_code}, authenticated={authed.status_code}."
            )

    return ProbeOutcome(
        findings=findings,
        summary=" | ".join(observations),
        conclusive=not inconclusive,
    )


async def probe_differential_default_creds(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """
    Differential baseline credential check: compares a known-invalid credential submission
    against candidate default pairs using status code, redirect Location, and body length.
    """
    if not ctx.allow_default_creds:
        return ProbeOutcome(
            findings=[],
            summary="SKIPPED_NOT_AUTHORIZED: Pass --allow-default-creds to run active credential probes.",
            conclusive=False,
        )

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        trust_env=True,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        landing = await client.get(target)
        form_m = re.search(r"<form\b[^>]*>(.*?)</form>", landing.text, re.IGNORECASE | re.DOTALL)
        if not form_m:
            return ProbeOutcome(
                findings=[],
                summary="No HTML login form found at target root.",
                conclusive=True,
            )

        form_html = form_m.group(0)
        action_m = re.search(r"action=['\"]([^'\"]*)['\"]", form_html, re.IGNORECASE)
        post_url = (
            resolve_endpoint(str(landing.url), action_m.group(1))
            if action_m and action_m.group(1)
            else str(landing.url)
        )

        user_m = re.search(
            r"<input\b[^>]*type=['\"]?(?:text|email)['\"]?[^>]*name=['\"]([^'\"]+)['\"]",
            form_html,
            re.IGNORECASE,
        )
        pass_m = re.search(
            r"<input\b[^>]*type=['\"]?password['\"]?[^>]*name=['\"]([^'\"]+)['\"]",
            form_html,
            re.IGNORECASE,
        )
        user_field = user_m.group(1) if user_m else "username"
        pass_field = pass_m.group(1) if pass_m else "password"

    findings: list[ProbeFinding] = []
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        trust_env=True,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        baseline = await client.post(
            post_url,
            data={
                user_field: "__tirweb_invalid_user_9x7__",
                pass_field: "__tirweb_wrong_pass_9x7__",
            },
        )
        base_sig = (
            baseline.status_code,
            baseline.headers.get("location", ""),
            len(baseline.content),
        )

        for cand_user, cand_pass in (("admin", "admin"), ("admin", "password"), ("jsmith", "Demo1234")):
            await asyncio.sleep(0.25)
            attempt = await client.post(
                post_url, data={user_field: cand_user, pass_field: cand_pass}
            )
            att_sig = (
                attempt.status_code,
                attempt.headers.get("location", ""),
                len(attempt.content),
            )

            if (
                att_sig[0] != base_sig[0]
                or att_sig[1] != base_sig[1]
                or abs(att_sig[2] - base_sig[2]) > 80
            ):
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:nuclei_auth:differential_login:{cand_user}",
                        title=f"Differential Login Response Detected for '{cand_user}'",
                        severity="Critical",
                        evidence=(
                            f"POST {post_url} with '{cand_user}' produced "
                            f"(status={att_sig[0]}, loc='{att_sig[1]}', len={att_sig[2]}) "
                            f"vs invalid baseline (status={base_sig[0]}, loc='{base_sig[1]}', len={base_sig[2]})."
                        ),
                        remediation="Disable default/demo credentials and enforce strong password policies and MFA.",
                        cwe="CWE-798",
                        confidence="SIGNAL",
                    )
                )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Differential login probe flagged {len(findings)} anomalous credential response(s)."
            if findings
            else "Candidate default credentials behaved identically to invalid baseline."
        ),
        conclusive=True,
    )


async def probe_bfla_exposed_panels(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """
    Soft-404-aware unauthenticated administrative endpoint discovery fallback
    when external nuclei binary is unavailable.
    """
    admin_paths = ["/admin", "/admin/dashboard", "/api/admin", "/manage", "/console"]
    findings: list[ProbeFinding] = []
    executed = 0

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,  # 302 to login is an access-denied signal; never follow
        trust_env=True,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        canary = await client.get(urljoin(target, "/__tirweb_bfla_404_canary__"))
        canary_len = len(canary.content)

        for path in admin_paths:
            try:
                resp = await client.get(urljoin(target, path))
            except httpx.HTTPError:
                continue
            executed += 1
            if resp.status_code == 200 and abs(len(resp.content) - canary_len) > 64:
                lower_body = resp.text[:2000].lower()
                if not any(tok in lower_body for tok in ("access denied", "unauthorized", "forbidden", "sign in", "log in")):
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:nuclei_bfla:exposed_panel:{path}",
                            title=f"Unauthenticated Administrative Endpoint Reachable ('{path}')",
                            severity="High",
                            evidence=f"GET {urljoin(target, path)} returned HTTP 200 without authentication.",
                            remediation=f"Enforce server-side role-based access control on '{path}'.",
                            cwe="CWE-284",
                            confidence="SIGNAL",
                        )
                    )

    if executed == 0:
        return ProbeOutcome(
            findings=[],
            summary="INCONCLUSIVE_BFLA: All administrative path probes failed due to network error.",
            conclusive=False,
        )
    return ProbeOutcome(
        findings=findings,
        summary=(
            f"BFLA fallback detected {len(findings)} exposed administrative path(s)."
            if findings
            else f"Probed {executed} administrative path(s); none reachable unauthenticated."
        ),
        conclusive=True,
    )

GRAPHQL_DEFAULT_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/console")
async def probe_graphql_security(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """WSTG-APIT-01: Test GraphQL endpoints for enabled __schema introspection and query batching."""
    candidate_paths: list[str] = list(GRAPHQL_DEFAULT_PATHS)
    if ctx.probe_endpoints:
        for ep in ctx.probe_endpoints:
            if "graphql" in ep.lower() and ep not in candidate_paths:
                candidate_paths.insert(0, ep)

    introspection_query = {"query": "{__schema{queryType{name}types{name}}}"}
    batch_payload = [{"query": "{__typename}"} for _ in range(5)]
    discovered_endpoints: list[str] = []
    findings: list[ProbeFinding] = []

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
                        findings.append(
                            ProbeFinding(
                                rule_id=f"{check.id}:httpx_graphql:introspection:{path}",
                                title=f"GraphQL Schema Introspection Enabled ({path})",
                                severity="Medium",
                                evidence=f"POST {gql_url} returned full __schema metadata.",
                                remediation="Disable GraphQL schema introspection in production environments.",
                                cwe="CWE-200",
                                confidence="SIGNAL",
                            )
                        )

                    try:
                        batch_resp = await client.post(gql_url, json=batch_payload)
                        if batch_resp.status_code == 200:
                            batch_body = batch_resp.json()
                            if (
                                isinstance(batch_body, list)
                                and len(batch_body) == len(batch_payload)
                                and all(isinstance(item, dict) and "data" in item for item in batch_body)
                            ):
                                findings.append(
                                    ProbeFinding(
                                        rule_id=f"{check.id}:httpx_graphql:batching:{path}",
                                        title=f"Unthrottled GraphQL Query Batching Allowed ({path})",
                                        severity="Medium",
                                        evidence=f"POST {gql_url} executed {len(batch_payload)} batched operations in a single request.",
                                        remediation="Limit or disable array query batching and enforce query depth/cost limits.",
                                        cwe="CWE-770",
                                        confidence="SIGNAL",
                                    )
                                )
                    except (httpx.HTTPError, ValueError):
                        pass

    if findings:
        return ProbeOutcome(
            findings=findings,
            summary=f"GraphQL probe identified {len(findings)} issue(s) on {', '.join(discovered_endpoints)}.",
            conclusive=True,
        )
    if discovered_endpoints:
        return ProbeOutcome(
            findings=[],
            summary=f"GraphQL endpoint(s) ({', '.join(discovered_endpoints)}) verified: introspection and batching restricted.",
            conclusive=True,
        )
    return ProbeOutcome(
        findings=[],
        summary="No GraphQL endpoints detected at standard paths (/graphql, /api/graphql) within probe scope.",
        conclusive=True,
    )

# ==============================================================================
# 14. EXPOSED BUILD ARTIFACTS, SOURCE METADATA & HPP CONSISTENCY PROBES
# ==============================================================================

ADDITIONAL_ARTIFACT_PATHS: list[tuple[str, str]] = [
    ("/.svn/entries", "High"),
    ("/.hg/store", "High"),
    ("/backup.sql", "Critical"),
    ("/db.sql", "Critical"),
    ("/dump.sql", "Critical"),
    ("/site.zip", "High"),
    ("/www.zip", "High"),
    ("/backup.zip", "High"),
    ("/config.php.bak", "High"),
    ("/web.config.bak", "High"),
    ("/index.php.old", "Medium"),
    ("/main.js.map", "Medium"),
    ("/app.js.map", "Medium"),
    ("/static/js/main.js.map", "Medium"),
    ("/actuator", "Medium"),
    ("/actuator/metrics", "High"),
    ("/debug", "Medium"),
    ("/trace.axd", "Medium"),
    ("/elmah.axd", "High"),
]


async def probe_exposed_build_artifacts(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """WSTG-CONF-04/05: Enumerate backup archives, VCS metadata, source maps, and debug endpoints."""
    findings: list[ProbeFinding] = []
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        trust_env=True,
        headers=ctx.primary_auth.to_http_headers(),
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        baseline = await client.get(urljoin(target, "/__tirweb_baseline_404__"))
        baseline_len = len(baseline.text)

        for path, severity in ADDITIONAL_ARTIFACT_PATHS:
            try:
                resp = await client.get(urljoin(target, path))
            except httpx.HTTPError:
                continue
            if resp.status_code != 200:
                continue
            if baseline.status_code == 200 and abs(len(resp.text) - baseline_len) < 128:
                continue
            lower_sample = resp.text[:1500].lower()
            if "page not found" in lower_sample or "404 not found" in lower_sample:
                continue

            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_exposed_artifacts:{path}",
                    title=f"Exposed Build Artifact / Backup File ('{path}')",
                    severity=severity,  # type: ignore[arg-type]
                    evidence=(
                        f"GET {urljoin(target, path)} returned HTTP 200 "
                        f"({len(resp.text)} bytes, distinct from baseline 404 response)."
                    ),
                    remediation=f"Remove '{path}' from the production webroot or block access at the reverse proxy.",
                    cwe="CWE-530",
                )
            )

    return ProbeOutcome(
        findings=findings,
        summary=(
            f"Discovered {len(findings)} exposed backup/build-artifact path(s)."
            if findings
            else "No exposed backup files, source maps, or debug endpoints detected at checked paths."
        ),
        conclusive=True,
    )


COMMENT_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("AWS Access Key ID", "High", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private Key Material", "Critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Live API Secret / Token", "High", re.compile(r"\b(?:sk_live_[0-9a-zA-Z]{16,}|ghp_[0-9a-zA-Z]{30,}|AIza[0-9A-Za-z\-_]{35})\b")),
    ("Internal Hostname / RFC1918 IP", "Low", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.internal)\b")),
    ("Developer / TODO HTML Comment", "Low", re.compile(r"(?i)<!--.*?(TODO|FIXME|HACK|DO NOT SHIP|remove before prod).*?-->", re.S)),
]


async def probe_source_comments_and_file_metadata(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """WSTG-INFO-05: Passively inspect landing HTML and same-origin JS bundles for secrets and TODO comments."""
    findings: list[ProbeFinding] = []
    notes: list[str] = []
    origin = urlparse(target)

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        trust_env=True,
        headers=ctx.primary_auth.to_http_headers(),
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        resp = await client.get(target)
        html = resp.text

        for label, severity, pattern in COMMENT_SECRET_PATTERNS:
            for m in pattern.finditer(html):
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_source_metadata:{label.lower().replace(' ', '_')}",
                        title=f"Information Leakage in Page Source: {label}",
                        severity=severity,  # type: ignore[arg-type]
                        evidence=f"Pattern matched on {resp.url}: '{m.group(0)[:100]}'.",
                        remediation="Strip developer comments, secrets, and internal hostnames from client-delivered HTML/JS.",
                        cwe="CWE-200",
                        confidence="SIGNAL" if severity == "Low" else "CONFIRMED",
                    )
                )

        js_paths = re.findall(r'src=["\']([^"\']+\.js)["\']', html)[:10]
        for js_path in js_paths:
            js_url = urljoin(str(resp.url), js_path)
            if urlparse(js_url).netloc != origin.netloc:
                continue
            try:
                js_resp = await client.get(js_url)
            except httpx.HTTPError:
                continue
            for label, severity, pattern in COMMENT_SECRET_PATTERNS:
                m = pattern.search(js_resp.text)
                if m:
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_source_metadata:js:{label.lower().replace(' ', '_')}",
                            title=f"Information Leakage in Bundled JavaScript: {label}",
                            severity=severity,  # type: ignore[arg-type]
                            evidence=f"Pattern matched in {js_url}: '{m.group(0)[:100]}'.",
                            remediation="Remove secrets and debug comments from production JS bundles.",
                            cwe="CWE-200",
                            confidence="SIGNAL" if severity == "Low" else "CONFIRMED",
                        )
                    )

        doc_links = re.findall(r'href=["\']([^"\']+\.(?:pdf|docx?|xlsx?))["\']', html, re.IGNORECASE)
        if doc_links:
            notes.append(
                f"{len(doc_links)} downloadable document link(s) found (e.g. {doc_links[0]}) — review manually for EXIF/author metadata."
            )

    summary = (
        (f"Flagged {len(findings)} source-level information leakage issue(s). " + " ".join(notes)).strip()
        if findings or notes
        else "No secrets, developer comments, or internal references detected in landing HTML/same-origin JS."
    )
    return ProbeOutcome(findings=findings, summary=summary, conclusive=True)


async def probe_http_parameter_pollution(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """WSTG-INPV-03: Observe duplicate query parameter precedence consistency using benign markers."""
    findings: list[ProbeFinding] = []
    parsed = urlparse(target)
    existing_params = parse_qsl(parsed.query)
    param_name = existing_params[0][0] if existing_params else "tirwebhpp"

    marker_a, marker_b = "tirweb_hpp_alpha", "tirweb_hpp_beta"
    base = parsed._replace(query="").geturl()

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        trust_env=True,
        headers=ctx.primary_auth.to_http_headers(),
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        dup_query = urlencode([(param_name, marker_a), (param_name, marker_b)])
        try:
            resp = await client.get(f"{base}?{dup_query}")
        except httpx.HTTPError as exc:
            return ProbeOutcome(findings=[], summary=f"HPP probe request failed: {exc}", conclusive=False)

        has_a, has_b = marker_a in resp.text, marker_b in resp.text
        if has_a and has_b:
            precedence = "both values reflected (parser does not deduplicate)"
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_hpp_consistency:duplicate_reflected",
                    title="Duplicate HTTP Parameters Both Reflected (Potential HPP Surface)",
                    severity="Low",
                    evidence=(
                        f"GET {base}?{param_name}={marker_a}&{param_name}={marker_b} "
                        f"reflected both markers ({precedence})."
                    ),
                    remediation="Enforce consistent single-value parameter precedence across WAF, reverse proxy, and backend.",
                    cwe="CWE-235",
                    confidence="SIGNAL",
                )
            )
        elif has_a:
            precedence = "first value wins"
        elif has_b:
            precedence = "last value wins"
        else:
            precedence = "neither value reflected (parameter stripped or not echoed)"

    return ProbeOutcome(
        findings=findings,
        summary=f"Duplicate-parameter precedence observed: {precedence}.",
        conclusive=True,
    )

# ==============================================================================
# 15. ARCHITECTURE, WAF/CDN FINGERPRINTING & SUBDOMAIN/ORIGIN PROBE
#     (WEB-INF-007: WSTG-INFO-01/04 & WEB-INF-010: WSTG-INFO-10)
# ==============================================================================

WAF_CDN_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("cf-ray", "", "Cloudflare WAF / CDN"),
    ("x-amz-cf-id", "", "AWS CloudFront CDN"),
    ("x-akamai-transformed", "", "Akamai CDN / Kona Site Defender"),
    ("x-sucuri-id", "", "Sucuri CloudProxy WAF"),
    ("x-cdn", "imperva", "Imperva / Incapsula WAF"),
    ("x-iinfo", "", "Imperva / Incapsula WAF"),
    ("x-azure-ref", "", "Azure Front Door / CDN"),
    ("x-fastly-request-id", "", "Fastly Edge CDN"),
    ("x-cache", "", "Reverse-Proxy / Edge Cache Layer"),
    ("via", "", "Intermediate Proxy / Gateway"),
]

COMMON_SHADOW_SUBDOMAINS = (
    "dev",
    "staging",
    "stage",
    "uat",
    "test",
    "qa",
    "sandbox",
    "internal",
    "admin",
    "api-dev",
    "beta",
)


def _extract_registrable_domain(hostname: str) -> str | None:
    """Return base domain (e.g., 'example.in' or 'example.co.in') from a hostname."""
    if not hostname or hostname in {"localhost", "127.0.0.1", "::1"}:
        return None
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        return None
    parts = hostname.lower().strip(".").split(".")
    if len(parts) < 2:
        return None
    if len(parts) >= 3 and parts[-2] in {"co", "gov", "nic", "ac", "org", "net", "in"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


async def probe_architecture_and_dns(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    """
    WSTG-INFO-01/04/10: Map DNS A/AAAA records, fingerprint WAF/CDN/reverse-proxy headers,
    test direct-IP origin bypass (Host header routing), and probe non-prod shadow subdomains.
    """
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)
    findings: list[ProbeFinding] = []
    arch_notes: list[str] = []

    if not hostname:
        return ProbeOutcome(
            findings=[],
            summary="INCONCLUSIVE_ARCH: Target URL lacks a valid hostname.",
            conclusive=False,
        )

    loop = asyncio.get_running_loop()

    # 1. Non-blocking DNS resolution (A & AAAA records)
    resolved_ips: list[str] = []
    try:
        addr_infos = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        resolved_ips = sorted({info[4][0] for info in addr_infos if info[4]})
        arch_notes.append(f"DNS resolved {hostname} -> {', '.join(resolved_ips)}.")
    except OSError as exc:
        return ProbeOutcome(
            findings=[],
            summary=f"INCONCLUSIVE_DNS: Failed to resolve hostname '{hostname}' ({exc}).",
            conclusive=False,
        )

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,
        trust_env=True,
        headers=ctx.primary_auth.to_http_headers(),
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        # 2. Fingerprint WAF / CDN / Reverse-Proxy perimeter headers
        try:
            resp = await client.get(target)
        except httpx.HTTPError as exc:
            return ProbeOutcome(
                findings=[],
                summary=f"INCONCLUSIVE_ARCH: Failed to connect to {target} ({exc}).",
                conclusive=False,
            )

        lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        detected_perimeters: list[str] = []
        for hdr_name, val_sub, label in WAF_CDN_HEADER_SIGNATURES:
            if hdr_name in lower_headers:
                if not val_sub or val_sub in lower_headers[hdr_name].lower():
                    detected_perimeters.append(f"{label} ({hdr_name})")

        if detected_perimeters:
            arch_notes.append(f"Perimeter layers: {', '.join(dict.fromkeys(detected_perimeters))}.")
        else:
            arch_notes.append("No standard CDN/WAF perimeter headers detected on edge response.")
            findings.append(
                ProbeFinding(
                    rule_id=f"{check.id}:httpx_arch_and_dns:no_waf_cdn_detected",
                    title="No Edge WAF / CDN Perimeter Layer Fingerprinted",
                    severity="Info",
                    evidence=f"Response from {target} (HTTP {resp.status_code}) exposed no standard WAF/CDN headers.",
                    remediation="Verify whether an upstream WAF/reverse-proxy protects the origin and ensure direct origin IPs are firewalled.",
                    cwe="CWE-693",
                    confidence="SIGNAL",
                )
            )

        # 3. Direct-IP Origin Isolation Check (WSTG-INFO-10)
        # If an edge CDN/WAF is present, verify the resolved IP doesn't serve the app directly without SNI/edge routing
        if detected_perimeters and resolved_ips:
            first_ip = resolved_ips[0]
            ip_host = f"[{first_ip}]" if ":" in first_ip else first_ip
            direct_url = f"{scheme}://{ip_host}:{port}/"
            try:
                direct_resp = await client.get(direct_url, headers={"Host": hostname})
                if direct_resp.status_code == resp.status_code and abs(len(direct_resp.content) - len(resp.content)) < 256:
                    findings.append(
                        ProbeFinding(
                            rule_id=f"{check.id}:httpx_arch_and_dns:direct_ip_origin",
                            title="Origin IP Directly Reachable via Host Header (Potential WAF Bypass)",
                            severity="Medium",
                            evidence=(
                                f"Direct request to {direct_url} with Host: {hostname} returned HTTP {direct_resp.status_code} "
                                f"matching edge response length ({len(direct_resp.content)} bytes)."
                            ),
                            remediation="Restrict origin web server ingress firewall rules to allow traffic exclusively from WAF/CDN IP ranges.",
                            cwe="CWE-284",
                            confidence="SIGNAL",
                        )
                    )
            except httpx.HTTPError:
                pass  # Direct IP blocked or TLS SNI mismatch — expected for properly isolated origins

        # 4. Shadow / Non-Production Subdomain DNS & Reachability Check (WSTG-INFO-01/04)
        base_domain = _extract_registrable_domain(hostname)
        if base_domain:
            exposed_shadows: list[str] = []
            for prefix in COMMON_SHADOW_SUBDOMAINS:
                candidate_host = f"{prefix}.{base_domain}"
                if candidate_host == hostname.lower():
                    continue
                try:
                    sub_addrs = await loop.getaddrinfo(candidate_host, port, type=socket.SOCK_STREAM)
                except OSError:
                    continue

                if sub_addrs:
                    sub_url = f"{scheme}://{candidate_host}/"
                    try:
                        sub_resp = await client.get(sub_url)
                        if sub_resp.status_code < 500:
                            exposed_shadows.append(f"{candidate_host} (HTTP {sub_resp.status_code})")
                    except httpx.HTTPError:
                        exposed_shadows.append(f"{candidate_host} (DNS resolved)")

            if exposed_shadows:
                findings.append(
                    ProbeFinding(
                        rule_id=f"{check.id}:httpx_arch_and_dns:shadow_subdomains",
                        title="Publicly Resolvable Non-Production / Shadow Subdomain(s) Detected",
                        severity="Medium",
                        evidence=f"Discovered active non-production host(s): {', '.join(exposed_shadows)}.",
                        remediation="Restrict dev/staging/UAT/admin subdomains to internal VPN/allowlisted IPs and remove stale DNS records.",
                        cwe="CWE-200",
                        confidence="SIGNAL",
                    )
                )

    return ProbeOutcome(
        findings=findings,
        summary=" ".join(arch_notes),
        conclusive=True,
    )