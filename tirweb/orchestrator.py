from __future__ import annotations

import asyncio
import random
import re
from typing import Awaitable, Callable, TypeVar
from urllib.parse import urljoin, urlparse
import httpx
from .dispatcher import CheckExecutionResult, ToolDispatcher
from .models import AuthContext, ChecklistItem, ChecklistModule, ProbeFinding
from .probes import ScanContext, resolve_endpoint

T = TypeVar("T")


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    *,
    retries: int = 2,
    base_delay: float = 0.75,
    retry_on: tuple[type[Exception], ...] = (
        httpx.TimeoutException,
        httpx.NetworkError,
        TimeoutError,
    ),
) -> T:
    """Bounded exponential-backoff retry for transient network/rate-limit blips."""
    attempt = 0
    while True:
        try:
            return await fn()
        except retry_on:
            attempt += 1
            if attempt > retries:
                raise
            await asyncio.sleep(base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.25))


async def discover_target_surface(
    target: str, ctx: ScanContext, max_paths: int = 25
) -> list[str]:
    """
    Phase-0 one-hop discovery: harvests relative paths from /robots.txt, /sitemap.xml,
    and landing HTML <a href> / <form action> tags before parallel check execution.
    """
    discovered: set[str] = set()
    origin_netloc = urlparse(target).netloc

    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=True,
        trust_env=True,
        headers=ctx.primary_auth.to_http_headers(),
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        # 1. Harvest Disallow / Allow paths from /robots.txt
        try:
            robots = await with_retry(lambda: client.get(urljoin(target, "/robots.txt")))
            if robots.status_code == 200:
                for line in robots.text.splitlines():
                    m = re.match(r"^(?:Disallow|Allow):\s*(/[^\s#]+)", line.strip(), re.IGNORECASE)
                    if m and "*" not in m.group(1):
                        discovered.add(m.group(1))
        except Exception:
            pass

        # 2. Harvest <loc> paths from /sitemap.xml
        try:
            sitemap = await with_retry(lambda: client.get(urljoin(target, "/sitemap.xml")))
            if sitemap.status_code == 200:
                for loc in re.findall(r"<loc>\s*(https?://[^<]+)\s*</loc>", sitemap.text, re.IGNORECASE):
                    parsed = urlparse(loc.strip())
                    if parsed.netloc == origin_netloc and parsed.path:
                        discovered.add(parsed.path)
        except Exception:
            pass

        # 3. Harvest same-origin <a href> and <form action> routes from landing page
        try:
            home = await with_retry(lambda: client.get(target))
            if home.status_code == 200:
                for raw_ref in re.findall(r'(?:href|action)=["\']([^"\'#?]+)["\']', home.text, re.IGNORECASE):
                    if raw_ref.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
                        continue
                    resolved = urlparse(urljoin(str(home.url), raw_ref))
                    if resolved.netloc == origin_netloc and resolved.path and resolved.path != "/":
                        discovered.add(resolved.path)
        except Exception:
            pass

    existing = set(ctx.probe_endpoints or [])
    merged = list(ctx.probe_endpoints or []) + [p for p in sorted(discovered) if p not in existing]
    return merged[:max_paths]


async def evaluate_privilege_tiers(
    target: str,
    check: ChecklistItem,
    ctx: ScanContext,
) -> list[ProbeFinding]:
    """
    Compare HTTP status across configured privilege tiers (unauthenticated,
    secondary_auth [low-priv], primary_auth [high-priv]) on discovered/configured endpoints.
    """
    if not ctx.probe_endpoints or not ctx.primary_auth.is_authenticated:
        return []

    tiers: list[tuple[str, AuthContext]] = [("unauthenticated", AuthContext())]
    if ctx.secondary_auth and ctx.secondary_auth.is_authenticated:
        tiers.append(("low_priv", ctx.secondary_auth))
    tiers.append(("high_priv", ctx.primary_auth))

    findings: list[ProbeFinding] = []
    async with httpx.AsyncClient(
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=False,  # 302 to login is an access-denied signal; never follow
        trust_env=True,
        event_hooks={"request": [ctx.track_request]},
    ) as client:
        for ep in ctx.probe_endpoints[:15]:
            url = resolve_endpoint(target, ep)
            statuses: dict[str, int] = {}
            for label, auth_ctx in tiers:
                try:
                    resp = await with_retry(
                        lambda h=auth_ctx.to_http_headers(): client.get(url, headers=h)
                    )
                    statuses[label] = resp.status_code
                except Exception:
                    statuses[label] = -1

            high_code = statuses.get("high_priv", -1)
            if 200 <= high_code < 300:
                for lower_tier in ("unauthenticated", "low_priv"):
                    low_code = statuses.get(lower_tier, -1)
                    if 200 <= low_code < 300:
                        findings.append(
                            ProbeFinding(
                                rule_id=f"{check.id}:priv_tier_diff:{lower_tier}_vs_high_priv:{ep}",
                                title=f"Endpoint '{ep}' Accessible to '{lower_tier}' Tier (HTTP {low_code})",
                                severity="High",
                                evidence=(
                                    f"GET {url} returned HTTP {low_code} for '{lower_tier}' "
                                    f"and HTTP {high_code} for 'high_priv'."
                                ),
                                remediation="Enforce role-based and object-level authorization checks server-side.",
                                cwe="CWE-284",
                                confidence="SIGNAL",
                            )
                        )
    return findings


def detect_session_expiry(results: list[CheckExecutionResult]) -> list[str]:
    """Identify checks that failed with 401/authentication-required after earlier checks succeeded."""
    flagged: list[str] = []
    seen_authed_success = False
    for res in results:
        if res.status in {"NO_ISSUES_FOUND", "FAIL"} and res.bindings_executed > 0:
            seen_authed_success = True
        elif res.status == "INCONCLUSIVE" and "authentication-required" in res.output_summary.lower():
            if seen_authed_success:
                flagged.append(res.check_id)
    return flagged


async def run_audit_pipeline(
    dispatcher: ToolDispatcher,
    target: str,
    selected: list[tuple[ChecklistModule, ChecklistItem]],
    scan_ctx: ScanContext,
    dry_run: bool = False,
) -> list[CheckExecutionResult]:
    """
    Full orchestrated scan loop:
      1. Phase-0 one-hop surface discovery (robots.txt, sitemap.xml, landing links/forms)
      2. Concurrent check execution via ToolDispatcher
      3. Privilege-tier differential enrichment on WEB-IAM-001/002/008
      4. Mid-scan session-expiry detection warning
    """
    if not dry_run:
        scan_ctx.probe_endpoints = await discover_target_surface(target, scan_ctx)

    tasks = [
        dispatcher.execute_check(
            target=target, module=mod, check=chk, ctx=scan_ctx, dry_run=dry_run
        )
        for mod, chk in selected
    ]
    results = list(await asyncio.gather(*tasks))

    # Enrich access-control checks with tiered privilege diff findings when authenticated
    if not dry_run and scan_ctx.primary_auth.is_authenticated:
        for res in results:
            if res.check_id in {"WEB-IAM-001", "WEB-IAM-002", "WEB-IAM-008"}:
                dummy_item = next(chk for _, chk in selected if chk.id == res.check_id)
                tier_findings = await evaluate_privilege_tiers(target, dummy_item, scan_ctx)
                if tier_findings:
                    res.findings.extend(tier_findings)
                    res.status = "FAIL"
                    res.conclusive = True
                    res.output_summary += (
                        f"\n[priv_tier_diff] Flagged {len(tier_findings)} cross-tier access candidate(s)."
                    )

    expired_ids = detect_session_expiry(results)
    if expired_ids:
        for res in results:
            if res.check_id in expired_ids:
                res.output_summary += (
                    "\n[session_monitor] Possible mid-scan session expiry detected (401 after earlier 200s); "
                    "refresh --auth-file token and re-run."
                )

    return results