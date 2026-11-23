import asyncio
import shutil
from datetime import datetime, timezone
from typing import Awaitable, Callable
from pydantic import BaseModel, Field
from .models import (
    AuthContext,
    CheckStatus,
    ChecklistItem,
    ChecklistModule,
    ExecutionMode,
    ManualPlaybookEntry,
    ProbeFinding,
    ProbeOutcome,
)
from .probes import (
    ScanContext,
    probe_api_authentication,
    probe_architecture_and_dns,
    probe_auth_surface,
    probe_bfla_exposed_panels,
    probe_cache_headers,
    probe_canary_injection,
    probe_client_assets_and_sri,
    probe_cookie_security,
    probe_cors_policy,
    probe_csrf_tokens,
    probe_cve_fingerprint,
    probe_differential_default_creds,
    probe_differential_idor,
    probe_directory_and_default_pages,
    probe_exposed_build_artifacts,
    probe_graphql_security,
    probe_http_methods,
    probe_http_parameter_pollution,
    probe_jwt_security,
    probe_metafiles_and_ria_policies,
    probe_open_redirect,
    probe_path_confusion,
    probe_security_headers,
    probe_source_comments_and_file_metadata,
    probe_tls_and_https,
    probe_verbose_errors,
)

MANUAL_BINDINGS = {"manual_proxy", "manual_review"}


class CheckExecutionResult(BaseModel):
    check_id: str
    module_id: str
    title: str
    severity: str
    execution_mode: str  # Always serialized string value ("automated" | "hybrid" | "manual")
    status: CheckStatus
    conclusive: bool
    bindings_executed: int
    bindings_total: int
    coverage_label: str
    tools_invoked: list[str]
    missing_tools: list[str] = Field(default_factory=list)
    findings: list[ProbeFinding] = Field(default_factory=list)
    manual_playbook: ManualPlaybookEntry | None = None
    output_summary: str
    india_compliance: list[str]
    global_compliance: list[str]
    timestamp: str


ToolHandler = Callable[[str, ChecklistItem, ScanContext], Awaitable[ProbeOutcome | tuple[bool, str]]]


async def _run_subprocess(cmd: list[str], timeout: int = 180) -> tuple[int, str]:
    if not shutil.which(cmd[0]):
        return 127, f"Binary '{cmd[0]}' not found in PATH"
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, f"Command timed out after {timeout}s"
    combined = (stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")).strip()
    return proc.returncode or 0, combined[-1500:]


def _normalize_outcome(
    binding: str,
    check: ChecklistItem,
    raw_result: ProbeOutcome | tuple[bool, str],
) -> ProbeOutcome:
    """Bridge legacy (bool, str) probes and structured ProbeOutcome instances."""
    if isinstance(raw_result, ProbeOutcome):
        return raw_result

    passed, detail = raw_result
    is_skipped = detail.startswith("SKIPPED_") or detail.startswith("INCONCLUSIVE_")
    if is_skipped:
        return ProbeOutcome(findings=[], summary=detail, conclusive=False)

    if passed:
        return ProbeOutcome(findings=[], summary=detail, conclusive=True)

    # Split multi-line bullet findings from legacy probes into atomic ProbeFinding items
    lines = [ln.lstrip("- ").strip() for ln in detail.splitlines() if ln.strip()]
    header_line = lines[0] if lines else detail
    bullet_lines = lines[1:] if len(lines) > 1 else [header_line]

    atomic_findings = [
        ProbeFinding(
            rule_id=f"{check.id}:{binding}:{idx}",
            title=bullet[:120],
            severity=check.severity.value,
            evidence=bullet,
            remediation=f"Review and remediate finding under {check.id} ({binding}).",
        )
        for idx, bullet in enumerate(bullet_lines, start=1)
    ]
    return ProbeOutcome(findings=atomic_findings, summary=detail, conclusive=True)


# --- External Tool Binding Adapters ---

async def bind_testssl(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    code, out = await _run_subprocess(["testssl.sh", "--quiet", "--warnings", "off", target])
    if code == 127:
        raise FileNotFoundError(out)
    if code != 0:
        return ProbeOutcome(
            findings=[
                ProbeFinding(
                    rule_id=f"{check.id}:testssl:err",
                    title="TLS/SSL Scanner Execution Error",
                    severity=check.severity.value,
                    evidence=out or f"testssl.sh exited with code {code}.",
                    remediation="Verify target TLS reachability and re-run testssl.sh.",
                )
            ],
            summary=out or f"testssl.sh exited with code {code}.",
            conclusive=False,
        )
    vulnerable = "VULNERABLE" in out or "NOT ok" in out
    findings = (
        [
            ProbeFinding(
                rule_id=f"{check.id}:testssl:1",
                title="Weak TLS Protocol, Cipher Suite, or Certificate Configuration",
                severity=check.severity.value,
                evidence=out,
                remediation="Enforce TLS 1.2/1.3 with AEAD cipher suites and valid X.509 certificates.",
                cwe="CWE-326",
            )
        ]
        if vulnerable
        else []
    )
    return ProbeOutcome(
        findings=findings,
        summary=out or "No TLS protocol/cipher issues detected within testssl.sh scope.",
        conclusive=True,
    )


async def bind_nuclei(tag: str) -> ToolHandler:
    async def _handler(
        target: str, check: ChecklistItem, ctx: ScanContext
    ) -> ProbeOutcome:
        cmd = ["nuclei", "-u", target, "-tags", tag, "-silent", "-nc"]
        for header_line in ctx.primary_auth.to_cli_header_strings():
            cmd.extend(["-H", header_line])

        code, out = await _run_subprocess(cmd)
        if code == 127:
            # Graceful native async fallbacks when external nuclei binary is absent
            if tag == "auth-bypass,bfla":
                return await probe_bfla_exposed_panels(target, check, ctx)
            if tag == "auth,oauth,saml":
                return await probe_differential_default_creds(target, check, ctx)
            # For idor,bola / injection / ssrf / exposures: never guess unauthenticated; report tooling gap
            raise FileNotFoundError(out)

        raw_findings = [line.strip() for line in out.splitlines() if line.strip()]
        findings = [
            ProbeFinding(
                rule_id=f"{check.id}:nuclei:{idx}",
                title=line[:120],
                severity=check.severity.value,
                evidence=line,
                remediation="Patch or harden the affected endpoint identified by Nuclei template.",
            )
            for idx, line in enumerate(raw_findings, start=1)
        ]
        summary = (
            f"Found {len(findings)} issue(s):\n" + "\n".join(raw_findings)
            if findings
            else f"No issues detected by nuclei (-tags {tag}) within template scope."
        )
        return ProbeOutcome(findings=findings, summary=summary, conclusive=True)

    return _handler


async def bind_trivy_sca(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> ProbeOutcome:
    code, out = await _run_subprocess(
        ["trivy", "fs", "--severity", "HIGH,CRITICAL", "--quiet", "."]
    )
    if code == 127:
        raise FileNotFoundError(out)
    has_vulns = code != 0 or ("Total:" in out and "Total: 0" not in out)
    findings = (
        [
            ProbeFinding(
                rule_id=f"{check.id}:trivy:1",
                title="High/Critical Vulnerable Third-Party Dependencies Detected",
                severity=check.severity.value,
                evidence=out or f"trivy exited with code {code}.",
                remediation="Upgrade vulnerable dependencies to patched versions and regenerate SBOM.",
                cwe="CWE-1395",
            )
        ]
        if has_vulns
        else []
    )
    return ProbeOutcome(
        findings=findings,
        summary=out or "No HIGH/CRITICAL dependency CVEs detected within local workspace scan.",
        conclusive=True,
    )


def summarize_tooling_gaps(results: list[CheckExecutionResult]) -> list[dict[str, object]]:
    """Aggregate missing external CLI tools across all checks into a single consolidated summary."""
    by_tool: dict[str, list[str]] = {}
    for res in results:
        for tool in res.missing_tools:
            by_tool.setdefault(tool, []).append(res.check_id)
    return [
        {
            "tool": tool,
            "affected_checks_count": len(check_ids),
            "affected_check_ids": sorted(check_ids),
            "remediation": f"Install '{tool}' or run inside the official TIRweb Docker image.",
        }
        for tool, check_ids in sorted(by_tool.items())
    ]


class ToolDispatcher:
    def __init__(self, concurrency: int = 4) -> None:
        self.semaphore = asyncio.Semaphore(concurrency)
        self.registry: dict[str, ToolHandler] = {
            # Native Python HTTPx probes (19 bindings)
            "httpx_tls": probe_tls_and_https,
            "httpx_headers": probe_security_headers,
            "httpx_cookies": probe_cookie_security,
            "httpx_methods": probe_http_methods,
            "httpx_discovery": probe_directory_and_default_pages,
            "httpx_errors": probe_verbose_errors,
            "httpx_auth_surface": probe_auth_surface,
            "httpx_cache": probe_cache_headers,
            "httpx_csrf": probe_csrf_tokens,
            "httpx_client_assets": probe_client_assets_and_sri,
            "httpx_cve_fingerprint": probe_cve_fingerprint,
            "httpx_canary_inj": probe_canary_injection,
            "httpx_cors": probe_cors_policy,
            "httpx_idor_diff": probe_differential_idor,
            "httpx_jwt": probe_jwt_security,
            "httpx_metafiles": probe_metafiles_and_ria_policies,
            "httpx_path_confusion": probe_path_confusion,
            "httpx_open_redirect": probe_open_redirect,
            "httpx_graphql": probe_graphql_security,
            "httpx_api_auth": probe_api_authentication,
            "httpx_exposed_artifacts": probe_exposed_build_artifacts,
            "httpx_source_metadata": probe_source_comments_and_file_metadata,
            "httpx_hpp_consistency": probe_http_parameter_pollution,
            "httpx_arch_and_dns": probe_architecture_and_dns,
            # External CLI scanners
            "testssl": bind_testssl,
            "trivy_sca": bind_trivy_sca,
        }

    async def initialize_dynamic_bindings(self) -> None:
        nuclei_tag_map = {
            "nuclei_bola": "idor,bola",
            "nuclei_bfla": "auth-bypass,bfla",
            "nuclei_auth": "auth,oauth,saml",
            "nuclei_injection": "sqli,ssti,cmdi,xxe",
            "nuclei_ssrf": "ssrf",
            "nuclei_exposures": "exposure,misconfig,cors,headers",
        }
        for binding_name, tags in nuclei_tag_map.items():
            self.registry[binding_name] = await bind_nuclei(tags)

    async def execute_check(
        self,
        target: str,
        module: ChecklistModule,
        check: ChecklistItem,
        ctx: ScanContext | AuthContext | None = None,
        dry_run: bool = False,
    ) -> CheckExecutionResult:
        if isinstance(ctx, AuthContext):
            scan_ctx = ScanContext(primary_auth=ctx)
        else:
            scan_ctx = ctx or ScanContext(primary_auth=AuthContext())

        now = datetime.now(timezone.utc).isoformat()
        bindings_total = len(check.tool_binding)
        has_manual_binding = (
            check.execution_mode in {ExecutionMode.MANUAL, ExecutionMode.HYBRID}
            or bool(MANUAL_BINDINGS.intersection(check.tool_binding))
        )
        playbook = (
            ManualPlaybookEntry(steps=list(check.test_procedures))
            if has_manual_binding
            else None
        )

        if check.execution_mode == ExecutionMode.MANUAL:
            return CheckExecutionResult(
                check_id=check.id,
                module_id=module.module_id,
                title=check.title,
                severity=check.severity.value,
                execution_mode=check.execution_mode.value,
                status="MANUAL_REQUIRED",
                conclusive=False,
                bindings_executed=0,
                bindings_total=bindings_total,
                coverage_label=f"0 of {bindings_total} automated bindings (manual playbook)",
                tools_invoked=check.tool_binding,
                manual_playbook=playbook,
                output_summary="Manual verification playbook ready (awaiting tester execution & evidence).",
                india_compliance=check.compliance.india,
                global_compliance=check.compliance.global_,
                timestamp=now,
            )

        if dry_run:
            auth_note = (
                f" (authenticated: {', '.join(scan_ctx.primary_auth.to_http_headers().keys())})"
                if scan_ctx.primary_auth.is_authenticated
                else " (unauthenticated)"
            )
            return CheckExecutionResult(
                check_id=check.id,
                module_id=module.module_id,
                title=check.title,
                severity=check.severity.value,
                execution_mode=check.execution_mode.value,
                status="DRY_RUN",
                conclusive=False,
                bindings_executed=0,
                bindings_total=bindings_total,
                coverage_label=f"0 of {bindings_total} bindings executed (dry-run)",
                tools_invoked=check.tool_binding,
                manual_playbook=playbook,
                output_summary=f"Would dispatch bindings: {', '.join(check.tool_binding)}{auth_note}",
                india_compliance=check.compliance.india,
                global_compliance=check.compliance.global_,
                timestamp=now,
            )

        async with self.semaphore:
            logs: list[str] = []
            collected_findings: list[ProbeFinding] = []
            missing_tools: list[str] = []
            bindings_executed = 0
            conclusive_runs = 0

            for binding in check.tool_binding:
                if binding in MANUAL_BINDINGS:
                    logs.append(f"[{binding}] Manual playbook verification queued.")
                    continue

                handler = self.registry.get(binding)
                if not handler:
                    logs.append(f"[{binding}] Unregistered plugin hook.")
                    continue

                try:
                    raw_res = await handler(target, check, scan_ctx)
                    outcome = _normalize_outcome(binding, check, raw_res)
                    bindings_executed += 1
                    if outcome.conclusive:
                        conclusive_runs += 1
                    collected_findings.extend(outcome.findings)

                    if outcome.findings:
                        label = f"FAIL ({len(outcome.findings)} finding(s))"
                    elif not outcome.conclusive:
                        label = "INCONCLUSIVE"
                    else:
                        label = "NO_ISSUES_FOUND"
                    logs.append(f"[{binding}] {label}: {outcome.summary}")
                except FileNotFoundError:
                    missing_tools.append(binding)
                    logs.append(f"[{binding}] Tooling gap: external binary not installed.")
                except RuntimeError as exc:
                    # Request budget exhausted -> mark inconclusive, never false pass/fail
                    logs.append(f"[{binding}] INCONCLUSIVE (budget cap): {exc}")
                except Exception as exc:
                    logs.append(f"[{binding}] Probe execution error: {exc}")
                

            coverage_label = f"{bindings_executed} of {bindings_total} bindings executed"

            # Coverage-aware status roll-up:
            # 1. Any affirmative finding -> FAIL
            # 2. At least one binding ran cleanly -> HYBRID_REVIEW (if manual step exists) or NO_ISSUES_FOUND
            # 3. Zero bindings ran conclusively (e.g., all external tools missing or skipped) -> INCONCLUSIVE
            if collected_findings:
                status: CheckStatus = "FAIL"
                is_conclusive = True
            elif conclusive_runs > 0:
                if has_manual_binding:
                    status = "HYBRID_REVIEW"
                    is_conclusive = False
                else:
                    status = "NO_ISSUES_FOUND"
                    is_conclusive = True
            else:
                status = "INCONCLUSIVE"
                is_conclusive = False

            return CheckExecutionResult(
                check_id=check.id,
                module_id=module.module_id,
                title=check.title,
                severity=check.severity.value,
                execution_mode=check.execution_mode.value,
                status=status,
                conclusive=is_conclusive,
                bindings_executed=bindings_executed,
                bindings_total=bindings_total,
                coverage_label=coverage_label,
                tools_invoked=check.tool_binding,
                missing_tools=missing_tools,
                findings=collected_findings,
                manual_playbook=playbook,
                output_summary="\n".join(logs) if logs else "No automated bindings configured.",
                india_compliance=check.compliance.india,
                global_compliance=check.compliance.global_,
                timestamp=now,
            )