import asyncio
import shutil
from datetime import datetime, timezone
from typing import Awaitable, Callable
from pydantic import BaseModel
from .models import AuthContext, ChecklistItem, ChecklistModule, ExecutionMode
from .probes import (
    ScanContext,
    probe_cors_policy,
    probe_differential_idor,
    probe_graphql_security,
    probe_jwt_security,
    probe_metafiles_and_ria_policies,
    probe_open_redirect,
    probe_path_confusion,
    probe_security_headers,
)


class CheckExecutionResult(BaseModel):
    check_id: str
    module_id: str
    title: str
    severity: str
    execution_mode: ExecutionMode
    status: str  # PASS | FAIL | HYBRID_REVIEW | MANUAL_REQUIRED | TOOL_MISSING | INCONCLUSIVE | DRY_RUN | ERROR
    tools_invoked: list[str]
    output_summary: str
    india_compliance: list[str]
    global_compliance: list[str]
    timestamp: str


ToolHandler = Callable[[str, ChecklistItem, ScanContext], Awaitable[tuple[bool, str]]]


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


# --- External Tool Binding Adapters ---

async def bind_testssl(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    code, out = await _run_subprocess(["testssl.sh", "--quiet", "--warnings", "off", target])
    if code == 127:
        raise FileNotFoundError(out)
    if code != 0:
        return False, out or f"testssl.sh exited with code {code}."
    vulnerable = "VULNERABLE" in out or "NOT ok" in out
    return (not vulnerable), out or "TLS scan completed."


async def bind_nuclei(tag: str) -> ToolHandler:
    async def _handler(
        target: str, check: ChecklistItem, ctx: ScanContext
    ) -> tuple[bool, str]:
        cmd = ["nuclei", "-u", target, "-tags", tag, "-silent", "-nc"]
        for header_line in ctx.primary_auth.to_cli_header_strings():
            cmd.extend(["-H", header_line])

        code, out = await _run_subprocess(cmd)
        if code == 127:
            raise FileNotFoundError(out)
        findings = [line for line in out.splitlines() if line.strip()]
        return (
            len(findings) == 0,
            f"Found {len(findings)} issue(s):\n" + "\n".join(findings)
            if findings
            else "No nuclei findings.",
        )

    return _handler


async def bind_trivy_sca(
    target: str, check: ChecklistItem, ctx: ScanContext
) -> tuple[bool, str]:
    code, out = await _run_subprocess(
        ["trivy", "fs", "--severity", "HIGH,CRITICAL", "--quiet", "."]
    )
    if code == 127:
        raise FileNotFoundError(out)
    if code != 0:
        return False, out or f"trivy exited with code {code}."
    has_vulns = "Total:" in out and "Total: 0" not in out
    return (not has_vulns), out or "SCA check completed."


class ToolDispatcher:
    def __init__(self, concurrency: int = 4) -> None:
        self.semaphore = asyncio.Semaphore(concurrency)
        self.registry: dict[str, ToolHandler] = {
            # Native Python HTTPx probes
            "httpx_headers": probe_security_headers,
            "httpx_cors": probe_cors_policy,
            "httpx_idor_diff": probe_differential_idor,
            "httpx_jwt": probe_jwt_security,
            "httpx_metafiles": probe_metafiles_and_ria_policies,
            "httpx_path_confusion": probe_path_confusion,
            "httpx_open_redirect": probe_open_redirect,
            "httpx_graphql": probe_graphql_security,
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

        if check.execution_mode == ExecutionMode.MANUAL:
            return CheckExecutionResult(
                check_id=check.id,
                module_id=module.module_id,
                title=check.title,
                severity=check.severity.value,
                execution_mode=check.execution_mode,
                status="MANUAL_REQUIRED",
                tools_invoked=check.tool_binding,
                output_summary="Queued for manual pentest playbook verification.",
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
                execution_mode=check.execution_mode,
                status="DRY_RUN",
                tools_invoked=check.tool_binding,
                output_summary=f"Would dispatch bindings: {', '.join(check.tool_binding)}{auth_note}",
                india_compliance=check.compliance.india,
                global_compliance=check.compliance.global_,
                timestamp=now,
            )

        async with self.semaphore:
            logs: list[str] = []
            observed_failure = False
            missing_tools: list[str] = []
            execution_errors: list[str] = []
            requires_manual_review = False
            inconclusive = False
            executed = 0

            for binding in check.tool_binding:
                handler = self.registry.get(binding)
                if not handler:
                    requires_manual_review = True
                    logs.append(f"[{binding}] MANUAL_REQUIRED: No executable adapter is registered.")
                    continue
                try:
                    passed, detail = await handler(target, check, scan_ctx)
                    if ("SKIPPED_" in detail or detail.lstrip().upper().startswith("SKIPPED")
                            or detail.lstrip().upper().startswith("INCONCLUSIVE_")):
                        inconclusive = True
                        logs.append(f"[{binding}] INCONCLUSIVE: {detail}")
                    else:
                        executed += 1
                        observed_failure = observed_failure or not passed
                        logs.append(f"[{binding}] {'PASS' if passed else 'FAIL'}: {detail}")
                except FileNotFoundError as exc:
                    missing_tools.append(binding)
                    logs.append(f"[{binding}] TOOL_MISSING: {exc}")
                except Exception as exc:
                    execution_errors.append(binding)
                    logs.append(f"[{binding}] ERROR: {type(exc).__name__}: {exc}")

            # A FAIL requires affirmative evidence from an executed control.
            # Network errors, skipped prerequisites and absent tools are not vulnerabilities.
            if observed_failure:
                status = "FAIL"
            elif execution_errors:
                status = "ERROR"
            elif missing_tools:
                status = "TOOL_MISSING"
            elif requires_manual_review or check.execution_mode == ExecutionMode.HYBRID:
                status = "HYBRID_REVIEW"
            elif inconclusive:
                status = "INCONCLUSIVE"
            elif executed == 0:
                status = "MANUAL_REQUIRED"
            else:
                status = "PASS"

            return CheckExecutionResult(
                check_id=check.id,
                module_id=module.module_id,
                title=check.title,
                severity=check.severity.value,
                execution_mode=check.execution_mode,
                status=status,
                tools_invoked=check.tool_binding,
                output_summary="\n".join(logs) if logs else "No automated bindings configured.",
                india_compliance=check.compliance.india,
                global_compliance=check.compliance.global_,
                timestamp=now,
            )