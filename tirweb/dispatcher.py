import asyncio
import shutil
from datetime import datetime, timezone
from typing import Callable, Awaitable
from pydantic import BaseModel
from .models import AuthContext, ChecklistItem, ChecklistModule, ExecutionMode
from .probes import (
    ScanContext,
    probe_cors_policy,
    probe_differential_idor,
    probe_jwt_security,
    probe_security_headers,
)


class CheckExecutionResult(BaseModel):
    check_id: str
    module_id: str
    title: str
    severity: str
    execution_mode: ExecutionMode
    status: str  # PASS | FAIL | MANUAL_REQUIRED | TOOL_MISSING | ERROR
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


# --- Tool Binding Adapters ---
# Updated handler signature accepting AuthContext

async def bind_testssl(
    target: str, check: ChecklistItem, auth: AuthContext
) -> tuple[bool, str]:
    # TLS handshake inspection operates at transport layer (no HTTP auth headers needed)
    code, out = await _run_subprocess(["testssl.sh", "--quiet", "--warnings", "off", target])
    if code == 127:
        raise FileNotFoundError(out)
    vulnerable = "VULNERABLE" in out or "NOT ok" in out
    return (not vulnerable), out or "TLS scan completed."


async def bind_nuclei(tag: str) -> ToolHandler:
    async def _handler(
        target: str, check: ChecklistItem, auth: AuthContext
    ) -> tuple[bool, str]:
        cmd = ["nuclei", "-u", target, "-tags", tag, "-silent", "-nc"]
        # Inject Authorization, Cookie, and custom headers via repeatable -H flags
        for header_line in auth.to_cli_header_strings():
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
    target: str, check: ChecklistItem, auth: AuthContext
) -> tuple[bool, str]:
    code, out = await _run_subprocess(
        ["trivy", "fs", "--severity", "HIGH,CRITICAL", "--quiet", "."]
    )
    if code == 127:
        raise FileNotFoundError(out)
    has_vulns = "Total:" in out and "Total: 0" not in out
    return (not has_vulns), out or "SCA check completed."


'''
async def bind_testssl(target: str, check: ChecklistItem) -> tuple[bool, str]:
    code, out = await _run_subprocess(["testssl.sh", "--quiet", "--warnings", "off", target])
    if code == 127:
        raise FileNotFoundError(out)
    vulnerable = "VULNERABLE" in out or "NOT ok" in out
    return (not vulnerable), out or "TLS scan completed."


async def bind_nuclei(tag: str) -> ToolHandler:
    async def _handler(target: str, check: ChecklistItem) -> tuple[bool, str]:
        code, out = await _run_subprocess(
            ["nuclei", "-u", target, "-tags", tag, "-silent", "-nc"]
        )
        if code == 127:
            raise FileNotFoundError(out)
        findings = [line for line in out.splitlines() if line.strip()]
        return (len(findings) == 0), (f"Found {len(findings)} issue(s):\n" + "\n".join(findings) if findings else "No nuclei findings.")
    return _handler


async def bind_trivy_sca(target: str, check: ChecklistItem) -> tuple[bool, str]:
    # Expects target repo/path or container reference via environment/target
    code, out = await _run_subprocess(["trivy", "fs", "--severity", "HIGH,CRITICAL", "--quiet", "."])
    if code == 127:
        raise FileNotFoundError(out)
    has_vulns = "Total:" in out and "Total: 0" not in out
    return (not has_vulns), out or "SCA check completed."
'''

class ToolDispatcher:
    def __init__(self, concurrency: int = 4) -> None:
        self.semaphore = asyncio.Semaphore(concurrency)
        self.registry: dict[str, ToolHandler] = {
            # Native Python HTTPx probes
            "httpx_headers": probe_security_headers,
            "httpx_cors": probe_cors_policy,
            "httpx_idor_diff": probe_differential_idor,
            "httpx_jwt": probe_jwt_security,
            # External CLI scanners wrapped to accept ScanContext
            "testssl": lambda t, c, ctx: bind_testssl(t, c, ctx.primary_auth),
            "trivy_sca": lambda t, c, ctx: bind_trivy_sca(t, c, ctx.primary_auth),
        }

    async def initialize_dynamic_bindings(self) -> None:
        for binding_name, tags in {
            "nuclei_bola": "idor,bola",
            "nuclei_bfla": "auth-bypass,bfla",
            "nuclei_auth": "auth,oauth,saml",
            "nuclei_injection": "sqli,ssti,cmdi,xxe",
            "nuclei_ssrf": "ssrf",
            "nuclei_exposures": "exposure,misconfig,cors,headers",
        }.items():
            base_handler = await bind_nuclei(tags)
            self.registry[binding_name] = (
                lambda h=base_handler: lambda t, c, ctx: h(t, c, ctx.primary_auth)
            )()

    async def execute_check(
        self,
        target: str,
        module: ChecklistModule,
        check: ChecklistItem,
        auth: AuthContext | None = None,
        dry_run: bool = False,
    ) -> CheckExecutionResult:
        auth_ctx = auth or AuthContext()
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
                f" (authenticated: {', '.join(auth_ctx.to_http_headers().keys())})"
                if auth_ctx.is_authenticated
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
            overall_pass = True
            missing_tools: list[str] = []

            for binding in check.tool_binding:
                handler = self.registry.get(binding)
                if not handler:
                    logs.append(f"[{binding}] Manual/unregistered plugin hook.")
                    continue
                try:
                    passed, detail = await handler(target, check, auth_ctx)
                    overall_pass = overall_pass and passed
                    logs.append(f"[{binding}] {'PASS' if passed else 'FAIL'}: {detail}")
                except FileNotFoundError as exc:
                    missing_tools.append(binding)
                    logs.append(f"[{binding}] SKIPPED: {exc}")
                except Exception as exc:
                    overall_pass = False
                    logs.append(f"[{binding}] ERROR: {exc}")

            if missing_tools and len(missing_tools) == len(check.tool_binding):
                status = "TOOL_MISSING"
            elif not overall_pass:
                status = "FAIL"
            elif check.execution_mode == ExecutionMode.HYBRID:
                status = "HYBRID_REVIEW"
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
    