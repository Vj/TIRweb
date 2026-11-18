import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional
import typer
from rich.console import Console
from rich.table import Table
from .dispatcher import ToolDispatcher
from .models import AppProfile, AuthContext, ExecutionMode, TIRWebChecklist
from .probes import ScanContext
from .reporter import generate_compliance_report, generate_html_report
from .scope import validate_scan_scope

app = typer.Typer(
    name="tirweb",
    help="TIRweb: OWASP, Advanced Pentest & Indian Regulatory Compliance Runner",
    no_args_is_help=True,
)
console = Console()


@app.command("validate")
def validate_checklist(
    checklist: Annotated[
        Path,
        typer.Option("--checklist", "-c", exists=True, help="Path to TIRweb YAML checklist"),
    ],
) -> None:
    """Validate YAML checklist syntax, regex patterns, and compliance mappings."""
    loaded = TIRWebChecklist.from_yaml(checklist)
    total_checks = sum(len(m.checks) for m in loaded.modules)
    console.print(
        f"[bold green]Valid TIRweb Checklist[/bold green] v{loaded.schema_version} "
        f"({len(loaded.modules)} modules, {total_checks} checks)"
    )


@app.command("scan")
def run_scan(
    target: Annotated[str, typer.Option("--target", "-t", help="Target base URL (e.g. https://staging.example.in)")],
    checklist: Annotated[
        Path,
        typer.Option("--checklist", "-c", exists=True, help="Path to TIRweb YAML checklist"),
    ],
    profile: Annotated[
        AppProfile,
        typer.Option("--profile", "-p", help="Application domain profile"),
    ] = AppProfile.CORE,
    client: Annotated[
        str,
        typer.Option("--client", help="Client or entity name for the HTML report header"),
    ] = "Target Organization",
    auditor: Annotated[
        str,
        typer.Option("--auditor", help="Assessing team or organization name"),
    ] = "Security Assessment Team",
    header: Annotated[
        Optional[list[str]],
        typer.Option("--header", "-H", help="Custom header in 'Name: Value' format (repeatable)"),
    ] = None,
    bearer_token: Annotated[
        Optional[str],
        typer.Option(
            "--bearer-token",
            envvar="TIRWEB_BEARER_TOKEN",
            help="Bearer token for Authorization header (or set TIRWEB_BEARER_TOKEN)",
        ),
    ] = None,
    cookie: Annotated[
        Optional[list[str]],
        typer.Option("--cookie", "-b", help="Session cookie in 'name=value' format (repeatable)"),
    ] = None,
    auth_file: Annotated[
        Optional[Path],
        typer.Option("--auth-file", exists=True, help="JSON/YAML file with headers, bearer_token, and cookies"),
    ] = None,
    secondary_auth_file: Annotated[
        Optional[Path],
        typer.Option(
            "--secondary-auth-file",
            exists=True,
            help="Secondary user JSON/YAML auth file for differential IDOR/BOLA comparison",
        ),
    ] = None,
    endpoint: Annotated[
        Optional[list[str]],
        typer.Option(
            "--endpoint",
            "-e",
            help="Specific resource path/URL to test for differential access (repeatable)",
        ),
    ] = None,
    automated_only: Annotated[
        bool,
        typer.Option("--automated-only", help="Run only fully automated checks"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview selected checks and bindings without executing"),
    ] = False,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-j", min=1, max=16, help="Max parallel tool executions"),
    ] = 4,
    scan_timeout: Annotated[
        int,
        typer.Option("--scan-timeout", min=1, max=7200, help="Maximum total scan duration in seconds"),
    ] = 900,
    max_requests: Annotated[
        int,
        typer.Option("--max-requests", min=1, max=10000, help="Maximum outbound HTTP requests across native probes"),
    ] = 500,
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Single self-contained HTML report output path"),
    ] = Path("tirweb_report.html"),
) -> None:
    """Run security checks and export a single self-contained HTML compliance report."""
    try:
        target, endpoint = validate_scan_scope(target, endpoint)
    except ValueError as exc:
        console.print(f"[bold red]Invalid scan scope:[/bold red] {exc}")
        raise typer.Exit(code=2)
    try:
        auth_ctx = AuthContext.from_inputs(
            raw_headers=header,
            bearer_token=bearer_token,
            raw_cookies=cookie,
            auth_file=auth_file,
        )
        secondary_ctx = (
            AuthContext.from_inputs(auth_file=secondary_auth_file)
            if secondary_auth_file
            else None
        )
    except ValueError as exc:
        console.print(f"[bold red]Authentication configuration error:[/bold red] {exc}")
        raise typer.Exit(code=2)

    scan_ctx = ScanContext(
        primary_auth=auth_ctx,
        secondary_auth=secondary_ctx,
        probe_endpoints=endpoint,
        max_requests=max_requests,
    )

    loaded = TIRWebChecklist.from_yaml(checklist)
    modes = {ExecutionMode.AUTOMATED} if automated_only else None
    selected = loaded.filter_checks(profile=profile, include_core=True, modes=modes)

    auth_badge = (
        "[green]Authenticated[/green]"
        if auth_ctx.is_authenticated
        else "[yellow]Unauthenticated[/yellow]"
    )
    console.print(
        f"[bold cyan]TIRweb Audit[/bold cyan] | Target: [bold]{target}[/bold] | "
        f"Profile: [bold]{profile.value}[/bold] | Mode: {auth_badge} | Checks: [bold]{len(selected)}[/bold]"
    )

    async def _orchestrate():
        dispatcher = ToolDispatcher(concurrency=concurrency)
        await dispatcher.initialize_dynamic_bindings()
        tasks = [
            dispatcher.execute_check(
                target=target, module=mod, check=chk, ctx=scan_ctx, dry_run=dry_run
            )
            for mod, chk in selected
        ]
        return await asyncio.wait_for(asyncio.gather(*tasks), timeout=scan_timeout)

    try:
        results = asyncio.run(_orchestrate())
    except TimeoutError:
        console.print(
            f"[bold red]Scan timed out:[/bold red] Maximum duration of {scan_timeout}s exceeded."
        )
        raise typer.Exit(code=124)

    table = Table(title=f"TIRweb Execution Summary ({profile.value})")
    table.add_column("Check ID", style="cyan", no_wrap=True)
    table.add_column("Module", style="magenta")
    table.add_column("Severity")
    table.add_column("Mode")
    table.add_column("Status", style="bold")
    table.add_column("Indian Regulatory Mapping")

    for res in results:
        table.add_row(
            res.check_id,
            res.module_id,
            res.severity,
            res.execution_mode.value,
            res.status,
            "; ".join(res.india_compliance[:2]),
        )
    console.print(table)

    if out:
        report_payload = {
            "tool": loaded.tool_suite,
            "schema_version": loaded.schema_version,
            "target": target,
            "profile": profile.value,
            "auth_context": auth_ctx.redacted_summary(),
            "summary": {
                "total": len(results),
                "pass": sum(1 for r in results if r.status == "PASS"),
                "fail": sum(1 for r in results if r.status == "FAIL"),
                "hybrid_review": sum(1 for r in results if r.status == "HYBRID_REVIEW"),
                "manual_required": sum(1 for r in results if r.status == "MANUAL_REQUIRED"),
                "tool_missing": sum(1 for r in results if r.status == "TOOL_MISSING"),
                "inconclusive": sum(1 for r in results if r.status == "INCONCLUSIVE"),
                "errors": sum(1 for r in results if r.status == "ERROR"),
                "dry_run": sum(1 for r in results if r.status == "DRY_RUN"),
            },
            "results": [r.model_dump() for r in results],
        }
        if out.suffix.lower() == ".json":
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(report_payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            console.print(f"\n[bold green]JSON scan results exported to:[/bold green] {out.resolve()}")
        else:
            html_path = out if out.suffix.lower() in {".html", ".htm"} else out.with_suffix(".html")
            saved_html = generate_html_report(
                payload=report_payload,
                output_html_path=html_path,
                client_name=client,
                auditor_org=auditor,
            )
            console.print(f"\n[bold green]HTML Compliance Report exported to:[/bold green] {saved_html.resolve()}")


@app.command("report")
def export_report(
    input_json: Annotated[
        Path,
        typer.Option("--input", "-i", exists=True, help="Path to TIRweb JSON report"),
    ],
    output: Annotated[
        Path,
        typer.Option("--out", "-o", help="Output HTML path"),
    ] = Path("tirweb_compliance_report.html"),
    client: Annotated[
        str,
        typer.Option("--client", help="Client or entity name for cover header"),
    ] = "Target Organization",
    auditor: Annotated[
        str,
        typer.Option("--auditor", help="Assessing organization name"),
    ] = "Security Assessment Team",
) -> None:
    """Convert an existing JSON report into a standalone HTML compliance report."""
    actual_path, _, _ = generate_compliance_report(
        report_json_path=input_json,
        output_path=output,
        client_name=client,
        auditor_org=auditor,
    )
    console.print(f"[bold green]Compliance HTML generated:[/bold green] {actual_path.resolve()}")


if __name__ == "__main__":
    app()