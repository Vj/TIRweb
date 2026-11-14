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
from .reporter import generate_pdf_report
from .reporter import generate_compliance_report

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
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="JSON output report path"),
    ] = Path("tirweb_report.json"),
) -> None:
    """Filter checklist by profile and dispatch authenticated or unauthenticated security checks."""
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
        return await asyncio.gather(*tasks)

    results = asyncio.run(_orchestrate())

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
            },
            "results": [r.model_dump() for r in results],
        }
        out.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
        console.print(f"\n[green]Report exported to:[/green] {out.resolve()}")


@app.command("report")
def export_report(
    input_json: Annotated[
        Path,
        typer.Option("--input", "-i", exists=True, help="Path to TIRweb JSON report"),
    ],
    output: Annotated[
        Path,
        typer.Option("--out", "-o", help="Output path (.pdf or .html)"),
    ] = Path("tirweb_compliance_report.pdf"),
    client: Annotated[
        str,
        typer.Option("--client", help="Client or entity name for cover header"),
    ] = "Target Organization",
    auditor: Annotated[
        str,
        typer.Option("--auditor", help="Assessing organization name"),
    ] = "Security Assessment Team",
    strict_pdf: Annotated[
        bool,
        typer.Option("--strict-pdf", help="Fail instead of falling back to HTML if WeasyPrint/GTK3 is unavailable"),
    ] = False,
) -> None:
    """Convert TIRweb JSON results into a CERT-In, RBI & DPDP Rules 2025 PDF or HTML report."""
    actual_path, fmt, warning = generate_compliance_report(
        report_json_path=input_json,
        output_path=output,
        client_name=client,
        auditor_org=auditor,
        allow_html_fallback=not strict_pdf,
    )
    if warning:
        console.print(f"[bold yellow]Notice:[/bold yellow] {warning}")
    console.print(f"[bold green]Compliance {fmt.upper()} generated:[/bold green] {actual_path.resolve()}")


if __name__ == "__main__":
    app()
