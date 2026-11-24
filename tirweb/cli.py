import asyncio
import platform
import shutil
import sys
from pathlib import Path
from typing import Annotated, Optional
import typer
from rich.console import Console
from rich.table import Table
from .dispatcher import ToolDispatcher, summarize_tooling_gaps
from .models import AppProfile, AuthContext, ExecutionMode, TIRWebChecklist
from .orchestrator import run_audit_pipeline
from .probes import ScanContext
from .reporter import generate_compliance_report, generate_html_report

app = typer.Typer(
    name="tirweb",
    help="TIRweb: OWASP, Advanced Pentest & Indian Regulatory Compliance Runner",
    no_args_is_help=True,
)
console = Console()


@app.command("doctor")
def run_doctor() -> None:
    """Run preflight diagnostics for Python runtime, native HTTPx probes, and external scanners."""
    table = Table(title="TIRweb Environment & Tooling Preflight (doctor)")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Status", style="bold")
    table.add_column("Notes / Remediation")

    table.add_row(
        f"Python {sys.version.split()[0]} ({platform.system()})",
        "Runtime",
        "[green]READY[/green]",
        "Core async probe engine available.",
    )
    table.add_row(
        "Native HTTPx Probe Suite (20+ probes)",
        "Built-in",
        "[green]READY[/green]",
        "TLS, Headers, Cookies, Methods, Discovery, Errors, Auth, Cache, CSRF, Assets/SRI, CVE, Canary Inj, CORS, IDOR, JWT, Metafiles, Path Confusion, Redirect, GraphQL, Arch/DNS.",
    )

    try:
        import weasyprint  # noqa: F401

        table.add_row(
            "WeasyPrint PDF Engine",
            "Optional",
            "[green]READY[/green]",
            "Native PDF export available (HTML report always available).",
        )
    except Exception as exc:
        table.add_row(
            "WeasyPrint PDF Engine",
            "Optional",
            "[yellow]HTML-ONLY[/yellow]",
            f"GTK3/Pango runtime missing ({exc}); HTML output unaffected.",
        )

    external_tools = [
        ("nuclei", "Template DAST scanner (nuclei_bola, nuclei_bfla, nuclei_injection, nuclei_ssrf)"),
        ("trivy", "Dependency SCA & SBOM vulnerability scanner (trivy_sca)"),
        ("testssl.sh", "Deep TLS cipher/protocol analyzer (testssl)"),
    ]
    for binary, desc in external_tools:
        path = shutil.which(binary)
        if path:
            table.add_row(binary, "External CLI", "[green]INSTALLED[/green]", f"{path} — {desc}")
        else:
            table.add_row(
                binary,
                "External CLI",
                "[yellow]MISSING[/yellow]",
                f"Not in PATH ({desc}). Install locally or use the TIRweb Docker image.",
            )

    console.print(table)


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
    client: Annotated[
        str,
        typer.Option("--client", help="Client or entity name for the report header (required)"),
    ],
    profile: Annotated[
        AppProfile,
        typer.Option("--profile", "-p", help="Application domain profile"),
    ] = AppProfile.CORE,
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
    scan_timeout: Annotated[
        int,
        typer.Option("--scan-timeout", min=1, max=7200, help="Max total scan duration in seconds (1-7200)"),
    ] = 900,
    max_requests: Annotated[
        int,
        typer.Option("--max-requests", min=1, max=10000, help="Max outbound HTTP requests across native probes (1-10000)"),
    ] = 500,
    allow_default_creds: Annotated[
        bool,
        typer.Option("--allow-default-creds", help="Opt-in to active differential default-credential testing"),
    ] = False,
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
        typer.Option("--out", "-o", help="Single self-contained HTML report output path"),
    ] = Path("tirweb_report.html"),
    source_path: Annotated[
        Optional[Path],
        typer.Option("--source-path", exists=True, help="Optional local repository path for SAST/SCA secret & weak-hash scanning"),
    ] = None,
    allow_active_injection: Annotated[
        bool,
        typer.Option("--allow-active-injection", help="Opt-in to bounded sleep timing probes for blind command injection"),
    ] = False,
) -> None:
    """Run security checks and export a single self-contained HTML compliance report."""
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
        allow_default_creds=allow_default_creds,
        allow_active_injection=allow_active_injection,
        source_path=str(source_path) if source_path else None,
    )

    loaded = TIRWebChecklist.from_yaml(checklist)
    modes = {ExecutionMode.AUTOMATED} if automated_only else None
    selected = loaded.filter_checks(profile=profile, include_core=True, modes=modes)
    selection_summary = loaded.explain_profile_selection(profile=profile, include_core=True, modes=modes)

    auth_badge = (
        "[green]Authenticated[/green]"
        if auth_ctx.is_authenticated
        else "[yellow]Unauthenticated[/yellow]"
    )
    console.print(
        f"[bold cyan]TIRweb Audit[/bold cyan] | Client: [bold]{client}[/bold] | Target: [bold]{target}[/bold] | "
        f"Profile: [bold]{profile.value}[/bold] ({selection_summary.selected_count}/{selection_summary.total_available} checks) | Mode: {auth_badge}"
    )

    async def _orchestrate():
        dispatcher = ToolDispatcher(concurrency=concurrency)
        await dispatcher.initialize_dynamic_bindings()
        return await asyncio.wait_for(
            run_audit_pipeline(
                dispatcher=dispatcher,
                target=target,
                selected=selected,
                scan_ctx=scan_ctx,
                dry_run=dry_run,
            ),
            timeout=scan_timeout,
        )

    results = asyncio.run(_orchestrate())

    conclusive_count = sum(1 for r in results if r.conclusive)
    total_atomic_findings = sum(len(r.findings) for r in results)
    tooling_gaps = summarize_tooling_gaps(results)

    table = Table(
        title=f"TIRweb Execution Summary ({profile.value}) — {conclusive_count} of {len(results)} conclusively assessed"
    )
    table.add_column("Check ID", style="cyan", no_wrap=True)
    table.add_column("Module", style="magenta")
    table.add_column("Severity")
    table.add_column("Coverage")
    table.add_column("Status", style="bold")
    table.add_column("Findings")

    for res in results:
        table.add_row(
            res.check_id,
            res.module_id,
            res.severity,
            res.coverage_label,
            res.status,
            str(len(res.findings)) if res.findings else "-",
        )
    console.print(table)

    if tooling_gaps:
        gap_names = ", ".join(f"{g['tool']} ({g['affected_checks_count']} checks)" for g in tooling_gaps)
        console.print(
            f"[bold yellow]Tooling Gaps:[/bold yellow] Optional external scanners unavailable: {gap_names}. "
            "Run [cyan]tirweb doctor[/cyan] for remediation."
        )

    if out:
        report_payload = {
            "tool": loaded.tool_suite,
            "schema_version": loaded.schema_version,
            "target": target,
            "profile": profile.value,
            "profile_selection": selection_summary.model_dump(),
            "auth_context": auth_ctx.redacted_summary(),
            "tooling_gaps": tooling_gaps,
            "summary": {
                "total": len(results),
                "conclusively_assessed": conclusive_count,
                "conclusive_label": f"{conclusive_count} of {len(results)} conclusively assessed",
                "atomic_findings_total": total_atomic_findings,
                "fail": sum(1 for r in results if r.status == "FAIL"),
                "no_issues_found": sum(1 for r in results if r.status == "NO_ISSUES_FOUND"),
                "hybrid_review": sum(1 for r in results if r.status == "HYBRID_REVIEW"),
                "manual_required": sum(1 for r in results if r.status == "MANUAL_REQUIRED"),
                "inconclusive": sum(1 for r in results if r.status == "INCONCLUSIVE"),
            },
            "results": [r.model_dump() for r in results],
        }
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
    client: Annotated[
        str,
        typer.Option("--client", help="Client or entity name for cover header (required)"),
    ],
    output: Annotated[
        Path,
        typer.Option("--out", "-o", help="Output HTML path"),
    ] = Path("tirweb_compliance_report.html"),
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