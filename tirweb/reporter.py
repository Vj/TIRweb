import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from jinja2 import Environment, FileSystemLoader, select_autoescape


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _classify_indian_framework(tag: str) -> str:
    upper = tag.upper()
    if "DPDP" in upper:
        return "DPDP Act 2023 & DPDP Rules, 2025"
    if "CERT-IN" in upper or "70B" in upper:
        return "CERT-In Directions (Sec 70B) & Technical Guidelines"
    if "RBI" in upper:
        return "RBI Digital Payment & Cyber Security Directions"
    return "Other Indian Statutory Requirements"


def build_compliance_matrix(results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group check execution outcomes under Indian regulatory pillars."""
    matrix: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for item in results:
        seen_pillars: set[tuple[str, str, str]] = set()
        for tag in item.get("india_compliance", []):
            pillar = _classify_indian_framework(tag)
            entry_key = (pillar, item["check_id"], tag)
            if entry_key not in seen_pillars:
                seen_pillars.add(entry_key)
                matrix[pillar].append(
                    {
                        "clause": tag,
                        "check_id": item["check_id"],
                        "title": item["title"],
                        "severity": item["severity"],
                        "status": item["status"],
                        "execution_mode": item["execution_mode"],
                    }
                )
    return dict(matrix)


def render_report_html(
    report_json_path: Path,
    client_name: str = "Target Organization",
    auditor_org: str = "Security Assessment Team",
) -> tuple[str, Path]:
    """Render tirweb_report.json into a self-contained HTML string and return (html, template_dir)."""
    payload = json.loads(report_json_path.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = payload.get("results", [])

    # Sort findings by severity then check_id
    sorted_results = sorted(
        results,
        key=lambda r: (SEVERITY_ORDER.get(r.get("severity", "Info"), 99), r.get("check_id", "")),
    )

    severity_counts = {
        sev: sum(1 for r in results if r.get("severity") == sev and r.get("status") == "FAIL")
        for sev in ("Critical", "High", "Medium", "Low", "Info")
    }

    compliance_matrix = build_compliance_matrix(sorted_results)

    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("audit_report.html")

    rendered_html = template.render(
        client_name=client_name,
        auditor_org=auditor_org,
        generated_at=datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
        tool=payload.get("tool", "TIRweb"),
        schema_version=payload.get("schema_version", "1.0.0"),
        target=payload.get("target", "N/A"),
        profile=payload.get("profile", "core").upper(),
        summary=payload.get("summary", {}),
        severity_counts=severity_counts,
        compliance_matrix=compliance_matrix,
        results=sorted_results,
    )
    return rendered_html, template_dir


def generate_compliance_report(
    report_json_path: Path,
    output_path: Path,
    client_name: str = "Target Organization",
    auditor_org: str = "Security Assessment Team",
    allow_html_fallback: bool = True,
) -> tuple[Path, str, str | None]:
    """
    Export TIRweb JSON results as PDF (via WeasyPrint) or self-contained HTML.

    Returns:
        (actual_output_path, format_used ['pdf' | 'html'], warning_message_or_none)
    """
    rendered_html, template_dir = render_report_html(
        report_json_path=report_json_path,
        client_name=client_name,
        auditor_org=auditor_org,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix.lower() in {".html", ".htm"}:
        output_path.write_text(rendered_html, encoding="utf-8")
        return output_path, "html", None

    try:
        from weasyprint import HTML  # Lazy import avoids startup crashes on Windows without GTK3

        HTML(string=rendered_html, base_url=str(template_dir)).write_pdf(str(output_path))
        return output_path, "pdf", None
    except (ImportError, OSError) as exc:
        if not allow_html_fallback:
            raise
        fallback_html_path = output_path.with_suffix(".html")
        fallback_html_path.write_text(rendered_html, encoding="utf-8")
        warning = (
            f"WeasyPrint native GTK3/Pango runtime unavailable ({exc}). "
            f"Exported self-contained HTML report instead."
        )
        return fallback_html_path, "html", warning


# Backward-compatible alias for any callers still importing generate_pdf_report
def generate_pdf_report(
    report_json_path: Path,
    output_pdf_path: Path,
    client_name: str = "Target Organization",
    auditor_org: str = "Security Assessment Team",
) -> Path:
    actual_path, _, _ = generate_compliance_report(
        report_json_path=report_json_path,
        output_path=output_pdf_path,
        client_name=client_name,
        auditor_org=auditor_org,
        allow_html_fallback=True,
    )
    return actual_path