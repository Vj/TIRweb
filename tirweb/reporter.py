import json
import re
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


def _normalize_clause_key(tag: str) -> str:
    """Strip parenthetical commentary so duplicate references under the same check collapse cleanly."""
    base = re.sub(r"\s*\([^)]*\)", "", tag).strip().lower()
    return base


def build_compliance_matrix(results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group check execution outcomes under Indian regulatory pillars with strict deduplication."""
    matrix: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for item in results:
        seen_entries: set[tuple[str, str, str]] = set()
        for tag in item.get("india_compliance", []):
            pillar = _classify_indian_framework(tag)
            norm_key = (pillar, item["check_id"], _normalize_clause_key(tag))
            if norm_key not in seen_entries:
                seen_entries.add(norm_key)
                matrix[pillar].append(
                    {
                        "clause": tag,
                        "check_id": item["check_id"],
                        "title": item["title"],
                        "severity": item["severity"],
                        "status": item["status"],
                        "coverage_label": item.get("coverage_label", ""),
                        "execution_mode": item.get("execution_mode", ""),
                    }
                )
    return dict(matrix)


def _compute_atomic_severity_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    """Count individual ProbeFinding severities (falling back to check severity if findings list is empty)."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in results:
        findings = r.get("findings") or []
        if findings:
            for f in findings:
                sev = f.get("severity", "Info")
                if sev in counts:
                    counts[sev] += 1
        elif r.get("status") == "FAIL":
            sev = r.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
    return counts


def render_payload_html(
    payload: dict[str, Any],
    client_name: str,
    auditor_org: str = "Security Assessment Team",
) -> str:
    """Render an in-memory TIRweb scan payload dictionary directly into HTML."""
    results: list[dict[str, Any]] = payload.get("results", [])

    sorted_results = sorted(
        results,
        key=lambda r: (SEVERITY_ORDER.get(r.get("severity", "Info"), 99), r.get("check_id", "")),
    )

    severity_counts = _compute_atomic_severity_counts(sorted_results)
    compliance_matrix = build_compliance_matrix(sorted_results)

    summary = dict(payload.get("summary", {}))
    total = summary.get("total", len(results))
    conclusive = summary.get(
        "conclusively_assessed",
        sum(1 for r in results if r.get("conclusive", False)),
    )
    summary.setdefault("total", total)
    summary.setdefault("conclusively_assessed", conclusive)
    summary.setdefault("conclusive_label", f"{conclusive} of {total} conclusively assessed")
    summary.setdefault("atomic_findings_total", sum(severity_counts.values()))

    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("audit_report.html")

    return template.render(
        client_name=client_name,
        auditor_org=auditor_org,
        generated_at=datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
        tool=payload.get("tool", "TIRweb"),
        schema_version=payload.get("schema_version", "2.0.0"),
        target=payload.get("target", "N/A"),
        profile=str(payload.get("profile", "core")).upper(),
        profile_selection=payload.get("profile_selection", {}),
        auth_context=payload.get("auth_context", {}),
        tooling_gaps=payload.get("tooling_gaps", []),
        summary=summary,
        severity_counts=severity_counts,
        compliance_matrix=compliance_matrix,
        results=sorted_results,
    )


def generate_html_report(
    payload: dict[str, Any],
    output_html_path: Path,
    client_name: str,
    auditor_org: str = "Security Assessment Team",
) -> Path:
    """Write a self-contained HTML compliance report directly from scan results."""
    rendered_html = render_payload_html(
        payload=payload,
        client_name=client_name,
        auditor_org=auditor_org,
    )
    output_html_path.parent.mkdir(parents=True, exist_ok=True)
    output_html_path.write_text(rendered_html, encoding="utf-8")
    return output_html_path


def generate_compliance_report(
    report_json_path: Path,
    output_path: Path,
    client_name: str,
    auditor_org: str = "Security Assessment Team",
    allow_html_fallback: bool = True,
) -> tuple[Path, str, str | None]:
    """Convert an existing JSON report into HTML (or PDF if requested and GTK3 is available)."""
    payload = json.loads(report_json_path.read_text(encoding="utf-8"))
    if output_path.suffix.lower() in {".html", ".htm"}:
        saved_path = generate_html_report(
            payload=payload,
            output_html_path=output_path,
            client_name=client_name,
            auditor_org=auditor_org,
        )
        return saved_path, "html", None

    rendered_html = render_payload_html(
        payload=payload,
        client_name=client_name,
        auditor_org=auditor_org,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from weasyprint import HTML

        template_dir = Path(__file__).parent / "templates"
        HTML(string=rendered_html, base_url=str(template_dir)).write_pdf(str(output_path))
        return output_path, "pdf", None
    except (ImportError, OSError) as exc:
        if not allow_html_fallback:
            raise
        html_out = output_path.with_suffix(".html")
        html_out.write_text(rendered_html, encoding="utf-8")
        return html_out, "html", f"WeasyPrint unavailable ({exc}); exported HTML instead."