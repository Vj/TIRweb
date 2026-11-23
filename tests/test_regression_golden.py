import json
import re
from pathlib import Path
import httpx
import pytest
from tirweb.dispatcher import ToolDispatcher, summarize_tooling_gaps
from tirweb.models import AppProfile, AuthContext, TIRWebChecklist
from tirweb.probes import ScanContext
from tirweb.reporter import render_payload_html

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "http" / "testfire_cassette.json"
GOLDEN_HTML_PATH = Path(__file__).parent / "golden" / "testfire_golden.html"


@pytest.fixture
def recorded_testfire_transport(monkeypatch: pytest.MonkeyPatch):
    cassette = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    recorded = cassette["responses"]

    def handler(request: httpx.Request) -> httpx.Response:
        key = f"{request.method} {str(request.url).rstrip('/')}"
        entry = recorded.get(key) or recorded.get(f"{request.method} {request.url}")
        if entry:
            return httpx.Response(
                entry["status_code"],
                headers=entry.get("headers", {}),
                text=entry.get("body", ""),
            )
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    orig_client = httpx.AsyncClient

    class RecordedAsyncClient(orig_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("tirweb.probes.httpx.AsyncClient", RecordedAsyncClient)
    return cassette["target"]


class TestRegressionAndGoldenSnapshot:
    async def test_recorded_testfire_precision_and_atomic_splitting(
        self, recorded_testfire_transport: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Simulate missing external binaries (nuclei/trivy/testssl.sh) to verify Tooling Gaps & coverage
        monkeypatch.setattr("tirweb.dispatcher.shutil.which", lambda _: None)

        checklist = TIRWebChecklist.from_yaml(Path("rules/tirweb_checklist_v1.yaml"))
        selected = checklist.filter_checks(profile=AppProfile.CORE, include_core=True)
        selection_summary = checklist.explain_profile_selection(profile=AppProfile.CORE, include_core=True)

        dispatcher = ToolDispatcher(concurrency=4)
        await dispatcher.initialize_dynamic_bindings()
        ctx = ScanContext(primary_auth=AuthContext())

        results = [
            await dispatcher.execute_check(recorded_testfire_transport, mod, chk, ctx=ctx)
            for mod, chk in selected
        ]

        by_id = {r.check_id: r for r in results}

        # 1. Coverage-aware roll-up: WEB-IAM-008 ran httpx_graphql and must NOT be TOOL_MISSING
        assert by_id["WEB-IAM-008"].status in {"HYBRID_REVIEW", "NO_ISSUES_FOUND"}
        assert by_id["WEB-IAM-008"].bindings_executed >= 1

        # 2. Native TLS probe detects cleartext HTTP & skips HSTS over HTTP
        cry_rules = {f.rule_id for f in by_id["WEB-CRY-001"].findings}
        assert "WEB-CRY-001:httpx_tls:cleartext_target" in cry_rules
        assert "WEB-CRY-001:httpx_tls:missing_hsts" not in cry_rules

        # 3. Atomic header splitting & Coyote/1.1 -> Tomcat CVE fingerprint
        inf1_rules = {f.rule_id for f in by_id["WEB-INF-001"].findings}
        assert "WEB-INF-001:httpx_headers:missing_content-security-policy" in inf1_rules
        assert "WEB-INF-001:httpx_headers:leak_server" in inf1_rules

        inf3_rules = {f.rule_id for f in by_id["WEB-INF-003"].findings}
        assert "WEB-INF-003:httpx_cve_fingerprint:CVE-2017-12617 / CVE-2020-1938" in inf3_rules

        # 4. Golden HTML snapshot verification
        conclusive_count = sum(1 for r in results if r.conclusive)
        tooling_gaps = summarize_tooling_gaps(results)
        payload = {
            "tool": checklist.tool_suite,
            "schema_version": "2.0.0",
            "target": recorded_testfire_transport,
            "profile": "core",
            "profile_selection": selection_summary.model_dump(),
            "tooling_gaps": tooling_gaps,
            "summary": {
                "total": len(results),
                "conclusively_assessed": conclusive_count,
                "conclusive_label": f"{conclusive_count} of {len(results)} conclusively assessed",
                "atomic_findings_total": sum(len(r.findings) for r in results),
                "fail": sum(1 for r in results if r.status == "FAIL"),
                "no_issues_found": sum(1 for r in results if r.status == "NO_ISSUES_FOUND"),
                "hybrid_review": sum(1 for r in results if r.status == "HYBRID_REVIEW"),
                "manual_required": sum(1 for r in results if r.status == "MANUAL_REQUIRED"),
                "inconclusive": sum(1 for r in results if r.status == "INCONCLUSIVE"),
            },
            "results": [r.model_dump() for r in results],
        }

        rendered_html = render_payload_html(payload, client_name="Altoro Mutual Demo")
        normalized_html = re.sub(r"Generated: \d{2} [A-Za-z]{3} \d{4}, \d{2}:\d{2} UTC", "Generated: <TIMESTAMP>", rendered_html)

        assert f"{conclusive_count} of {len(results)} conclusively assessed" in normalized_html
        assert "Tooling Gaps &amp; Environment Coverage" in normalized_html
        assert "Apache-Coyote/1.1" in normalized_html

        if not GOLDEN_HTML_PATH.exists():
            GOLDEN_HTML_PATH.parent.mkdir(parents=True, exist_ok=True)
            GOLDEN_HTML_PATH.write_text(normalized_html, encoding="utf-8")
        else:
            assert normalized_html == GOLDEN_HTML_PATH.read_text(encoding="utf-8")