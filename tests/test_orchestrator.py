import httpx
import pytest
from tirweb.dispatcher import CheckExecutionResult, ToolDispatcher
from tirweb.models import AppProfile, AuthContext, ChecklistItem, ComplianceMapping, ExecutionMode, Severity
from tirweb.orchestrator import (
    detect_session_expiry,
    discover_target_surface,
    evaluate_privilege_tiers,
)
from tirweb.probes import ScanContext


@pytest.fixture
def iam_check() -> ChecklistItem:
    return ChecklistItem(
        id="WEB-IAM-002",
        title="Vertical Privilege Escalation & BFLA",
        category="Broken Access Control",
        severity=Severity.HIGH,
        execution_mode=ExecutionMode.HYBRID,
        tool_binding=["nuclei_bfla", "manual_proxy"],
        profiles=[AppProfile.CORE],
        test_procedures=["Verify low-priv user cannot reach admin endpoints."],
        compliance=ComplianceMapping.model_validate(
            {
                "india": ["DPDP Rules 2025 - Rule 6(1)(b)"],
                "global": ["OWASP API Top 10: API5 BFLA"],
            }
        ),
    )


@pytest.fixture
def patch_orchestrator_transport(monkeypatch: pytest.MonkeyPatch):
    def _apply(handler):
        transport = httpx.MockTransport(handler)
        orig_client = httpx.AsyncClient

        class MockedAsyncClient(orig_client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        monkeypatch.setattr("tirweb.orchestrator.httpx.AsyncClient", MockedAsyncClient)

    return _apply


class TestOrchestrator:
    async def test_discover_target_surface_harvests_robots_sitemap_and_links(
        self, patch_orchestrator_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /internal/reports\n")
            if path == "/sitemap.xml":
                return httpx.Response(
                    200,
                    text="<urlset><url><loc>https://app.example.in/api/v1/profile</loc></url></urlset>",
                )
            if path in {"", "/"}:
                return httpx.Response(
                    200,
                    text='<html><body><a href="/dashboard">Dash</a><form action="/transfer"></form></body></html>',
                )
            return httpx.Response(404)

        patch_orchestrator_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext(), probe_endpoints=["/existing"])
        discovered = await discover_target_surface("https://app.example.in", ctx)

        assert "/existing" in discovered
        assert "/internal/reports" in discovered
        assert "/api/v1/profile" in discovered
        assert "/dashboard" in discovered
        assert "/transfer" in discovered

    async def test_evaluate_privilege_tiers_flags_cross_tier_200_access(
        self, iam_check: ChecklistItem, patch_orchestrator_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/admin/users":
                # Broken access control: returns 200 to all tiers
                return httpx.Response(200, json={"users": ["admin", "alice"]})
            return httpx.Response(403)

        patch_orchestrator_transport(handler)
        ctx = ScanContext(
            primary_auth=AuthContext(bearer_token="admin_tok"),
            secondary_auth=AuthContext(bearer_token="user_tok"),
            probe_endpoints=["/api/admin/users"],
        )

        findings = await evaluate_privilege_tiers("https://app.example.in", iam_check, ctx)
        assert len(findings) == 2  # unauthenticated + low_priv both reached 200
        rule_ids = {f.rule_id for f in findings}
        assert "WEB-IAM-002:priv_tier_diff:unauthenticated_vs_high_priv:/api/admin/users" in rule_ids
        assert "WEB-IAM-002:priv_tier_diff:low_priv_vs_high_priv:/api/admin/users" in rule_ids

    def test_detect_session_expiry_flags_late_401_after_early_200(self) -> None:
        early_ok = CheckExecutionResult(
            check_id="WEB-INF-001",
            module_id="TIR-INFRA",
            title="Headers",
            severity="Medium",
            execution_mode="automated",
            status="NO_ISSUES_FOUND",
            conclusive=True,
            bindings_executed=1,
            bindings_total=1,
            coverage_label="1 of 1 bindings executed",
            tools_invoked=["httpx_headers"],
            output_summary="Clean",
            india_compliance=["CERT-In CISG-2024-01"],
            global_compliance=["OWASP A05"],
            timestamp="2026-11-23T14:00:00Z",
        )
        late_401 = CheckExecutionResult(
            check_id="WEB-IAM-008",
            module_id="TIR-IAM",
            title="API Auth",
            severity="High",
            execution_mode="hybrid",
            status="INCONCLUSIVE",
            conclusive=False,
            bindings_executed=1,
            bindings_total=2,
            coverage_label="1 of 2 bindings executed",
            tools_invoked=["httpx_api_auth"],
            output_summary="unauthenticated=401/authentication-required",
            india_compliance=["CERT-In CISG-2024-01"],
            global_compliance=["OWASP API1"],
            timestamp="2026-11-23T14:01:00Z",
        )

        expired = detect_session_expiry([early_ok, late_401])
        assert expired == ["WEB-IAM-008"]