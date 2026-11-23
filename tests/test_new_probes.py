import json
import httpx
import pytest
from tirweb.models import AppProfile, AuthContext, ChecklistItem, ComplianceMapping, ExecutionMode, Severity
from tirweb.probes import (
    ScanContext,
    probe_cookie_security,
    probe_cve_fingerprint,
    probe_graphql_security,
    probe_metafiles_and_ria_policies,
    probe_open_redirect,
    probe_path_confusion,
    probe_tls_and_https,
)


@pytest.fixture
def check_fixture() -> ChecklistItem:
    return ChecklistItem(
        id="WEB-INF-008",
        title="Native Probe Suite Fixture",
        category="Security Misconfiguration",
        severity=Severity.MEDIUM,
        execution_mode=ExecutionMode.AUTOMATED,
        tool_binding=["httpx_metafiles"],
        profiles=[AppProfile.CORE],
        test_procedures=["Automated HTTPx probe test."],
        compliance=ComplianceMapping.model_validate(
            {
                "india": ["DPDP Rules 2025 - Rule 6(1)(a)"],
                "global": ["OWASP Top 10: A05 Security Misconfiguration"],
            }
        ),
    )


@pytest.fixture
def mock_transport(monkeypatch: pytest.MonkeyPatch):
    def _apply(handler):
        transport = httpx.MockTransport(handler)
        orig_client = httpx.AsyncClient

        class MockedAsyncClient(orig_client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        monkeypatch.setattr("tirweb.probes.httpx.AsyncClient", MockedAsyncClient)

    return _apply


class TestNewProbes:
    async def test_metafiles_detects_leaked_paths_and_wildcard_crossdomain(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /admin/backup/\n")
            if request.url.path == "/crossdomain.xml":
                return httpx.Response(200, text='<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>')
            return httpx.Response(404)

        mock_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_metafiles_and_ria_policies("https://example.in", check_fixture, ctx)

        assert outcome.conclusive is True
        assert len(outcome.findings) == 2
        titles = " ".join(f.title for f in outcome.findings)
        assert "/robots.txt" in titles
        assert "/crossdomain.xml" in titles

    async def test_path_confusion_flags_bypass_when_variant_returns_200(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raw_path = request.url.raw_path.decode()
            if raw_path == "/__tirweb_baseline_404_canary__":
                return httpx.Response(404, text="Not Found")
            if raw_path == "/admin":
                return httpx.Response(403, text="Forbidden")
            if raw_path == "/admin/..;/":
                return httpx.Response(200, text="Admin Dashboard Content " * 10)
            return httpx.Response(403)

        mock_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext(), probe_endpoints=["/admin"])
        outcome = await probe_path_confusion("https://example.in", check_fixture, ctx)

        assert outcome.conclusive is True
        assert len(outcome.findings) >= 1
        assert "/admin/..;/" in outcome.findings[0].evidence

    async def test_open_redirect_detects_unvalidated_location_header(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            next_val = request.url.params.get("next", "")
            if next_val:
                return httpx.Response(302, headers={"Location": next_val})
            return httpx.Response(200)

        mock_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_open_redirect("https://example.in", check_fixture, ctx)

        assert outcome.conclusive is True
        assert len(outcome.findings) == 1
        assert "untrusted-redirect-audit.example.invalid" in outcome.findings[0].evidence

    async def test_graphql_detects_enabled_introspection_and_batching(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/graphql":
                payload = json.loads(request.content.decode())
                if isinstance(payload, dict) and "__schema" in payload.get("query", ""):
                    return httpx.Response(
                        200,
                        json={"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}},
                    )
                if isinstance(payload, list):
                    return httpx.Response(
                        200,
                        json=[{"data": {"__typename": "Query"}} for _ in payload],
                    )
            return httpx.Response(404)

        mock_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_graphql_security("https://example.in", check_fixture, ctx)

        assert outcome.conclusive is True
        assert len(outcome.findings) == 2
        rule_ids = {f.rule_id for f in outcome.findings}
        assert "WEB-INF-008:httpx_graphql:introspection:/api/graphql" in rule_ids
        assert "WEB-INF-008:httpx_graphql:batching:/api/graphql" in rule_ids

    async def test_graphql_passes_when_introspection_and_batching_blocked(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/graphql":
                payload = json.loads(request.content.decode())
                if isinstance(payload, dict):
                    return httpx.Response(
                        200,
                        json={"errors": [{"message": "GraphQL introspection is not allowed."}]},
                    )
                if isinstance(payload, list):
                    return httpx.Response(
                        400,
                        json={"errors": [{"message": "Query batching is disabled."}]},
                    )
            return httpx.Response(404)

        mock_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_graphql_security("https://example.in", check_fixture, ctx)

        assert outcome.conclusive is True
        assert outcome.findings == []
        assert "introspection and batching restricted" in outcome.summary

    async def test_tls_probe_flags_cleartext_http_and_skips_hsts(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        mock_transport(lambda request: httpx.Response(200, text="Plain HTTP"))
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_tls_and_https("http://demo.testfire.net", check_fixture, ctx)

        rule_ids = {f.rule_id for f in outcome.findings}
        assert "WEB-INF-008:httpx_tls:cleartext_target" in rule_ids
        assert "WEB-INF-008:httpx_tls:no_https_redirect" in rule_ids
        assert "WEB-INF-008:httpx_tls:missing_hsts" not in rule_ids

    async def test_cookie_and_cve_fingerprint_probes(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        mock_transport(
            lambda request: httpx.Response(
                200,
                headers={
                    "Server": "Apache-Coyote/1.1",
                    "Set-Cookie": "JSESSIONID=12345; Path=/",
                },
            )
        )
        ctx = ScanContext(primary_auth=AuthContext())
        cookie_out = await probe_cookie_security("http://demo.testfire.net", check_fixture, ctx)
        cve_out = await probe_cve_fingerprint("http://demo.testfire.net", check_fixture, ctx)

        assert len(cookie_out.findings) == 3  # missing Secure, HttpOnly, SameSite
        assert any(f.cve == "CVE-2017-12617 / CVE-2020-1938" for f in cve_out.findings)