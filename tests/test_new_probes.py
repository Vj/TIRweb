import httpx
import pytest
from tirweb.models import AppProfile, AuthContext, ChecklistItem, ComplianceMapping, ExecutionMode, Severity
from tirweb.probes import (
    ScanContext,
    probe_metafiles_and_ria_policies,
    probe_open_redirect,
    probe_path_confusion,
)


@pytest.fixture
def check_fixture() -> ChecklistItem:
    return ChecklistItem(
        id="WEB-INF-008",
        title="Metafile, Path Confusion & Open Redirect Probe Fixture",
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
        passed, detail = await probe_metafiles_and_ria_policies("https://example.in", check_fixture, ctx)

        assert passed is False
        assert "/robots.txt lists sensitive-looking paths" in detail
        assert "listing alone does not prove the resource is publicly accessible" in detail
        assert "/crossdomain.xml allows wildcard '*' cross-domain access" in detail

    async def test_sitemap_path_listing_alone_is_inconclusive(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/sitemap.xml":
                return httpx.Response(200, text="<urlset><loc>https://example.in/internal</loc></url></urlset>")
            return httpx.Response(404)

        mock_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        passed, detail = await probe_metafiles_and_ria_policies("https://example.in", check_fixture, ctx)

        assert passed is True
        assert "INCONCLUSIVE_METAFILE_REVIEW" in detail

    async def test_path_confusion_flags_bypass_when_variant_returns_200(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raw_path = request.url.raw_path.decode()
            if raw_path == "/admin":
                return httpx.Response(403, text="Forbidden")
            if raw_path == "/admin/..;/":
                return httpx.Response(200, text="Admin Dashboard")
            return httpx.Response(403)

        mock_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext(), probe_endpoints=["/admin"])
        passed, detail = await probe_path_confusion("https://example.in", check_fixture, ctx)

        assert passed is False
        assert "Path confusion ACL bypass detected" in detail
        assert "/admin/..;/" in detail

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
        passed, detail = await probe_open_redirect("https://example.in", check_fixture, ctx)

        assert passed is False
        assert "Open redirect vulnerability detected" in detail
        assert "?next=https://untrusted-redirect-audit.example.invalid/phish" in detail

    async def test_graphql_detects_enabled_introspection_and_batching(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        import json
        from tirweb.probes import probe_graphql_security

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
        passed, detail = await probe_graphql_security("https://example.in", check_fixture, ctx)

        assert passed is False
        assert "[/api/graphql] GraphQL schema introspection (__schema) is enabled" in detail
        assert "[/api/graphql] Unauthenticated/unthrottled GraphQL query batching allowed" in detail

    async def test_graphql_passes_when_introspection_and_batching_blocked(
        self, check_fixture: ChecklistItem, mock_transport
    ) -> None:
        import json
        from tirweb.probes import probe_graphql_security

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
        passed, detail = await probe_graphql_security("https://example.in", check_fixture, ctx)

        assert passed is True
        assert "introspection disabled and query batching restricted" in detail