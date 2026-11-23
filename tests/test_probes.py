import base64
import json
from datetime import datetime, timedelta, timezone
import httpx
import pytest
from tirweb.models import AppProfile, AuthContext, ChecklistItem, ComplianceMapping, ExecutionMode, Severity
from tirweb.probes import (
    ScanContext,
    probe_api_authentication,
    probe_cors_policy,
    probe_differential_idor,
    probe_jwt_security,
    probe_security_headers,
)


def _make_jwt(header: dict, payload: dict, signature: str = "sig_placeholder") -> str:
    def _enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_enc(header)}.{_enc(payload)}.{signature}"


@pytest.fixture
def dummy_check() -> ChecklistItem:
    return ChecklistItem(
        id="WEB-INF-001",
        title="Security Headers, CORS, IDOR & JWT Probe Fixture",
        category="Security Misconfiguration",
        severity=Severity.HIGH,
        execution_mode=ExecutionMode.AUTOMATED,
        tool_binding=["httpx_headers"],
        profiles=[AppProfile.CORE],
        test_procedures=["Automated diagnostic probe verification."],
        compliance=ComplianceMapping.model_validate(
            {
                "india": ["DPDP Rules 2025 - Rule 6(1)(a)"],
                "global": ["OWASP Top 10: A05 Security Misconfiguration"],
            }
        ),
    )


@pytest.mark.asyncio
async def test_idor_skips_when_primary_identity_is_missing(dummy_check: ChecklistItem) -> None:
    ctx = ScanContext(
        primary_auth=AuthContext(),
        secondary_auth=AuthContext(bearer_token="test-user-b"),
    )
    outcome = await probe_differential_idor("https://app.example.in", dummy_check, ctx)
    assert outcome.conclusive is False
    assert "SKIPPED_PRIMARY_AUTH" in outcome.summary


@pytest.fixture
def patch_httpx_transport(monkeypatch: pytest.MonkeyPatch):
    def _apply(handler):
        transport = httpx.MockTransport(handler)
        orig_client = httpx.AsyncClient

        class MockedAsyncClient(orig_client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        monkeypatch.setattr("tirweb.probes.httpx.AsyncClient", MockedAsyncClient)

    return _apply


class TestProbeSecurityHeaders:
    async def test_passes_with_complete_hardened_headers(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "geolocation=(), camera=()",
                },
            )

        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_security_headers("https://app.example.in", dummy_check, ctx)

        assert outcome.findings == []
        assert "No baseline security header issues detected" in outcome.summary

    async def test_accepts_csp_frame_ancestors_instead_of_x_frame_options(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "Strict-Transport-Security": "max-age=31536000",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "microphone=()",
                },
            )

        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_security_headers("https://app.example.in", dummy_check, ctx)

        assert outcome.findings == []

    async def test_fails_on_missing_headers_and_version_leaks(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "Server": "nginx/1.18.0 (Ubuntu)",
                    "X-Powered-By": "Express",
                    "X-Content-Type-Options": "invalid-val",
                },
            )

        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_security_headers("https://legacy.example.in", dummy_check, ctx)

        assert len(outcome.findings) >= 5
        rule_ids = {f.rule_id for f in outcome.findings}
        assert "WEB-INF-001:httpx_headers:missing_content-security-policy" in rule_ids
        assert "WEB-INF-001:httpx_headers:leak_server" in rule_ids


class TestProbeCorsPolicy:
    async def test_passes_when_untrusted_origin_not_reflected(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                204,
                headers={
                    "Access-Control-Allow-Origin": "https://portal.example.in",
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext(bearer_token="tok_123"))
        outcome = await probe_cors_policy("https://api.example.in", dummy_check, ctx)

        assert outcome.findings == []
        assert "No permissive CORS reflection detected" in outcome.summary

    async def test_fails_when_arbitrary_origin_reflected_with_credentials(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("Origin", "")
            return httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_cors_policy("https://api.example.in", dummy_check, ctx)

        assert len(outcome.findings) == 1
        assert "Credentialed Arbitrary CORS Origin Reflection" in outcome.findings[0].title

    async def test_fails_on_wildcard_origin_for_authenticated_request(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})

        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext(bearer_token="user_jwt"))
        outcome = await probe_cors_policy("https://api.example.in", dummy_check, ctx)

        assert len(outcome.findings) == 1
        assert "Wildcard CORS Policy" in outcome.findings[0].title


class TestProbeDifferentialIdor:
    async def test_skips_cleanly_when_secondary_auth_missing(
        self, dummy_check: ChecklistItem
    ) -> None:
        ctx = ScanContext(primary_auth=AuthContext(bearer_token="token_a"), secondary_auth=None)
        outcome = await probe_differential_idor("https://api.example.in", dummy_check, ctx)
        assert outcome.conclusive is False
        assert "SKIPPED_SECONDARY_AUTH" in outcome.summary

    async def test_passes_when_token_b_gets_403_forbidden(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            auth_hdr = request.headers.get("Authorization", "")
            if auth_hdr == "Bearer token_user_a":
                return httpx.Response(200, json={"order_id": "ORD-101", "amount": 4500})
            return httpx.Response(403, json={"error": "Forbidden"})

        patch_httpx_transport(handler)
        ctx = ScanContext(
            primary_auth=AuthContext(bearer_token="token_user_a"),
            secondary_auth=AuthContext(bearer_token="token_user_b"),
            probe_endpoints=["/api/v1/orders/ORD-101"],
        )
        outcome = await probe_differential_idor("https://api.example.in", dummy_check, ctx)

        assert outcome.findings == []
        assert "properly isolated" in outcome.summary

    async def test_fails_when_token_b_receives_identical_json_schema_200(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"account_id": 9001, "kyc_status": "VERIFIED", "balance": 125000.50},
            )

        patch_httpx_transport(handler)
        ctx = ScanContext(
            primary_auth=AuthContext(bearer_token="token_user_a"),
            secondary_auth=AuthContext(bearer_token="token_user_b"),
            probe_endpoints=["/api/v1/accounts/9001"],
        )
        outcome = await probe_differential_idor("https://api.example.in", dummy_check, ctx)

        assert len(outcome.findings) == 1
        assert "Cross-User Access Parity Signal" in outcome.findings[0].title


class TestProbeJwtSecurity:
    async def test_skips_when_no_bearer_token_present(self, dummy_check: ChecklistItem) -> None:
        ctx = ScanContext(primary_auth=AuthContext(cookies={"sid": "abc"}))
        outcome = await probe_jwt_security("https://api.example.in", dummy_check, ctx)
        assert outcome.conclusive is False
        assert "SKIPPED_NO_JWT" in outcome.summary

    async def test_passes_on_compliant_es256_jwt_without_pii(
        self, dummy_check: ChecklistItem
    ) -> None:
        now = datetime.now(timezone.utc)
        token = _make_jwt(
            header={"alg": "ES256", "typ": "JWT", "kid": "key-2026-01"},
            payload={
                "sub": "usr_9f8e7d6c5b4a",
                "iss": "https://auth.example.in",
                "aud": "tirweb-api",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=30)).timestamp()),
                "scope": "orders:read",
            },
        )
        ctx = ScanContext(primary_auth=AuthContext(bearer_token=token))
        outcome = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert outcome.findings == []
        assert "No JWT hygiene issues detected" in outcome.summary

    async def test_detects_alg_none_risky_headers_missing_exp_and_pii(
        self, dummy_check: ChecklistItem
    ) -> None:
        token = _make_jwt(
            header={
                "alg": "none",
                "jku": "https://attacker.example.invalid/jwks.json",
            },
            payload={
                "sub": "1042",
                "email": "vijay.user@example.in",
                "pan_card": "ABCDE1234F",
                "contact": "+91-9876543210",
            },
            signature="",
        )
        ctx = ScanContext(primary_auth=AuthContext(bearer_token=token))
        outcome = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert len(outcome.findings) >= 4
        titles = " ".join(f.title for f in outcome.findings)
        assert "Insecure JWT Signing Algorithm ('none')" in titles
        assert "Untrusted Key-Location JWT Header" in titles
        assert "Unencrypted PII/Sensitive Claim" in titles

    async def test_flags_excessive_ttl_and_symmetric_hmac_alg(
        self, dummy_check: ChecklistItem
    ) -> None:
        now = datetime.now(timezone.utc)
        token = _make_jwt(
            header={"alg": "HS256", "typ": "JWT"},
            payload={
                "sub": "usr_123",
                "iss": "https://auth.example.in",
                "aud": "api",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(days=7)).timestamp()),
            },
        )
        ctx = ScanContext(primary_auth=AuthContext(bearer_token=token))
        outcome = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert len(outcome.findings) == 2
        titles = " ".join(f.title for f in outcome.findings)
        assert "Symmetric JWT Algorithm ('HS256')" in titles
        assert "Excessive JWT Lifetime" in titles


class TestProbeApiAuthentication:
    async def test_observes_authentication_required(
        self, dummy_check, patch_httpx_transport
    ):
        def handler(request):
            if request.headers.get("Authorization") == "Bearer test-token":
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(401)

        patch_httpx_transport(handler)
        ctx = ScanContext(
            primary_auth=AuthContext(bearer_token="test-token"),
            probe_endpoints=["/api/profile"],
        )

        outcome = await probe_api_authentication("https://app.example.test", dummy_check, ctx)
        assert outcome.findings == []
        assert "unauthenticated=401" in outcome.summary
        assert "authenticated=200" in outcome.summary

    async def test_missing_credentials_is_inconclusive(
        self, dummy_check, patch_httpx_transport
    ):
        # Return 401 when an invalid Authorization header is sent, and 200 when unauthenticated
        def handler(request):
            if "Authorization" in request.headers:
                return httpx.Response(401)
            return httpx.Response(200)

        patch_httpx_transport(handler)
        ctx = ScanContext(
            primary_auth=AuthContext(),
            probe_endpoints=["/api/profile"],
        )

        outcome = await probe_api_authentication("https://app.example.test", dummy_check, ctx)
        assert outcome.findings == []
        assert outcome.conclusive is False

    async def test_missing_endpoint_is_skipped(self, dummy_check):
        ctx = ScanContext(primary_auth=AuthContext())
        outcome = await probe_api_authentication("https://app.example.test", dummy_check, ctx)
        assert outcome.findings == []
        assert outcome.conclusive is False
        assert "SKIPPED_NO_ENDPOINTS" in outcome.summary

    async def test_404_and_405_are_not_vulnerabilities(
        self, dummy_check, patch_httpx_transport
    ):
        def handler(request):
            return httpx.Response(404 if request.url.path.endswith("missing") else 405)

        patch_httpx_transport(handler)
        ctx = ScanContext(
            primary_auth=AuthContext(bearer_token="test-token"),
            probe_endpoints=["/api/missing", "/api/unsupported"],
        )

        outcome = await probe_api_authentication("https://app.example.test", dummy_check, ctx)
        assert outcome.findings == []