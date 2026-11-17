import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Callable
import httpx
import pytest
from tirweb.models import AppProfile, AuthContext, ChecklistItem, ComplianceMapping, ExecutionMode, Severity
from tirweb.probes import (
    ScanContext,
    probe_cors_policy,
    probe_differential_idor,
    probe_jwt_security,
    probe_security_headers,
)


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


@pytest.fixture
def patch_httpx_transport(monkeypatch: pytest.MonkeyPatch):
    """Monkeypatch httpx.AsyncClient inside tirweb.probes to route via MockTransport."""

    def _apply(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        transport = httpx.MockTransport(handler)
        orig_async_client = httpx.AsyncClient

        class MockedAsyncClient(orig_async_client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        monkeypatch.setattr("tirweb.probes.httpx.AsyncClient", MockedAsyncClient)

    return _apply


def _make_jwt(header: dict, payload: dict, signature: str = "dummy_sig") -> str:
    """Helper to encode a 3-segment JWS token for passive inspection tests."""
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{signature}"


# ==============================================================================
# 1. Security Headers Probe Tests
# ==============================================================================
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
        passed, detail = await probe_security_headers("https://app.example.in", dummy_check, ctx)

        assert passed is True
        assert "All baseline security headers verified" in detail

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
        passed, _ = await probe_security_headers("https://app.example.in", dummy_check, ctx)

        assert passed is True

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
        passed, detail = await probe_security_headers("https://legacy.example.in", dummy_check, ctx)

        assert passed is False
        assert "HSTS missing" in detail
        assert "Content-Security-Policy (CSP) header missing" in detail
        assert "X-Content-Type-Options misconfigured" in detail
        assert "server=nginx/1.18.0 (Ubuntu)" in detail
        assert "x-powered-by=Express" in detail


# ==============================================================================
# 2. CORS Policy Probe Tests
# ==============================================================================
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
        passed, detail = await probe_cors_policy("https://api.example.in", dummy_check, ctx)

        assert passed is True
        assert "CORS policy safe" in detail

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
        passed, detail = await probe_cors_policy("https://api.example.in", dummy_check, ctx)

        assert passed is False
        assert "Arbitrary Origin reflected" in detail
        assert "Access-Control-Allow-Credentials: true" in detail

    async def test_fails_on_wildcard_origin_for_authenticated_request(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})

        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext(bearer_token="user_jwt"))
        passed, detail = await probe_cors_policy("https://api.example.in", dummy_check, ctx)

        assert passed is False
        assert "Wildcard Access-Control-Allow-Origin: *" in detail


# ==============================================================================
# 3. Differential IDOR / BOLA Probe Tests
# ==============================================================================
class TestProbeDifferentialIdor:
    async def test_skips_cleanly_when_secondary_auth_missing(
        self, dummy_check: ChecklistItem
    ) -> None:
        ctx = ScanContext(primary_auth=AuthContext(bearer_token="token_a"), secondary_auth=None)
        passed, detail = await probe_differential_idor("https://api.example.in", dummy_check, ctx)

        assert passed is True
        assert "SKIPPED_SECONDARY_AUTH" in detail

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
        passed, detail = await probe_differential_idor("https://api.example.in", dummy_check, ctx)

        assert passed is True
        assert "Token B properly isolated" in detail

    async def test_fails_when_token_b_receives_identical_json_schema_200(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            # Simulates broken object-level authorization returning User A's record to User B
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
        passed, detail = await probe_differential_idor("https://api.example.in", dummy_check, ctx)

        assert passed is False
        assert "Potential cross-user access control parity detected" in detail
        assert "/api/v1/accounts/9001" in detail


# ==============================================================================
# 4. JWT Security Inspection Probe Tests
# ==============================================================================
class TestProbeJwtSecurity:
    async def test_skips_when_no_bearer_token_present(self, dummy_check: ChecklistItem) -> None:
        ctx = ScanContext(primary_auth=AuthContext(cookies={"sid": "abc"}))
        passed, detail = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert passed is True
        assert "SKIPPED_NO_JWT" in detail

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
        passed, detail = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert passed is True
        assert "1 JWS token(s) verified clean" in detail

    async def test_jwe_is_reported_as_inconclusive_not_clean(
        self, dummy_check: ChecklistItem
    ) -> None:
        ctx = ScanContext(primary_auth=AuthContext(bearer_token="a.b.c.d.e"))
        passed, detail = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert passed is True
        assert "INCONCLUSIVE_JWT" in detail
        assert "JWE token requires issuer/key-aware verification" in detail

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
        passed, detail = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert passed is False
        assert "Insecure or missing signing algorithm: alg='none'" in detail
        assert "Untrusted key-location header parameter(s) present: jku" in detail
        assert "Missing 'exp' (expiration) claim" in detail
        assert "Missing 'aud' (audience) claim" in detail
        assert "Email address detected inside claim 'email'" in detail
        assert "Indian PAN-like identifier detected inside claim 'pan_card'" in detail
        assert "Indian mobile number detected inside claim 'contact'" in detail

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
                "exp": int((now + timedelta(days=7)).timestamp()),  # 168h > 24h max
            },
        )
        ctx = ScanContext(primary_auth=AuthContext(bearer_token=token))
        passed, detail = await probe_jwt_security("https://api.example.in", dummy_check, ctx)

        assert passed is True
        assert "Symmetric algorithm" not in detail
        assert "signature validation is not performed" in detail
        assert "Excessive token lifetime (168.0h > 24h recommended maximum)" in detail