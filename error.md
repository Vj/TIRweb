>> python benchmarks/evaluate.py --target-filter "_local" --min-precision 0.90 --min-recall 0.90
>> docker compose -f benchmarks/docker-compose.benchmark.yml down -v
[+] up 47/50
 ✔ Image vulnerables/web-dvwa:latest  Pulled                                                         121.7s ✔ Image bkimminich/juice-shop:latest Pulled                                                         116.5s ✔ Image erev0s/vampi:latest          Pulled                                                          85.4s ✔ Network benchmarks_default         Created                                                          0.2s
 - Container benchmarks-vampi-1       Waiting                                                        106.4s
 - Container benchmarks-juice-shop-1  Waiting                                                        106.4s
 - Container benchmarks-dvwa-1        Waiting                                                        106.4scontainer benchmarks-vampi-1 is unhealthy

What's next:
    Debug this Compose error with Gordon → docker ai "help me fix this compose error"
[juice_shop_local] TP=1, FP=0, FN=2
  Missed expected rules: ['WEB-CRY-001:httpx_tls:cleartext_target', 'WEB-INF-001:httpx_cors:wildcard_auth'][dvwa_local] TP=0, FP=0, FN=4
  Missed expected rules: ['WEB-CRY-001:httpx_tls:cleartext_target', 'WEB-IAM-006:httpx_cookies:PHPSESSID:secure', 'WEB-IAM-006:httpx_cookies:PHPSESSID:httponly', 'WEB-IAM-004:httpx_auth_surface:http_login']
[vampi_local] TP=2, FP=0, FN=1
  Missed expected rules: ['WEB-CRY-001:httpx_tls:cleartext_target']

Benchmark Summary -> Precision: 1.000 | Recall: 0.300 | F1: 0.462
ERROR: Benchmark threshold failed (required Precision >= 0.90, Recall >= 0.90).
[+] down 4/4
 ✔ Container benchmarks-dvwa-1       Removed                                                           4.1s ✔ Container benchmarks-vampi-1      Removed                                                           1.0s ✔ Container benchmarks-juice-shop-1 Removed                                                           0.9s
 ✔ Network benchmarks_default        Removed                                                           0.3sPS C:\Users\ADMIN\Documents\TIRweb> pytest -v                                                              
========================================== test session starts ===========================================
platform win32 -- Python 3.14.7, pytest-8.4.2, pluggy-1.6.0 -- C:\Users\ADMIN\AppData\Local\Programs\Python\Python314\python.exe                                               
cachedir: .pytest_cache
rootdir: C:\Users\ADMIN\Documents\TIRweb
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.14.2, asyncio-1.5.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=function, asyncio_default_test_loop_scope=function
collected 50 items                                                                                        

tests/test_cli.py::TestCLI::test_validate_command_succeeds PASSED                                   [  2%]
tests/test_cli.py::TestCLI::test_scan_dry_run_exports_html_report PASSED                            [  4%]
tests/test_cli.py::TestCLI::test_scan_with_mocked_tools_and_automated_only PASSED                   [  6%]
tests/test_dispatcher.py::TestToolDispatcher::test_automated_check_passes_when_tool_reports_clean FAILED [ 8%]
tests/test_dispatcher.py::TestToolDispatcher::test_automated_check_fails_on_vulnerability_output PASSED [ 10%]
tests/test_dispatcher.py::TestToolDispatcher::test_nuclei_binding_fails_when_findings_returned PASSED [ 12%]
tests/test_dispatcher.py::TestToolDispatcher::test_hybrid_check_returns_hybrid_review_on_clean_probe PASSED [ 14%]
tests/test_dispatcher.py::TestToolDispatcher::test_manual_check_skips_subprocess_execution PASSED   [ 16%]
tests/test_dispatcher.py::TestToolDispatcher::test_missing_binary_marks_check_tool_missing FAILED   [ 18%]
tests/test_dispatcher.py::TestToolDispatcher::test_dry_run_mode_does_not_spawn_processes PASSED     [ 20%]
tests/test_dispatcher.py::TestToolDispatcher::test_subprocess_timeout_kills_process_and_fails PASSED [ 22%]tests/test_models.py::TestSchemaValidation::test_valid_checklist_loads_cleanly PASSED               [ 24%]
tests/test_models.py::TestSchemaValidation::test_rejects_invalid_check_id_pattern[IAM-001] PASSED   [ 26%]
tests/test_models.py::TestSchemaValidation::test_rejects_invalid_check_id_pattern[WEB-iam-001] PASSED [ 28%]
tests/test_models.py::TestSchemaValidation::test_rejects_invalid_check_id_pattern[WEB-IAM-12] PASSED [ 30%]tests/test_models.py::TestSchemaValidation::test_rejects_invalid_check_id_pattern[WEB-IAM-0001] PASSED [ 32%]
tests/test_models.py::TestSchemaValidation::test_rejects_invalid_module_id_pattern PASSED           [ 34%]
tests/test_models.py::TestSchemaValidation::test_rejects_wrong_tool_suite_literal PASSED            [ 36%]
tests/test_models.py::TestSchemaValidation::test_rejects_empty_indian_compliance_mapping PASSED     [ 38%]
tests/test_models.py::TestSchemaValidation::test_rejects_duplicate_check_ids_across_modules PASSED  [ 40%]
tests/test_models.py::TestProfileFiltering::test_bfsi_profile_includes_core_and_bfsi_checks PASSED  [ 42%]
tests/test_models.py::TestProfileFiltering::test_saas_profile_includes_multitenant_and_core_checks PASSED [ 44%]
tests/test_models.py::TestProfileFiltering::test_exclude_core_returns_only_domain_specific_checks PASSED [46%]
tests/test_models.py::TestProfileFiltering::test_execution_mode_filtering_automated_only PASSED     [ 48%]
tests/test_new_probes.py::TestNewProbes::test_metafiles_detects_leaked_paths_and_wildcard_crossdomain PASSED [ 50%]
tests/test_new_probes.py::TestNewProbes::test_path_confusion_flags_bypass_when_variant_returns_200 PASSED [ 52%]
tests/test_new_probes.py::TestNewProbes::test_open_redirect_detects_unvalidated_location_header PASSED [ 54%]
tests/test_new_probes.py::TestNewProbes::test_graphql_detects_enabled_introspection_and_batching PASSED [ 56%]
tests/test_new_probes.py::TestNewProbes::test_graphql_passes_when_introspection_and_batching_blocked PASSED [ 58%]
tests/test_new_probes.py::TestNewProbes::test_tls_probe_flags_cleartext_http_and_skips_hsts PASSED  [ 60%]
tests/test_new_probes.py::TestNewProbes::test_cookie_and_cve_fingerprint_probes PASSED              [ 62%]
tests/test_probes.py::test_idor_skips_when_primary_identity_is_missing PASSED                       [ 64%]
tests/test_probes.py::TestProbeSecurityHeaders::test_passes_with_complete_hardened_headers FAILED   [ 66%]
tests/test_probes.py::TestProbeSecurityHeaders::test_accepts_csp_frame_ancestors_instead_of_x_frame_options FAILED [ 68%]
tests/test_probes.py::TestProbeSecurityHeaders::test_fails_on_missing_headers_and_version_leaks FAILED [ 70%]
tests/test_probes.py::TestProbeCorsPolicy::test_passes_when_untrusted_origin_not_reflected FAILED   [ 72%]
tests/test_probes.py::TestProbeCorsPolicy::test_fails_when_arbitrary_origin_reflected_with_credentials FAILED [ 74%]
tests/test_probes.py::TestProbeCorsPolicy::test_fails_on_wildcard_origin_for_authenticated_request FAILED [ 76%]
tests/test_probes.py::TestProbeDifferentialIdor::test_skips_cleanly_when_secondary_auth_missing PASSED [ 78%]
tests/test_probes.py::TestProbeDifferentialIdor::test_passes_when_token_b_gets_403_forbidden FAILED [ 80%]
tests/test_probes.py::TestProbeDifferentialIdor::test_fails_when_token_b_receives_identical_json_schema_200 FAILED [ 82%]
tests/test_probes.py::TestProbeJwtSecurity::test_skips_when_no_bearer_token_present PASSED          [ 84%]
tests/test_probes.py::TestProbeJwtSecurity::test_passes_on_compliant_es256_jwt_without_pii FAILED   [ 86%]
tests/test_probes.py::TestProbeJwtSecurity::test_detects_alg_none_risky_headers_missing_exp_and_pii FAILED[ 88%]
tests/test_probes.py::TestProbeJwtSecurity::test_flags_excessive_ttl_and_symmetric_hmac_alg FAILED  [ 90%]
tests/test_probes.py::TestProbeApiAuthentication::test_observes_authentication_required FAILED      [ 92%]
tests/test_probes.py::TestProbeApiAuthentication::test_missing_credentials_is_inconclusive PASSED   [ 94%]
tests/test_probes.py::TestProbeApiAuthentication::test_missing_endpoint_is_skipped PASSED           [ 96%]
tests/test_probes.py::TestProbeApiAuthentication::test_404_and_405_are_not_vulnerabilities FAILED   [ 98%]
tests/test_regression_golden.py::TestRegressionAndGoldenSnapshot::test_recorded_testfire_precision_and_atomic_splitting FAILED [100%]

================================================ FAILURES ================================================
_________________ TestToolDispatcher.test_automated_check_passes_when_tool_reports_clean _________________

self = <test_dispatcher.TestToolDispatcher object at 0x000001A382E85A90>
loaded_checklist = TIRWebChecklist(schema_version='1.0.0', tool_suite='TIRweb', metadata=ChecklistMetadata(description='Test TIRweb Check...ompliance=ComplianceMapping(india=['RBI Digital Payment Security Controls'], global_=['PCI DSS v4.0: Req. 6.2.4']))])])
mock_subprocess_factory = <function mock_subprocess_factory.<locals>._configure at 0x000001A383048040>

    async def test_automated_check_passes_when_tool_reports_clean(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        create_proc = mock_subprocess_factory(
            which_map={"testssl.sh": "/usr/local/bin/testssl.sh"},
            returncode=0,
            stdout=b"TLS 1.3 offered\nHSTS: max-age=31536000 (OK)\n",
        )
    
        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )
    
        dispatcher = ToolDispatcher(concurrency=2)
        await dispatcher.initialize_dynamic_bindings()
        res = await dispatcher.execute_check("https://example.in", mod, chk)
    
>       assert res.status == "PASS"
E       AssertionError: assert 'NO_ISSUES_FOUND' == 'PASS'
E         
E         - PASS
E         + NO_ISSUES_FOUND

tests\test_dispatcher.py:25: AssertionError
____________________ TestToolDispatcher.test_missing_binary_marks_check_tool_missing _____________________

self = <test_dispatcher.TestToolDispatcher object at 0x000001A382EDF680>
loaded_checklist = TIRWebChecklist(schema_version='1.0.0', tool_suite='TIRweb', metadata=ChecklistMetadata(description='Test TIRweb Check...ompliance=ComplianceMapping(india=['RBI Digital Payment Security Controls'], global_=['PCI DSS v4.0: Req. 6.2.4']))])])
mock_subprocess_factory = <function mock_subprocess_factory.<locals>._configure at 0x000001A382F5FCC0>

    async def test_missing_binary_marks_check_tool_missing(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        mock_subprocess_factory(which_map={})  # No binaries installed
    
        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )
    
        dispatcher = ToolDispatcher()
        res = await dispatcher.execute_check("https://example.in", mod, chk)
    
>       assert res.status == "TOOL_MISSING"
E       AssertionError: assert 'INCONCLUSIVE' == 'TOOL_MISSING'
E         
E         - TOOL_MISSING
E         + INCONCLUSIVE

tests\test_dispatcher.py:129: AssertionError
__________________ TestProbeSecurityHeaders.test_passes_with_complete_hardened_headers ___________________

self = <test_probes.TestProbeSecurityHeaders object at 0x000001A382E860D0>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A3840EBD70>

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
>       assert "All applicable baseline security headers verified" in detail
                                                                      ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:105: NameError
__________ TestProbeSecurityHeaders.test_accepts_csp_frame_ancestors_instead_of_x_frame_options __________

self = <test_probes.TestProbeSecurityHeaders object at 0x000001A382E87110>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A3840EAFB0>

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
>       passed, _ = await probe_security_headers("https://app.example.in", dummy_check, ctx)
        ^^^^^^^^^
E       ValueError: too many values to unpack (expected 2)

tests\test_probes.py:124: ValueError
________________ TestProbeSecurityHeaders.test_fails_on_missing_headers_and_version_leaks ________________

self = <test_probes.TestProbeSecurityHeaders object at 0x000001A382EEF230>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A3840EA2A0>

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
    
        assert len(outcome.findings) >= 1
>       assert "HSTS missing" in detail
                                 ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:146: NameError
__________________ TestProbeCorsPolicy.test_passes_when_untrusted_origin_not_reflected ___________________

self = <test_probes.TestProbeCorsPolicy object at 0x000001A382E87390>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A384108880>

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
>       assert "CORS policy safe" in detail
                                     ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:174: NameError
____________ TestProbeCorsPolicy.test_fails_when_arbitrary_origin_reflected_with_credentials _____________

self = <test_probes.TestProbeCorsPolicy object at 0x000001A382E874D0>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A3841090C0>

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
    
        assert len(outcome.findings) >= 1
>       assert "Arbitrary Origin reflected" in detail
                                               ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:194: NameError
______________ TestProbeCorsPolicy.test_fails_on_wildcard_origin_for_authenticated_request _______________

self = <test_probes.TestProbeCorsPolicy object at 0x000001A382EEF5C0>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A3841099B0>

    async def test_fails_on_wildcard_origin_for_authenticated_request(
        self, dummy_check: ChecklistItem, patch_httpx_transport
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})
    
        patch_httpx_transport(handler)
        ctx = ScanContext(primary_auth=AuthContext(bearer_token="user_jwt"))
        outcome = await probe_cors_policy("https://api.example.in", dummy_check, ctx)
    
        assert len(outcome.findings) >= 1
>       assert "Wildcard Access-Control-Allow-Origin: *" in detail
                                                            ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:208: NameError
_________________ TestProbeDifferentialIdor.test_passes_when_token_b_gets_403_forbidden __________________

self = <test_probes.TestProbeDifferentialIdor object at 0x000001A382E87750>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A38410A400>

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
>       assert "Token B properly isolated" in detail
                                              ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:242: NameError
__________ TestProbeDifferentialIdor.test_fails_when_token_b_receives_identical_json_schema_200 __________

self = <test_probes.TestProbeDifferentialIdor object at 0x000001A382EEF6F0>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A3840E9BC0>

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
        outcome = await probe_differential_idor("https://api.example.in", dummy_check, ctx)
    
        assert len(outcome.findings) >= 1
>       assert "Potential cross-user access control parity detected" in detail
                                                                        ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:263: NameError
__________________ TestProbeJwtSecurity.test_passes_on_compliant_es256_jwt_without_pii ___________________

self = <test_probes.TestProbeJwtSecurity object at 0x000001A382E87890>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))

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
>       assert "1 JWS token(s) verified clean" in detail
                                                  ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:297: NameError
______________ TestProbeJwtSecurity.test_detects_alg_none_risky_headers_missing_exp_and_pii ______________

self = <test_probes.TestProbeJwtSecurity object at 0x000001A382EEF820>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))

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
    
        assert len(outcome.findings) >= 1
>       assert "Insecure or missing signing algorithm: alg='none'" in detail
                                                                      ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:319: NameError
__________________ TestProbeJwtSecurity.test_flags_excessive_ttl_and_symmetric_hmac_alg __________________

self = <test_probes.TestProbeJwtSecurity object at 0x000001A382EEF950>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))

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
        outcome = await probe_jwt_security("https://api.example.in", dummy_check, ctx)
    
        assert len(outcome.findings) >= 1
>       assert "Symmetric algorithm 'HS256' used" in detail
                                                     ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:345: NameError
____________________ TestProbeApiAuthentication.test_observes_authentication_required ____________________

self = <test_probes.TestProbeApiAuthentication object at 0x000001A382E879D0>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A38304AFB0>

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
    
        outcome = await probe_api_authentication(
            "https://app.example.test", dummy_check, ctx
        )
    
        assert outcome.findings == []
>       assert "API_AUTH_OBSERVATION" in detail
                                         ^^^^^^
E       NameError: name 'detail' is not defined

tests\test_probes.py:372: NameError
__________________ TestProbeApiAuthentication.test_404_and_405_are_not_vulnerabilities ___________________

self = <test_probes.TestProbeApiAuthentication object at 0x000001A382EEFBB0>
dummy_check = ChecklistItem(id='WEB-INF-001', title='Security Headers, CORS, IDOR & JWT Probe Fixture', category='Security Misconfig...e=ComplianceMapping(india=['DPDP Rules 2025 - Rule 6(1)(a)'], global_=['OWASP Top 10: A05 Security Misconfiguration']))
patch_httpx_transport = <function patch_httpx_transport.<locals>._apply at 0x000001A38410A610>

    async def test_404_and_405_are_not_vulnerabilities(
        self, dummy_check, patch_httpx_transport
    ):
        def handler(request):
            return httpx.Response(
                404 if request.url.path.endswith("missing") else 405
            )
    
        patch_httpx_transport(handler)
        ctx = ScanContext(
            primary_auth=AuthContext(bearer_token="test-token"),
            probe_endpoints=["/api/missing", "/api/unsupported"],
        )
    
        outcome = await probe_api_authentication(
            "https://app.example.test", dummy_check, ctx
        )
    
        assert outcome.findings == []
>       assert outcome.conclusive is False
E       AssertionError: assert True is False
E        +  where True = ProbeOutcome(findings=[], summary='https://app.example.test/api/missing: unauthenticated=404, authenticated=404. | https://app.example.test/api/unsupported: unauthenticated=405, authenticated=405.', conclusive=True, not_detected_scope=None).conclusive

tests\test_probes.py:422: AssertionError
_________ TestRegressionAndGoldenSnapshot.test_recorded_testfire_precision_and_atomic_splitting __________

self = <test_regression_golden.TestRegressionAndGoldenSnapshot object at 0x000001A382E87ED0>
recorded_testfire_transport = 'http://demo.testfire.net'
monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x000001A38410FD90>

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
>       assert "WEB-CRY-001:httpx_tls:cleartext_target" in cry_rules
E       AssertionError: assert 'WEB-CRY-001:httpx_tls:cleartext_target' in {'WEB-CRY-001:httpx_headers:leak_server', 'WEB-CRY-001:httpx_headers:missing_content-security-policy', 'WEB-CRY-001:httpx_headers:missing_permissions-policy', 'WEB-CRY-001:httpx_headers:missing_referrer-policy', 'WEB-CRY-001:httpx_headers:missing_x-content-type-options', 'WEB-CRY-001:httpx_headers:missing_x-frame-options'}

tests\test_regression_golden.py:71: AssertionError
======================================== short test summary info =========================================
FAILED tests/test_dispatcher.py::TestToolDispatcher::test_automated_check_passes_when_tool_reports_clean -AssertionError: assert 'NO_ISSUES_FOUND' == 'PASS'
FAILED tests/test_dispatcher.py::TestToolDispatcher::test_missing_binary_marks_check_tool_missing - AssertionError: assert 'INCONCLUSIVE' == 'TOOL_MISSING'
FAILED tests/test_probes.py::TestProbeSecurityHeaders::test_passes_with_complete_hardened_headers - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeSecurityHeaders::test_accepts_csp_frame_ancestors_instead_of_x_frame_options - ValueError: too many values to unpack (expected 2)
FAILED tests/test_probes.py::TestProbeSecurityHeaders::test_fails_on_missing_headers_and_version_leaks - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeCorsPolicy::test_passes_when_untrusted_origin_not_reflected - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeCorsPolicy::test_fails_when_arbitrary_origin_reflected_with_credentia
FAILED tests/test_probes.py::TestProbeCorsPolicy::test_fails_on_wildcard_origin_for_authenticated_request - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeDifferentialIdor::test_passes_when_token_b_gets_403_forbidden - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeDifferentialIdor::test_fails_when_token_b_receives_identical_json_schema_200 - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeJwtSecurity::test_passes_on_compliant_es256_jwt_without_pii - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeJwtSecurity::test_detects_alg_none_risky_headers_missing_exp_and_pii- NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeJwtSecurity::test_flags_excessive_ttl_and_symmetric_hmac_alg - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeApiAuthentication::test_observes_authentication_required - NameError: name 'detail' is not defined
FAILED tests/test_probes.py::TestProbeApiAuthentication::test_404_and_405_are_not_vulnerabilities - AssertionError: assert True is False
FAILED tests/test_regression_golden.py::TestRegressionAndGoldenSnapshot::test_recorded_testfire_precision_and_atomic_splitting - AssertionError: assert 'WEB-CRY-001:httpx_tls:cleartext_target' in {'WEB-CRY-001:httpx_headers:leak_se...
===================================== 16 failed, 34 passed in 2.60s ======================================
PS C:\Users\ADMIN\Documents\TIRweb> docker compose -f benchmarks/docker-compose.benchmark.yml up -d --wait juice-shop dvwa vampi
>> python benchmarks/evaluate.py --target-filter "_local" --min-precision 0.90 --min-recall 0.90
>> docker compose -f benchmarks/docker-compose.benchmark.yml down -v
[+] up 1/4
 ✔ Network benchmarks_default        Created                                                           0.1s
 - Container benchmarks-vampi-1      Waiting                                                         102.5s
 - Container benchmarks-juice-shop-1 Waiting                                                         102.5s
 - Container benchmarks-dvwa-1       Waiting                                                         102.5scontainer benchmarks-vampi-1 is unhealthy

What's next:
    Debug this Compose error with Gordon → docker ai "help me fix this compose error"
[juice_shop_local] TP=1, FP=0, FN=2
  Missed expected rules: ['WEB-CRY-001:httpx_tls:cleartext_target', 'WEB-INF-001:httpx_cors:wildcard_auth'][dvwa_local] TP=0, FP=0, FN=4
  Missed expected rules: ['WEB-CRY-001:httpx_tls:cleartext_target', 'WEB-IAM-006:httpx_cookies:PHPSESSID:secure', 'WEB-IAM-006:httpx_cookies:PHPSESSID:httponly', 'WEB-IAM-004:httpx_auth_surface:http_login']
[vampi_local] TP=2, FP=0, FN=1
  Missed expected rules: ['WEB-CRY-001:httpx_tls:cleartext_target']

Benchmark Summary -> Precision: 1.000 | Recall: 0.300 | F1: 0.462
ERROR: Benchmark threshold failed (required Precision >= 0.90, Recall >= 0.90).
[+] down 4/4
 ✔ Container benchmarks-dvwa-1       Removed                                                           3.8s ✔ Container benchmarks-vampi-1      Removed                                                           0.9s ✔ Container benchmarks-juice-shop-1 Removed                                                           0.8s
 ✔ Network benchmarks_default        Removed                                                           0.3sPS C:\Users\ADMIN\Documents\TIRweb> 