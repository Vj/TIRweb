from tirweb.dispatcher import ToolDispatcher
from tirweb.probes import RequestBudgetExceeded
from tirweb.models import AppProfile, TIRWebChecklist


class TestToolDispatcher:
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

        assert res.status == "PASS"
        assert res.check_id == "WEB-CRY-001"
        assert "TLS 1.3 offered" in res.output_summary
        create_proc.assert_awaited_once()

    async def test_automated_check_fails_on_vulnerability_output(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        mock_subprocess_factory(
            which_map={"testssl.sh": "/usr/local/bin/testssl.sh"},
            returncode=0,
            stdout=b"TLS 1.0 offered (NOT ok)\nBEAST VULNERABLE\n",
        )

        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )

        dispatcher = ToolDispatcher()
        res = await dispatcher.execute_check("https://legacy.example.in", mod, chk)

        assert res.status == "FAIL"
        assert "VULNERABLE" in res.output_summary

    async def test_nuclei_binding_fails_when_findings_returned(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        create_proc = mock_subprocess_factory(
            which_map={"nuclei": "/usr/bin/nuclei"},
            returncode=0,
            stdout=b"[ssrf-aws-metadata] [http] [critical] https://example.in/fetch?url=http://169.254.169.254\n",
        )

        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.BFSI_FINTECH)
            if c.id == "WEB-LOG-001"
        )

        dispatcher = ToolDispatcher()
        await dispatcher.initialize_dynamic_bindings()
        res = await dispatcher.execute_check("https://example.in", mod, chk)

        assert res.status == "FAIL"
        assert "Found 1 issue(s)" in res.output_summary
        # Verify nuclei was invoked with expected tags
        called_args = create_proc.call_args.args
        assert called_args[:4] == ("nuclei", "-u", "https://example.in", "-tags")
        assert called_args[4] == "ssrf"

    async def test_hybrid_check_returns_hybrid_review_on_clean_probe(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        mock_subprocess_factory(
            which_map={"nuclei": "/usr/bin/nuclei"},
            returncode=0,
            stdout=b"",
        )

        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-IAM-001"
        )

        dispatcher = ToolDispatcher()
        await dispatcher.initialize_dynamic_bindings()
        res = await dispatcher.execute_check("https://example.in", mod, chk)

        assert res.status == "HYBRID_REVIEW"

    async def test_manual_check_skips_subprocess_execution(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        create_proc = mock_subprocess_factory(which_map={})

        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.SAAS_MULTITENANT)
            if c.id == "WEB-IAM-003"
        )

        dispatcher = ToolDispatcher()
        res = await dispatcher.execute_check("https://saas.example.in", mod, chk)

        assert res.status == "MANUAL_REQUIRED"
        create_proc.assert_not_awaited()

    async def test_network_error_is_not_reported_as_vulnerability(
        self, loaded_checklist: TIRWebChecklist
    ) -> None:
        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )
        dispatcher = ToolDispatcher()

        async def network_failure(target, check, ctx):
            raise OSError("getaddrinfo failed")

        dispatcher.registry["testssl"] = network_failure
        result = await dispatcher.execute_check("https://example.in", mod, chk)

        assert result.status == "ERROR"
        assert "getaddrinfo failed" in result.output_summary

    async def test_request_budget_exhaustion_is_inconclusive_not_execution_error(
        self, loaded_checklist: TIRWebChecklist
    ) -> None:
        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )
        dispatcher = ToolDispatcher()

        async def budget_exhausted(target, check, ctx):
            raise RequestBudgetExceeded("Scan request budget exhausted (1 requests).")

        dispatcher.registry["testssl"] = budget_exhausted
        result = await dispatcher.execute_check("https://example.in", mod, chk)

        assert result.status == "INCONCLUSIVE"
        assert "INCONCLUSIVE_SCAN_BUDGET" in result.output_summary

    async def test_probe_review_marker_maps_to_inconclusive_status(
        self, loaded_checklist: TIRWebChecklist
    ) -> None:
        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )
        dispatcher = ToolDispatcher()

        async def review_required(target, check, ctx):
            return True, "INCONCLUSIVE_JWT_REVIEW: Verify issuer and relying-party policy."

        dispatcher.registry["testssl"] = review_required
        result = await dispatcher.execute_check("https://example.in", mod, chk)

        assert result.status == "INCONCLUSIVE"
        assert "INCONCLUSIVE_JWT_REVIEW" in result.output_summary

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

        assert res.status == "TOOL_MISSING"
        assert "not found in PATH" in res.output_summary

    async def test_dry_run_mode_does_not_spawn_processes(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        create_proc = mock_subprocess_factory(which_map={"testssl.sh": "/usr/bin/testssl.sh"})

        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )

        dispatcher = ToolDispatcher()
        res = await dispatcher.execute_check("https://example.in", mod, chk, dry_run=True)

        assert res.status == "DRY_RUN"
        assert "Would dispatch bindings: testssl" in res.output_summary
        create_proc.assert_not_awaited()

    async def test_subprocess_timeout_kills_process_and_fails(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory, monkeypatch
    ) -> None:
        # Reduce timeout inside _run_subprocess to 0.05s for fast testing
        from tirweb import dispatcher as disp_mod

        orig_run = disp_mod._run_subprocess

        async def fast_timeout_run(cmd, timeout=180):
            return await orig_run(cmd, timeout=0.05)

        monkeypatch.setattr(disp_mod, "_run_subprocess", fast_timeout_run)
        create_proc = mock_subprocess_factory(
            which_map={"testssl.sh": "/usr/bin/testssl.sh"},
            hang=True,
        )

        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )

        dispatcher = ToolDispatcher()
        res = await dispatcher.execute_check("https://slow.example.in", mod, chk)

        assert res.status == "ERROR"
        assert "timed out" in res.output_summary
        create_proc.return_value.wait.assert_awaited_once()

    async def test_nonzero_testssl_exit_is_execution_error_not_vulnerability(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        mock_subprocess_factory(
            which_map={"testssl.sh": "/usr/bin/testssl.sh"},
            returncode=2,
            stderr=b"connection setup failed",
        )
        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.CORE)
            if c.id == "WEB-CRY-001"
        )

        result = await ToolDispatcher().execute_check("https://example.in", mod, chk)

        assert result.status == "ERROR"
        assert "connection setup failed" in result.output_summary
        assert "FAIL:" not in result.output_summary

    async def test_nonzero_nuclei_exit_is_execution_error_not_clean_scan(
        self, loaded_checklist: TIRWebChecklist, mock_subprocess_factory
    ) -> None:
        mock_subprocess_factory(
            which_map={"nuclei": "/usr/bin/nuclei"},
            returncode=2,
            stderr=b"template initialization failed",
        )
        mod, chk = next(
            (m, c)
            for m, c in loaded_checklist.filter_checks(AppProfile.BFSI_FINTECH)
            if c.id == "WEB-LOG-001"
        )
        dispatcher = ToolDispatcher()
        await dispatcher.initialize_dynamic_bindings()

        result = await dispatcher.execute_check("https://example.in", mod, chk)

        assert result.status == "ERROR"
        assert "template initialization failed" in result.output_summary
        assert "No nuclei findings" not in result.output_summary
