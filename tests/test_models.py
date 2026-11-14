import copy
import pytest
from pydantic import ValidationError
from tirweb.models import AppProfile, ExecutionMode, TIRWebChecklist


class TestSchemaValidation:
    def test_valid_checklist_loads_cleanly(self, loaded_checklist: TIRWebChecklist) -> None:
        assert loaded_checklist.tool_suite == "TIRweb"
        assert loaded_checklist.schema_version == "1.0.0"
        assert len(loaded_checklist.modules) == 3

    @pytest.mark.parametrize(
        "bad_id",
        [
            "IAM-001",        # Missing WEB- prefix
            "WEB-iam-001",    # Lowercase module code
            "WEB-IAM-12",     # Only 2 digits
            "WEB-IAM-0001",   # 4 digits
        ],
    )
    def test_rejects_invalid_check_id_pattern(
        self, sample_checklist_dict: dict, bad_id: str
    ) -> None:
        data = copy.deepcopy(sample_checklist_dict)
        data["modules"][0]["checks"][0]["id"] = bad_id

        with pytest.raises(ValidationError) as exc_info:
            TIRWebChecklist.model_validate(data)
        assert "WEB-[A-Z]{3}-\\d{3}" in str(exc_info.value)

    def test_rejects_invalid_module_id_pattern(self, sample_checklist_dict: dict) -> None:
        data = copy.deepcopy(sample_checklist_dict)
        data["modules"][0]["module_id"] = "INVALID-123"

        with pytest.raises(ValidationError):
            TIRWebChecklist.model_validate(data)

    def test_rejects_wrong_tool_suite_literal(self, sample_checklist_dict: dict) -> None:
        data = copy.deepcopy(sample_checklist_dict)
        data["tool_suite"] = "TIRiOS"

        with pytest.raises(ValidationError):
            TIRWebChecklist.model_validate(data)

    def test_rejects_empty_indian_compliance_mapping(self, sample_checklist_dict: dict) -> None:
        data = copy.deepcopy(sample_checklist_dict)
        data["modules"][0]["checks"][0]["compliance"]["india"] = []

        with pytest.raises(ValidationError):
            TIRWebChecklist.model_validate(data)

    def test_rejects_duplicate_check_ids_across_modules(
        self, sample_checklist_dict: dict
    ) -> None:
        data = copy.deepcopy(sample_checklist_dict)
        # Copy WEB-IAM-001 into TIR-CRYPTO module
        duplicate_check = copy.deepcopy(data["modules"][0]["checks"][0])
        data["modules"][1]["checks"].append(duplicate_check)

        with pytest.raises(ValidationError) as exc_info:
            TIRWebChecklist.model_validate(data)
        assert "Duplicate check ID detected: WEB-IAM-001" in str(exc_info.value)


class TestProfileFiltering:
    def test_bfsi_profile_includes_core_and_bfsi_checks(
        self, loaded_checklist: TIRWebChecklist
    ) -> None:
        results = loaded_checklist.filter_checks(profile=AppProfile.BFSI_FINTECH)
        ids = [chk.id for _, chk in results]

        assert ids == ["WEB-IAM-001", "WEB-CRY-001", "WEB-LOG-001"]
        # SaaS-only check must be excluded
        assert "WEB-IAM-003" not in ids

    def test_saas_profile_includes_multitenant_and_core_checks(
        self, loaded_checklist: TIRWebChecklist
    ) -> None:
        results = loaded_checklist.filter_checks(profile=AppProfile.SAAS_MULTITENANT)
        ids = [chk.id for _, chk in results]

        assert ids == ["WEB-IAM-001", "WEB-IAM-003", "WEB-CRY-001"]
        assert "WEB-LOG-001" not in ids

    def test_exclude_core_returns_only_domain_specific_checks(
        self, loaded_checklist: TIRWebChecklist
    ) -> None:
        results = loaded_checklist.filter_checks(
            profile=AppProfile.ECOMMERCE, include_core=False
        )
        ids = [chk.id for _, chk in results]

        assert ids == ["WEB-LOG-001"]

    def test_execution_mode_filtering_automated_only(
        self, loaded_checklist: TIRWebChecklist
    ) -> None:
        results = loaded_checklist.filter_checks(
            profile=AppProfile.BFSI_FINTECH,
            modes={ExecutionMode.AUTOMATED},
        )
        ids = [chk.id for _, chk in results]

        # WEB-IAM-001 is hybrid, so only automated checks remain
        assert ids == ["WEB-CRY-001", "WEB-LOG-001"]