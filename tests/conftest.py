from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest
import yaml
from tirweb.models import TIRWebChecklist


@pytest.fixture
def sample_checklist_dict() -> dict:
    return {
        "schema_version": "1.0.0",
        "tool_suite": "TIRweb",
        "metadata": {
            "description": "Test TIRweb Checklist",
            "supported_profiles": [
                "core",
                "bfsi_fintech",
                "saas_multitenant",
                "healthcare_pii",
                "ecommerce",
            ],
        },
        "modules": [
            {
                "module_id": "TIR-IAM",
                "name": "Identity & Access",
                "checks": [
                    {
                        "id": "WEB-IAM-001",
                        "title": "IDOR / BOLA Check",
                        "category": "Broken Access Control",
                        "severity": "Critical",
                        "execution_mode": "hybrid",
                        "tool_binding": ["nuclei_bola"],
                        "profiles": ["core", "bfsi_fintech", "saas_multitenant"],
                        "test_procedures": ["Swap User A and User B IDs."],
                        "compliance": {
                            "india": ["DPDP Rules 2025 - Rule 6(1)(b)"],
                            "global": ["OWASP Top 10: A01"],
                        },
                    },
                    {
                        "id": "WEB-IAM-003",
                        "title": "Multi-Tenant Isolation",
                        "category": "Multi-Tenancy",
                        "severity": "Critical",
                        "execution_mode": "manual",
                        "tool_binding": ["manual_proxy"],
                        "profiles": ["saas_multitenant"],
                        "test_procedures": ["Modify tenant_id header across tenants."],
                        "compliance": {
                            "india": ["DPDP Rules 2025 - Rule 6(1)(b)"],
                            "global": ["SOC 2: CC6.1"],
                        },
                    },
                ],
            },
            {
                "module_id": "TIR-CRYPTO",
                "name": "Cryptography",
                "checks": [
                    {
                        "id": "WEB-CRY-001",
                        "title": "TLS 1.2/1.3 & HSTS",
                        "category": "Cryptographic Failures",
                        "severity": "High",
                        "execution_mode": "automated",
                        "tool_binding": ["testssl"],
                        "profiles": ["core", "bfsi_fintech"],
                        "test_procedures": ["Reject weak ciphers and verify HSTS."],
                        "compliance": {
                            "india": ["DPDP Rules 2025 - Rule 6(1)(a)"],
                            "global": ["PCI DSS v4.0: Req. 4.2.1"],
                        },
                    }
                ],
            },
            {
                "module_id": "TIR-LOGIC",
                "name": "Business Logic",
                "checks": [
                    {
                        "id": "WEB-LOG-001",
                        "title": "Payment Race Condition & Tampering",
                        "category": "Business Logic",
                        "severity": "Critical",
                        "execution_mode": "automated",
                        "tool_binding": ["nuclei_ssrf"],
                        "profiles": ["bfsi_fintech", "ecommerce"],
                        "test_procedures": ["Send concurrent wallet debit requests."],
                        "compliance": {
                            "india": ["RBI Digital Payment Security Controls"],
                            "global": ["PCI DSS v4.0: Req. 6.2.4"],
                        },
                    }
                ],
            },
        ],
    }


@pytest.fixture
def checklist_yaml_file(tmp_path: Path, sample_checklist_dict: dict) -> Path:
    file_path = tmp_path / "tirweb_test.yaml"
    file_path.write_text(yaml.safe_dump(sample_checklist_dict), encoding="utf-8")
    return file_path


@pytest.fixture
def loaded_checklist(checklist_yaml_file: Path) -> TIRWebChecklist:
    return TIRWebChecklist.from_yaml(checklist_yaml_file)


@pytest.fixture
def mock_subprocess_factory(monkeypatch: pytest.MonkeyPatch):
    """Factory fixture to mock shutil.which and asyncio.create_subprocess_exec."""

    def _configure(
        which_map: dict[str, str | None],
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        hang: bool = False,
    ) -> AsyncMock:
        monkeypatch.setattr(
            "tirweb.dispatcher.shutil.which",
            lambda binary: which_map.get(binary),
        )

        mock_proc = MagicMock()
        mock_proc.returncode = returncode
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(return_value=returncode)

        if hang:
            async def _hang():
                import asyncio
                await asyncio.sleep(10)
                return stdout, stderr

            mock_proc.communicate = AsyncMock(side_effect=_hang)
        else:
            mock_proc.communicate = AsyncMock(return_value=(stdout, stderr))

        create_mock = AsyncMock(return_value=mock_proc)
        monkeypatch.setattr(
            "tirweb.dispatcher.asyncio.create_subprocess_exec",
            create_mock,
        )
        return create_mock

    return _configure