import json
from pathlib import Path
from typer.testing import CliRunner
from tirweb.cli import app

runner = CliRunner()


class TestCLI:
    def test_validate_command_succeeds(self, checklist_yaml_file: Path) -> None:
        result = runner.invoke(app, ["validate", "-c", str(checklist_yaml_file)])
        assert result.exit_code == 0
        assert "Valid TIRweb Checklist" in result.stdout
        assert "3 modules, 4 checks" in result.stdout

    def test_scan_dry_run_exports_json_report(
        self, checklist_yaml_file: Path, tmp_path: Path
    ) -> None:
        report_file = tmp_path / "out_report.json"
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://staging.fintech.in",
                "--checklist",
                str(checklist_yaml_file),
                "--profile",
                "bfsi_fintech",
                "--dry-run",
                "--out",
                str(report_file),
            ],
        )

        assert result.exit_code == 0
        assert report_file.exists()

        payload = json.loads(report_file.read_text(encoding="utf-8"))
        assert payload["profile"] == "bfsi_fintech"
        assert payload["summary"]["total"] == 3
        assert {r["check_id"] for r in payload["results"]} == {
            "WEB-IAM-001",
            "WEB-CRY-001",
            "WEB-LOG-001",
        }

    def test_scan_with_mocked_tools_and_automated_only(
        self,
        checklist_yaml_file: Path,
        tmp_path: Path,
        mock_subprocess_factory,
    ) -> None:
        mock_subprocess_factory(
            which_map={
                "testssl.sh": "/usr/bin/testssl.sh",
                "nuclei": "/usr/bin/nuclei",
            },
            returncode=0,
            stdout=b"",
        )
        report_file = tmp_path / "auto_report.json"

        result = runner.invoke(
            app,
            [
                "scan",
                "-t",
                "https://staging.fintech.in",
                "-c",
                str(checklist_yaml_file),
                "-p",
                "bfsi_fintech",
                "--automated-only",
                "-o",
                str(report_file),
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(report_file.read_text(encoding="utf-8"))
        assert payload["summary"]["total"] == 2
        assert payload["summary"]["pass"] == 2
        assert payload["summary"]["fail"] == 0