"""
Convert OWASP WSTG v4.2 Excel Tracker (Book1.xlsx) into a TIRweb-compatible YAML checklist
with Indian statutory/regulatory compliance tags (CERT-In, DPDP Rules 2025, RBI).

Usage:
    python scripts/convert_wstg_excel.py --excel Book1.xlsx --out rules/tirweb_wstg_v42.yaml
"""

import argparse
import re
from pathlib import Path
import pandas as pd
import yaml


CATEGORY_MODULE_MAP: dict[str, tuple[str, str]] = {
    "Information Gathering": ("TIR-INFRA", "INF"),
    "Config & Deploy Management": ("TIR-INFRA", "INF"),
    "Identity Management": ("TIR-IAM", "IAM"),
    "Authentication Testing": ("TIR-IAM", "IAM"),
    "Authorization Testing": ("TIR-IAM", "IAM"),
    "Session Management": ("TIR-IAM", "IAM"),
    "Input Validation Testing": ("TIR-INJECT", "INJ"),
    "Error Handling": ("TIR-LOGIC", "LOG"),
    "Cryptography": ("TIR-CRYPTO", "CRY"),
    "Business Logic Testing": ("TIR-LOGIC", "LOG"),
    "Client-Side Testing": ("TIR-INJECT", "INJ"),
    "API Testing": ("TIR-IAM", "IAM"),
}

MODULE_NAMES: dict[str, str] = {
    "TIR-IAM": "Identity, Access Control & Session Engine",
    "TIR-CRYPTO": "Cryptography, Transport & Data Protection Engine",
    "TIR-INJECT": "Injection, Protocol & Client-Side Parser Engine",
    "TIR-LOGIC": "Business Logic, Error Handling & File Security Engine",
    "TIR-INFRA": "Infrastructure, Reconnaissance, Deployment & Telemetry Engine",
}

CATEGORY_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    "Information Gathering": {
        "india": [
            "CERT-In CISG-2026-02 (Attack Surface & Public Exposure Reduction)",
            "CERT-In CISG-2024-01 (Information Leakage & Recon Hardening)",
        ],
        "global": [
            "OWASP Top 10: A05 Security Misconfiguration",
            "ISO 27001:2022: A.8.9, A.8.26",
            "SOC 2: CC6.6",
        ],
    },
    "Config & Deploy Management": {
        "india": [
            "CERT-In CISG-2024-01 (Secure Server & Deployment Hardening)",
            "CERT-In CISG-2026-02 (Cloud & Infrastructure Exposure Hardening)",
            "DPDP Rules 2025 - Rule 6(1)(b) (Infrastructure Access Safeguards)",
        ],
        "global": [
            "OWASP Top 10: A05 Security Misconfiguration",
            "PCI DSS v4.0: Req. 2.2, 6.4.1",
            "ISO 27001:2022: A.8.9, A.8.31",
            "SOC 2: CC6.6, CC7.1",
        ],
    },
    "Identity Management": {
        "india": [
            "DPDP Rules 2025 - Rule 6(1)(b) (Identity & Least-Privilege Access Control)",
            "CERT-In CISG-2024-01 (Identity & Provisioning Governance)",
        ],
        "global": [
            "OWASP Top 10: A01 Broken Access Control / A07 Auth Failures",
            "PCI DSS v4.0: Req. 7.2, 8.2",
            "ISO 27001:2022: A.5.15, A.8.2, A.8.3",
            "SOC 2: CC6.1, CC6.2",
        ],
    },
    "Authentication Testing": {
        "india": [
            "RBI Digital Payment Security Controls (Mandatory 2FA & Credential Hygiene)",
            "CERT-In CISG-2024-01 (Authentication Hardening)",
            "DPDP Rules 2025 - Rule 6(1)(b) (Authentication Safeguards)",
        ],
        "global": [
            "OWASP Top 10: A07 Identification and Authentication Failures",
            "PCI DSS v4.0: Req. 8.3, 8.4",
            "ISO 27001:2022: A.8.5",
            "SOC 2: CC6.1",
        ],
    },
    "Authorization Testing": {
        "india": [
            "DPDP Rules 2025 - Rule 6(1)(b) (Unauthorized Access Prevention)",
            "RBI Digital Payment Security Controls (Customer Data Isolation & RBAC)",
            "CERT-In CISG-2024-01 (Server-Side Authorization)",
        ],
        "global": [
            "OWASP Top 10: A01 Broken Access Control",
            "OWASP API Top 10: API1 BOLA / API5 BFLA",
            "PCI DSS v4.0: Req. 6.2.4, 7.2",
            "ISO 27001:2022: A.8.3, A.8.26",
            "SOC 2: CC6.1, CC6.3",
        ],
    },
    "Session Management": {
        "india": [
            "CERT-In CISG-2024-01 (Session & Token Lifecycle Security)",
            "RBI Digital Payment Security Controls (Session Timeout & Binding)",
            "DPDP Rules 2025 - Rule 6(1)(a) & (b) (Session Token Protection)",
        ],
        "global": [
            "OWASP Top 10: A07 Identification and Authentication Failures",
            "PCI DSS v4.0: Req. 8.2.8",
            "ISO 27001:2022: A.8.5",
            "SOC 2: CC6.1",
        ],
    },
    "Input Validation Testing": {
        "india": [
            "CERT-In CISG-2024-01 (Input Validation & Sanitization)",
            "CERT-In CISG-2026-02 (Defending Against Automated & AI-Assisted Exploitation)",
        ],
        "global": [
            "OWASP Top 10: A03 Injection / A10 SSRF",
            "PCI DSS v4.0: Req. 6.2.4",
            "ISO 27001:2022: A.8.25, A.8.28",
            "SOC 2: CC7.1",
        ],
    },
    "Error Handling": {
        "india": [
            "CERT-In CISG-2024-01 (Safe Error Handling & Stack Trace Suppression)",
            "CERT-In CISG-2026-02 (Preventing Information Disclosure)",
        ],
        "global": [
            "OWASP Top 10: A04 Insecure Design / A05 Security Misconfiguration",
            "PCI DSS v4.0: Req. 6.2.4",
            "ISO 27001:2022: A.8.26",
            "SOC 2: CC7.1",
        ],
    },
    "Cryptography": {
        "india": [
            "DPDP Rules 2025 - Rule 6(1)(a) (Encryption, Obfuscation & Masking)",
            "CERT-In CISG-2024-02 (CBOM Cryptographic Inventory)",
            "RBI Digital Payment Security Controls (End-to-End Encryption)",
        ],
        "global": [
            "OWASP Top 10: A02 Cryptographic Failures",
            "PCI DSS v4.0: Req. 3.5, 4.2.1",
            "ISO 27001:2022: A.8.24",
            "SOC 2: CC6.1, CC6.7",
        ],
    },
    "Business Logic Testing": {
        "india": [
            "RBI Digital Payment Security Controls (Transaction Integrity & Anti-Tampering)",
            "CERT-In CISG-2024-01 (Secure Business Logic & File Upload Controls)",
        ],
        "global": [
            "OWASP Top 10: A04 Insecure Design",
            "PCI DSS v4.0: Req. 6.2.4",
            "ISO 27001:2022: A.8.26",
            "SOC 2: PI1.1",
        ],
    },
    "Client-Side Testing": {
        "india": [
            "CERT-In CISG-2024-01 (Browser & Client-Side Security Controls)",
            "DPDP Rules 2025 - Rule 6(1)(a) (Preventing Client-Side PII Exposure)",
        ],
        "global": [
            "OWASP Top 10: A03 Injection / A05 Security Misconfiguration",
            "PCI DSS v4.0: Req. 6.2.4, 6.4.3",
            "ISO 27001:2022: A.8.26, A.8.28",
            "SOC 2: CC7.1",
        ],
    },
    "API Testing": {
        "india": [
            "CERT-In CISG-2024-01 (API & GraphQL Security Hardening)",
            "RBI Digital Payment Security Controls (API Gateway & Rate Limit Controls)",
        ],
        "global": [
            "OWASP API Top 10: API1 BOLA, API3 BOPLA, API4 Resource Consumption",
            "PCI DSS v4.0: Req. 6.2.4",
            "ISO 27001:2022: A.8.26",
            "SOC 2: CC6.1",
        ],
    },
}


def infer_bindings_and_mode(wstg_id: str, tools_text: str) -> tuple[str, list[str]]:
    t = (tools_text or "").lower()
    bindings: list[str] = []

    if wstg_id == "WSTG-SESS-10":
        bindings.append("httpx_jwt")
    if wstg_id in {"WSTG-CONF-07", "WSTG-CONF-12", "WSTG-SESS-02", "WSTG-CLNT-09", "WSTG-INFO-02", "WSTG-INFO-08"}:
        bindings.append("httpx_headers")
    if wstg_id == "WSTG-CLNT-07":
        bindings.append("httpx_cors")
    if wstg_id == "WSTG-ATHZ-04":
        bindings.append("httpx_idor_diff")
    if "testssl" in t or "sslyze" in t:
        bindings.append("testssl")
    if "nuclei" in t or wstg_id in {"WSTG-CONF-03", "WSTG-CONF-04", "WSTG-CONF-05", "WSTG-INFO-03"}:
        bindings.append("nuclei_exposures")
    if wstg_id in {"WSTG-INPV-01", "WSTG-INPV-04", "WSTG-INPV-06", "WSTG-INPV-10", "WSTG-INPV-11"}:
        bindings.append("nuclei_injection")
    if wstg_id == "WSTG-INPV-17":
        bindings.append("nuclei_ssrf")
    if wstg_id in {"WSTG-ATHN-02", "WSTG-ATHN-03", "WSTG-ATHN-04"}:
        bindings.append("nuclei_auth")
    if wstg_id in {"WSTG-ATHZ-02", "WSTG-ATHZ-03"}:
        bindings.append("nuclei_bfla")

    bindings = list(dict.fromkeys(bindings))
    if not bindings:
        return "manual", ["manual_proxy"]
    if wstg_id in {"WSTG-CONF-07", "WSTG-CONF-12", "WSTG-CRYP-01", "WSTG-CLNT-07", "WSTG-CLNT-09"}:
        return "automated", bindings
    return "hybrid", bindings


def infer_profiles(wstg_id: str) -> list[str]:
    if wstg_id in {"WSTG-BUSL-01", "WSTG-BUSL-03", "WSTG-BUSL-04", "WSTG-BUSL-05"}:
        return ["bfsi_fintech", "ecommerce", "saas_multitenant"]
    if wstg_id in {"WSTG-IDNT-01", "WSTG-IDNT-03"}:
        return ["core", "bfsi_fintech", "saas_multitenant", "healthcare_pii"]
    return ["core", "bfsi_fintech", "saas_multitenant", "healthcare_pii", "ecommerce"]


def parse_steps(objective: str, step_text: str, expected_text: str, tools_text: str) -> list[str]:
    procedures = [f"Objective: {objective}"]
    parts = re.split(r"\s*\d+\)\s*", step_text.strip())
    procedures.extend(p.strip().rstrip(".") + "." for p in parts if p.strip())
    if expected_text.strip():
        procedures.append(f"Expected Secure Result: {expected_text.strip()}")
    cmds = [line.strip() for line in tools_text.splitlines() if line.strip()]
    if cmds:
        procedures.append("Reference Commands: " + " | ".join(cmds))
    return procedures


def convert_excel_to_yaml(excel_path: Path, output_yaml: Path, sheet_name: str = "Tracker") -> int:
    df = pd.read_excel(excel_path, sheet_name=sheet_name, header=1)
    df = df.dropna(subset=["WSTG ID"]).reset_index(drop=True)

    counters = {"IAM": 0, "CRY": 0, "INJ": 0, "LOG": 0, "INF": 0}
    modules_map: dict[str, list[dict]] = {m: [] for m in MODULE_NAMES}

    for _, row in df.iterrows():
        wstg_id = str(row["WSTG ID"]).strip()
        cat = str(row["Category"]).strip()
        name = str(row["Test Case / Name"]).strip()
        objective = str(row["Objective"]).strip()
        steps_raw = str(row["Step-by-Step Process"]).strip()
        tools_raw = str(row["Tools / Commands"]).strip()
        expected_raw = str(row["Expected Secure Result"]).strip()
        severity = str(row["Severity"]).strip().capitalize()
        if severity not in {"Critical", "High", "Medium", "Low", "Info"}:
            severity = "Medium"

        mod_id, prefix = CATEGORY_MODULE_MAP[cat]
        counters[prefix] += 1
        check_id = f"WEB-{prefix}-{counters[prefix]:03d}"

        exec_mode, bindings = infer_bindings_and_mode(wstg_id, tools_raw)
        comp = CATEGORY_COMPLIANCE_MAP[cat]

        modules_map[mod_id].append(
            {
                "id": check_id,
                "title": f"[{wstg_id}] {name}",
                "category": cat,
                "severity": severity,
                "execution_mode": exec_mode,
                "tool_binding": bindings,
                "profiles": infer_profiles(wstg_id),
                "test_procedures": parse_steps(objective, steps_raw, expected_raw, tools_raw),
                "compliance": {
                    "india": list(comp["india"]) + [f"OWASP WSTG v4.2: {wstg_id}"],
                    "global": [f"OWASP WSTG v4.2: {wstg_id}"] + list(comp["global"]),
                },
            }
        )

    document = {
        "schema_version": "1.0.0",
        "tool_suite": "TIRweb",
        "metadata": {
            "description": "TIRweb Full OWASP WSTG v4.2 (99 Checks) Ruleset Converted from Excel with Indian & Global Regulatory Mappings",
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
                "module_id": mod_id,
                "name": MODULE_NAMES[mod_id],
                "checks": checks,
            }
            for mod_id, checks in modules_map.items()
            if checks
        ],
    }

    output_yaml.parent.mkdir(parents=True, exist_ok=True)
    output_yaml.write_text(
        yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    return len(df)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Book1.xlsx WSTG tracker to TIRweb YAML.")
    parser.add_argument("--excel", "-e", type=Path, default=Path("Book1.xlsx"), help="Input Excel file")
    parser.add_argument("--out", "-o", type=Path, default=Path("rules/tirweb_wstg_v42.yaml"), help="Output YAML path")
    args = parser.parse_args()

    count = convert_excel_to_yaml(args.excel, args.out)
    print(f"Converted {count} WSTG v4.2 test cases into {args.out}")
```[cite: 1]

### Running It Locally in PowerShell

1. Ensure `pandas` and `openpyxl` are installed in your `.venv`:
   ```powershell
   pip install pandas openpyxl