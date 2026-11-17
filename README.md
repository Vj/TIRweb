# TIRweb

**TIRweb** is a standalone, profile-driven Web Application, API, DevSecOps, and Cloud-Native Security Auditing CLI tool. It achieves **1:1 parity with all 99 OWASP WSTG v4.2 test cases** while mapping controls directly to **Indian statutory and regulatory frameworks** (**CERT-In Directions u/s 70B & Technical Guidelines**, **DPDP Act 2023 & DPDP Rules 2025**, **RBI Digital Payment Security Controls**) alongside **global standards** (**OWASP Top 10**, **OWASP API Top 10**, **PCI DSS v4.0**, **ISO 27001:2022**, **SOC 2**).

---

## Rulesets & Coverage

TIRweb ships with two validated YAML rulesets in `rules/`:

1. **`rules/tirweb_checklist_v1.yaml` (42 Consolidated Compliance & WSTG v4.2 Checks):**
   * `TIR-IAM` (`WEB-IAM-001`..`011`): IDOR/BOLA, BFLA, Multi-Tenancy, Auth Hardening, MFA/OAuth2/OIDC/SAML, Session Lifecycle & JWTs, Account Erasure, GraphQL/gRPC, Remember-Me/Recovery, Alternative Channels, and Session Puzzling.
   * `TIR-CRYPTO` (`WEB-CRY-001`..`004`): TLS 1.2/1.3 & HSTS, At-Rest Encryption/Argon2id/KMS, PII Exposure Prevention, and Padding Oracle Resistance.
   * `TIR-INJECT` (`WEB-INJ-001`..`009`): SQL/NoSQLi, XSS (Reflected, Stored, DOM, SVG), OS Command/LDAP/SSTI/CRLF/Email Injection, XXE & Deserialization, Request Smuggling/Prototype Pollution/WebSockets/Cache Poisoning, HPP, SSI/XPath, Memory Safety, and Open Redirect/CSS/Resource Manipulation.
   * `TIR-LOGIC` (`WEB-LOG-001`..`006`): Threat Modeling & Rate Limits, Financial/E-Commerce Tampering & Race Conditions, Workflow/Approval Chains, SSRF & Cloud Metadata Isolation, File Upload Security, and BFSI/Healthcare Sector Controls.
   * `TIR-INFRA` (`WEB-INF-001`..`012`): Security Headers/CORS/HTTP Methods, Build Artifacts & Admin Interfaces, SCA/SBOM/CBOM, SRI & Supply Chain, CI/CD DevSecOps Gates, Tamper-Resistant Logging & NTP Sync, Search Recon/Subdomains, Metafiles & RIA Policies, Source/EXIF Metadata, Architecture/WAF Mapping, Subdomain Takeover, and Path Confusion.
2. **`rules/tirweb_wstg_v42_full.yaml` (99 Granular OWASP WSTG v4.2 Checks):**
   * 1:1 mapping of `WSTG-INFO-01` through `WSTG-APIT-01` generated from `Book1.xlsx` via `convert_wstg_excel.py`.

---

## Native Python HTTPx Probes

TIRweb includes **8 built-in asynchronous probes** (`tirweb/probes.py`) that execute natively on Windows, macOS, Linux, and Docker without external CLI dependencies:

* `httpx_headers`: HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Server`/`X-Powered-By` leak detection.
* `httpx_cors`: Arbitrary `Origin` reflection with `Access-Control-Allow-Credentials: true` and wildcard `*` checks.
* `httpx_idor_diff`: Differential cross-user BOLA/IDOR comparison using primary (`--auth-file`) vs. secondary (`--secondary-auth-file`) sessions.
* `httpx_jwt`: RFC 8725 algorithm/header hygiene (`alg=none`, `HS256` warning, `jku`/`x5u`/`jwk`, `exp`/`aud`/`iss`) and DPDP Rules 2025 PII detection in unencrypted JWS claims.
* `httpx_metafiles`: `/robots.txt` & `/sitemap.xml` path disclosure and `/crossdomain.xml` & `/clientaccesspolicy.xml` wildcard checks.
* `httpx_path_confusion`: Reverse-proxy/WAF path normalization bypass checks (`/admin/..;/`, double slashes, case variations).
* `httpx_open_redirect`: External `Location` reflection across common redirect parameters (`next`, `url`, `redirect`, `redirect_uri`, `returnTo`, `dest`).
* `httpx_graphql`: `/graphql` and `/api/graphql` `__schema` introspection and query batching abuse checks (`WSTG-APIT-01`).

---

## Repository Structure

```text
TIRweb/
├── .github/
│   └── workflows/
│       └── ci.yml           # Automated Ruff, YAML validation, Pytest & Docker smoke CI
├── Dockerfile
├── .dockerignore
├── convert_wstg_excel.py    # OWASP WSTG v4.2 Excel (Book1.xlsx) -> YAML converter
├── pyproject.toml
├── requirements.txt
├── README.md
├── rules/
│   ├── tirweb_checklist_v1.yaml
│   └── tirweb_wstg_v42_full.yaml
├── tirweb/
│   ├── __init__.py
│   ├── models.py            # Pydantic v2 schema, profile filters & AuthContext
│   ├── probes.py            # 8 native async HTTPx security probes
│   ├── dispatcher.py        # Async tool-binding orchestrator
│   ├── reporter.py          # WeasyPrint PDF & interactive HTML compliance generator
│   ├── templates/
│   │   └── audit_report.html
│   └── cli.py               # Typer CLI entrypoint
└── tests/
    ├── conftest.py
    ├── test_models.py
    ├── test_probes.py
    ├── test_new_probes.py
    ├── test_dispatcher.py
    └── test_cli.py

1- Installation & Quick Start

python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .

2 - Validate, Scan & Export Reports

# Validate both YAML rulesets
tirweb validate --checklist rules/tirweb_checklist_v1.yaml
tirweb validate --checklist rules/tirweb_wstg_v42_full.yaml

# Run an authorized assessment against a staging environment
tirweb scan --target https://staging.example.in --checklist rules/tirweb_checklist_v1.yaml --profile bfsi_fintech --out report.json

# Bound total scan duration and native HTTP probe traffic (defaults: 900s / 500 requests)
tirweb scan --target https://staging.example.in --checklist rules/tirweb_checklist_v1.yaml --scan-timeout 900 --max-requests 500 --out report.json

# Convert JSON scan results into an interactive HTML report
tirweb report --input report.json --out report.html --client "Example Organization"
Start-Process .\report.html



# Export interactive HTML report (works natively on Windows, macOS & Linux)
tirweb report --input report.json --out report.html --client "Target Organization"

# Export compliance PDF report (uses WeasyPrint; auto-falls back to .html if GTK3 is absent)
tirweb report --input report.json --out report.pdf --client "Target Organization"


3 - Run Unit Tests
pytest -v

---

### Final End-to-End Verification in PowerShell

Run these commands to generate and open the new interactive compliance report locally:

```powershell
tirweb scan --target https://staging.example.in --checklist rules/tirweb_checklist_v1.yaml --out report.json
tirweb report --input report.json --out report.html --client "Example Organization"
Start-Process .\report.html

> **Scan safety limits:** `--scan-timeout` caps total scan duration (1–7200 seconds), while `--max-requests` caps outbound requests made by native HTTP probes (1–10000). Exhausting the request budget is reported as inconclusive, not as a vulnerability or a clean result. Differential access checks that receive HTTP 200 for both test users are also inconclusive until resource ownership and sharing expectations are manually verified.

> **API and authentication interpretation:** CORS origin reflection (including credentialed reflection) and wildcard ACAO, GraphQL introspection, accepted query batching, JWT header/claim policy concerns, and two-session HTTP parity are review signals—not automatic vulnerabilities. JWT inspection is passive and does not validate signatures or relying-party acceptance. A confirmed JWT finding requires evidence such as sensitive values exposed in a readable token payload; verify API data sensitivity and access policy before escalating review signals.

> **Assessment interpretation:** TIRweb distinguishes confirmed findings from assessment gaps. A check is marked **FAIL** only when an executed check produces affirmative evidence of a weakness. Missing tools, network errors, skipped prerequisites and manual-only controls are reported separately and must not be interpreted as vulnerabilities or as evidence of compliance. Run scans only against systems for which you have explicit authorization.

> **Regulatory scope:** DPDP Rules 2025 have phased commencement. Rule 6's commencement is scheduled 18 months after its Gazette publication on 13 November 2025; until effective, Rule 6 mappings are readiness guidance. RBI mappings are conditional on the assessed entity and activity falling within RBI's applicable regulatory scope. Confirm legal applicability with qualified counsel.
