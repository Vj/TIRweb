# TIRweb

**TIRweb** is a standalone, profile-driven Web Application, API, and Cloud-Native Security Auditing CLI tool. It combines native asynchronous HTTPx security probes, external scanner orchestration (`nuclei`, `testssl.sh`, `trivy`), and guided manual verification playbooks—mapped directly to **Indian statutory/regulatory mandates** (**CERT-In Directions & Technical Guidelines**, **DPDP Act 2023 & DPDP Rules 2025**, **RBI Digital Payment Security Controls**) and **global frameworks** (**OWASP Top 10**, **OWASP API Top 10**, **PCI DSS v4.0**, **ISO 27001:2022**, **SOC 2**).

> **Note:** TIRweb is developed as a completely independent, self-contained tool alongside **TIR** and **TIRiOS**.

---

## Key Capabilities

* **28 Granular Security Controls Across 5 Core Modules:**
  * `TIR-IAM`: Identity, Access Control (IDOR/BOLA, BFLA, Multi-Tenancy), Session Lifecycle, OAuth 2.0/OIDC/SAML, and GraphQL/gRPC API authorization.
  * `TIR-CRYPTO`: TLS 1.2/1.3 & cipher hardening, HSTS, encryption at rest, Argon2/bcrypt password hashing, key management, and PII exposure prevention.
  * `TIR-INJECT`: SQL/NoSQL, XSS (Reflected, Stored, DOM, SVG upload), OS Command/LDAP/SSTI/CRLF/Email Header injection, XXE, Deserialization, Request Smuggling, Prototype Pollution, and WebSockets.
  * `TIR-LOGIC`: Insecure design controls, financial/e-commerce business logic, workflow/approval chains, SSRF & cloud metadata isolation (`169.254.169.254`), file upload security, and regulated sector controls.
  * `TIR-INFRA`: Security headers, CORS validation, build artifact/source map exposure, SCA & SBOM/CBOM hygiene, Subresource Integrity (SRI), DevSecOps CI/CD gates, and statutory audit logging.
* **Domain-Specific Application Profiles:**
  * `core` (25 baseline checks)
  * `bfsi_fintech` (28 checks — adds multi-tenancy, financial race conditions/tampering, transaction signing, and KYC/AML controls)
  * `saas_multitenant` (27 checks — adds tenant isolation and subscription/workflow logic)
  * `healthcare_pii` (27 checks — adds PHI need-to-know and emergency break-glass auditability)
  * `ecommerce` (26 checks — adds cart, coupon, inventory, and payment gateway integrity)
* **Native Async HTTPx Probes:** Built-in, zero-external-dependency probes for security headers (`httpx_headers`), CORS reflection (`httpx_cors`), differential cross-user BOLA/IDOR comparison (`httpx_idor_diff`), and RFC 8725 / DPDP JWT hygiene inspection (`httpx_jwt`).
* **Authenticated Scanning:** Supports repeatable custom headers (`-H`), bearer tokens (`--bearer-token` / `TIRWEB_BEARER_TOKEN`), cookies (`-b`), YAML/JSON session files (`--auth-file`), and secondary user contexts (`--secondary-auth-file`) with automatic secret redaction in reports.
* **Compliance PDF Reporting:** Converts JSON scan outputs into styled A4 compliance reports via **WeasyPrint**.

---

## Repository Structure

```text
TIRweb/
├── Dockerfile
├── .dockerignore
├── pyproject.toml
├── requirements.txt
├── README.md
├── rules/
│   └── tirweb_checklist_v1.yaml
├── tirweb/
│   ├── __init__.py
│   ├── models.py          # Pydantic v2 schema, profile filters & AuthContext
│   ├── probes.py          # Native async HTTPx probes (headers, CORS, IDOR, JWT)
│   ├── dispatcher.py      # Async tool-binding orchestrator
│   ├── reporter.py        # WeasyPrint compliance matrix & PDF generator
│   ├── templates/
│   │   └── audit_report.html
│   └── cli.py             # Typer CLI entrypoint
└── tests/
    ├── conftest.py
    ├── test_models.py
    ├── test_probes.py
    ├── test_dispatcher.py
    └── test_cli.py


Quick Installation
pip install -r requirements.txt

### Installation

Option 1: Docker (Recommended — All Scanners & WeasyPrint Pre-Installed)

docker build -t tirweb:0.1.0 .
docker run --rm tirweb:0.1.0 --help

Option 2: Local Python Environment (Python 3.12+)
Install system dependencies for WeasyPrint (Debian/Ubuntu/WSL2):

sudo apt-get update && sudo apt-get install -y \
  libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
  libgdk-pixbuf-2.0-0 libffi8 shared-mime-info fonts-liberation

Create a virtual environment and install TIRweb:

python -m venv .venv

.\.venv\Scripts\Activate.ps1

source .venv/bin/activate

pip install -r requirements.txt
pip install -e .


(Optional) Ensure external scanners (nuclei, testssl.sh, trivy) are available in your PATH if running full external bindings.
CLI Usage
1. Validate Checklist Schema
Verify YAML syntax, regex check IDs (WEB-XXX-000), uniqueness, and compliance tags:

Bash
tirweb validate --checklist rules/tirweb_checklist_v1.yaml
2. Preview Selected Checks (Dry Run)
Bash
tirweb scan \
  --target [https://staging.example.in](https://staging.example.in) \
  --checklist rules/tirweb_checklist_v1.yaml \
  --profile bfsi_fintech \
  --dry-run
3. Run Authenticated & Differential BOLA/IDOR Scan
Create a session file (auth_user_a.yaml):

YAML
bearer_token: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
headers:
  X-Tenant-ID: "tenant-alpha-01"
cookies:
  session_id: "s3ss10n_t0k3n"
Execute the scan against your staging target:

Bash
tirweb scan \
  --target [https://api.staging.example.in](https://api.staging.example.in) \
  --checklist rules/tirweb_checklist_v1.yaml \
  --profile saas_multitenant \
  --auth-file auth_user_a.yaml \
  --secondary-auth-file auth_user_b.yaml \
  --endpoint "/api/v1/orders/ORD-10492" \
  --endpoint "/api/v1/users/profile/8821" \
  --out reports/saas_audit.json
4. Generate Compliance PDF Report (CERT-In, RBI & DPDP Rules 2025)
Bash
tirweb report \
  --input reports/saas_audit.json \
  --out reports/saas_compliance_report.pdf \
  --client "Acme Technologies India Pvt. Ltd." \
  --auditor "Security Assessment Team"
Running Tests
Bash
pip install -e ".[dev]"
pytest -v

---

### 2. `requirements.txt`

```text
# Core Runtime Dependencies
pydantic>=2.14.0
typer>=0.29.0
pyyaml>=6.0.2
rich>=13.9.0
httpx>=0.28.0
jinja2>=3.1.4
weasyprint>=63.0

# Development & Testing Dependencies
pytest>=8.4.0
pytest-asyncio>=1.5.0
ruff>=0.8.0
mypy>=1.13.0