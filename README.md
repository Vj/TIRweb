# TIRweb

**TIRweb** is a standalone, profile-driven Web Application, API, DevSecOps, and Cloud-Native Security Auditing CLI tool. It achieves **1:1 parity with all 99 OWASP WSTG v4.2 test cases** while mapping controls directly to **Indian statutory and regulatory frameworks** (**CERT-In Directions u/s 70B & Technical Guidelines**, **DPDP Act 2023 & DPDP Rules 2025**, **RBI Digital Payment Security Controls**) alongside **global standards** (**OWASP Top 10**, **OWASP API Top 10**, **PCI DSS v4.0**, **ISO 27001:2022**, **SOC 2**)[cite: 5].
---

## Key Capabilities

* **Atomic Findings & Coverage Roll-Up:** Splits multi-defect responses into individual findings with independent severities, CWE/CVE tags, and remediations. Displays per-check binding coverage (`1 of 4 bindings executed`) and top-of-report conclusiveness (`X of Y conclusively assessed`).
* **19 Native Python HTTPx Probes:** Executes TLS/HTTPS validation, atomic security header checks, cookie attribute checks (`Secure`, `HttpOnly`, `SameSite`), HTTP method checks (`TRACE`, `PUT`), directory listing/admin console discovery, stack-trace error probes, HTTP login/autocomplete checks, authenticated `Cache-Control` checks, anti-CSRF form checks, mixed content/SRI checks, version-to-CVE fingerprinting, canary XSS/SQLi probes, CORS reflection, differential IDOR/BOLA, JWT hygiene, metafiles/RIA policies, baseline-aware path confusion, open redirects, and GraphQL introspection/batching checks without external CLI dependencies.
* **Consolidated Tooling Gaps & Environment Preflight (`tirweb doctor`):** Validates runtime and external CLI scanner availability (`nuclei`, `trivy`, `testssl.sh`) and consolidates missing optional scanners into a single report section rather than inflating failure counts.
* **Interactive Manual Verification Playbooks:** Generates structured step-by-step tester worksheets (Tester Name, Verdict, Observation Notes) for manual and hybrid controls.

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

## Native Python HTTPx Probes (24 Built-in Bindings)

TIRweb includes **24 built-in asynchronous probes** (`tirweb/probes.py` & `tirweb/dispatcher.py`) that run natively on Windows, macOS, Linux, and Docker without external CLI dependencies:

* **Transport & Cryptography:** `httpx_tls` (HTTPS enforcement, TLS 1.2/1.3, active weak-cipher handshake probe, HSTS), `httpx_jwt` (RFC 8725 alg/header checks + DPDP PII claim inspection), `httpx_cache` (`Cache-Control: no-store`), `httpx_client_assets` (mixed content, SRI hashes, Web Storage `localStorage`/`sessionStorage` token leaks).
* **Identity & Access Control:** `httpx_idor_diff` (dual-session BOLA/IDOR comparison), `httpx_api_auth` (unauthenticated & malformed Bearer token enforcement), `httpx_auth_surface` (cleartext login & autocomplete checks), `httpx_cookies` (`Secure`, `HttpOnly`, `SameSite`), `httpx_csrf` (anti-CSRF token + `SameSite` correlation), `httpx_graphql` (`__schema` introspection & query batching).
* **Infrastructure, Recon & Configuration:** `httpx_headers` (5 security headers + banner disclosure), `httpx_cors` (credentialed origin reflection), `httpx_methods` (`OPTIONS` / `TRACE`), `httpx_discovery` (directory indexing & default consoles), `httpx_exposed_artifacts` (`.svn`, `.hg`, `.sql`, `.zip`, `.bak`, `.map`, `actuator`), `httpx_metafiles` (`robots.txt`, `sitemap.xml`, RIA policies), `httpx_source_metadata` (HTML/JS secrets & TODO comments), `httpx_arch_and_dns` (DNS resolution, WAF/CDN fingerprinting, direct-IP origin bypass, shadow subdomains), `httpx_path_confusion` (`/admin/..;/` ACL normalization), `httpx_cve_fingerprint` (legacy server banner CVE mapping), `httpx_errors` (stack trace disclosures).
* **Injection & Native Fallbacks:** `httpx_canary_inj` (reflected XSS canary, single-quote SQLi, `{inj}` templates), `httpx_hpp_consistency` (HTTP Parameter Pollution precedence), plus native async fallbacks for `nuclei_bfla`, `nuclei_auth` (differential default-credential baseline), `nuclei_injection` (SSTI `{{7*7}}` & command echo), and `trivy_sca` (`--source-path` secret & weak-hash scanner).

---

## Orchestration Pipeline (`tirweb/orchestrator.py`)

1. **Phase-0 One-Hop Surface Discovery:** Harvests relative routes from `/robots.txt`, `/sitemap.xml`, and landing HTML `<a href>` / `<form action>` tags before parallel check execution.
2. **Concurrent Tool Execution:** Runs all selected checks via `ToolDispatcher` with bounded retry/backoff (`with_retry`) and request budget enforcement (`--max-requests`).
3. **Privilege-Tier Differential Enrichment:** Compares HTTP access outcomes across `unauthenticated`, `low_priv` (`--secondary-auth-file`), and `high_priv` (`--auth-file`) tiers on access-control checks (`WEB-IAM-001`, `WEB-IAM-002`, `WEB-IAM-008`).
4. **Mid-Scan Session Expiry Detection:** Flags late `401` responses if an earlier authenticated probe succeeded.

---

## Repository Structure

```text
TIRweb/
├── .github/workflows/ci.yml   # Automated Ruff, YAML validation, Pytest & Docker smoke CI
├── Dockerfile                 # Full container image bundling Python, Nuclei, Trivy & testssl.sh
├── convert_wstg_excel.py      # OWASP WSTG v4.2 Excel (Book1.xlsx) -> YAML converter
├── pyproject.toml
├── requirements.txt
├── README.md
├── rules/
│   ├── tirweb_checklist_v1.yaml
│   └── tirweb_wstg_v42_full.yaml
├── tirweb/
│   ├── __init__.py
│   ├── models.py              # Pydantic v2 schema, profile filters & AuthContext
│   ├── probes.py              # 24 native async HTTPx security probes & fallbacks
│   ├── dispatcher.py          # Async tool-binding adapter & tooling-gap aggregator
│   ├── orchestrator.py        # Phase-0 discovery, privilege-tier diff & session monitor
│   ├── reporter.py            # Self-contained HTML & WeasyPrint PDF compliance generator
│   ├── templates/
│   │   └── audit_report.html
│   └── cli.py                 # Typer CLI entrypoint (doctor, validate, scan, report)
└── tests/                     # 53 unit, recorded-fixture, orchestrator & golden snapshot tests
---

## Quick Start

```powershell
# 1. Create virtual environment and install
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Windows (via WinGet):
winget install --id ProjectDiscovery.Nuclei -e
winget install --id AquaSecurity.Trivy -e
nuclei -update-templates

# Linux / WSL2 (Debian/Ubuntu) — includes testssl.sh:
sudo apt update && sudo apt install -y curl unzip git openssl dnsutils bsdmainutils
sudo git clone --depth 1 [https://github.com/drwetter/testssl.sh.git](https://github.com/drwetter/testssl.sh.git) /opt/testssl.sh
sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

#Docker (All external scanners pre-installed):
docker build -t tirweb:v2 .
docker run --rm -v "${PWD}:/workspace" tirweb:v2 doctor


# 2. Check environment and scanner readiness
tirweb doctor

# 3. Validate both YAML rulesets (42 compliance checks & 99 WSTG v4.2 checks)
tirweb validate --checklist rules/tirweb_checklist_v1.yaml
tirweb validate --checklist rules/tirweb_wstg_v42_full.yaml

# 4. Run a scan and export a single self-contained HTML compliance report
tirweb scan `
  --target [http://demo.testfire.net](http://demo.testfire.net) `
  --checklist rules/tirweb_checklist_v1.yaml `
  --client "Altoro Mutual Demo" `
  --scan-timeout 900 `
  --max-requests 500 `
  --out testfire_report.html

Start-Process .\testfire_report.html
-------------------------
# 5. Run an authenticated privilege-tier & IDOR differential scan (BFSI profile)
tirweb scan `
  --target [https://staging.example.in](https://staging.example.in) `
  --checklist rules/tirweb_checklist_v1.yaml `
  --client "Target Organization" `
  --profile bfsi_fintech `
  --auth-file auth_user_a.yaml `
  --secondary-auth-file auth_user_b.yaml `
  --endpoint "/api/v1/orders/ORD-101" `
  --out bfsi_report.html


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
tirweb scan --target https://www.testfire.net/ --checklist rules/tirweb_checklist_v1.yaml --out report18.html
tirweb report --input report.json --out report.html --client "Example Organization"
Start-Process .\report.html

> **Scan safety limits:** `--scan-timeout` caps total scan duration (1–7200 seconds), while `--max-requests` caps outbound requests made by native HTTP probes (1–10000). Exhausting the request budget is reported as inconclusive, not as a vulnerability or a clean result. Differential access checks that receive HTTP 200 for both test users are also inconclusive until resource ownership and sharing expectations are manually verified.

> **API and authentication interpretation:** CORS origin reflection (including credentialed reflection) and wildcard ACAO, GraphQL introspection, accepted query batching, JWT header/claim policy concerns, and two-session HTTP parity are review signals—not automatic vulnerabilities. JWT inspection is passive and does not validate signatures or relying-party acceptance. A confirmed JWT finding requires evidence such as sensitive values exposed in a readable token payload; verify API data sensitivity and access policy before escalating review signals.

> **Endpoint-level access evidence:** When both `--auth-file` and `--secondary-auth-file` are configured, the differential access probe records each in-scope endpoint's HTTP status and a neutral outcome (success, authentication-required, forbidden, not-found-or-hidden, rate-limited, redirect-not-followed, server-error, or other). Credential types are summarized without printing token, cookie, or header values. A primary-session success paired with a secondary-session denial is recorded as an observed access restriction; dual-success, inverse access differences, 404s, rate limits, redirects, transport failures, and other ambiguous outcomes require review. HTTP status alone never confirms BOLA/IDOR, and redirects are not followed.

> **Assessment interpretation:** TIRweb distinguishes confirmed findings from assessment gaps. A check is marked **FAIL** only when an executed check produces affirmative evidence of a weakness. Missing tools, network errors, skipped prerequisites and manual-only controls are reported separately and must not be interpreted as vulnerabilities or as evidence of compliance. Run scans only against systems for which you have explicit authorization.

> **Regulatory scope:** DPDP Rules 2025 have phased commencement. Rule 6's commencement is scheduled 18 months after its Gazette publication on 13 November 2025; until effective, Rule 6 mappings are readiness guidance. RBI mappings are conditional on the assessed entity and activity falling within RBI's applicable regulatory scope. Confirm legal applicability with qualified counsel.
