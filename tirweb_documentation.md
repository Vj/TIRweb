# TIRweb

**TIRweb** is a standalone, profile-driven Web Application, API, DevSecOps, and Cloud-Native Security Auditing CLI tool. It achieves **1:1 parity with all 99 OWASP WSTG v4.2 test cases** while mapping controls directly to **Indian statutory and regulatory frameworks** (**CERT-In Directions u/s 70B & Technical Guidelines**, **DPDP Act 2023 & DPDP Rules 2025**, **RBI Digital Payment Security Controls**) alongside **global standards** (**OWASP Top 10**, **OWASP API Top 10**, **PCI DSS v4.0**, **ISO 27001:2022**, **SOC 2**).

---

## Key Capabilities (v2.0.0)

* **Atomic Findings & Coverage Roll-Up:** Splits multi-defect responses into individual `ProbeFinding` items with independent severities (`Critical`, `High`, `Medium`, `Low`, `Info`), CWE/CVE identifiers, confidence levels (`CONFIRMED` / `SIGNAL`), evidence, and remediation guidance. Displays per-check binding ratios (`1 of 4 bindings executed`) and top-of-report conclusiveness (`X of Y conclusively assessed`).
* **23+ Native Python HTTPx Probes:** Executes full-spectrum Web & API security checks out of the box without external binary dependencies:
  * **Transport & Cryptography:** `httpx_tls` (cleartext HTTP detection, HTTP→HTTPS redirect, TLS 1.0/1.1 detection, HSTS validation)
  * **Headers, Methods & CORS:** `httpx_headers` (atomic CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy & version banner leaks), `httpx_methods` (`TRACE`, `PUT`, `DELETE`, WebDAV), `httpx_cors` (credentialed/uncredentialed origin reflection)
  * **Session & Authentication:** `httpx_cookies` (`Secure`, `HttpOnly`, `SameSite`), `httpx_auth_surface` (cleartext login forms & `autocomplete`), `httpx_cache` (`Cache-Control: no-store`), `httpx_csrf` (anti-CSRF tokens correlated with `SameSite` cookies), `httpx_jwt` (RFC 8725 & DPDP PII-in-JWS hygiene), `nuclei_auth` differential login baseline fallback (`--allow-default-creds`)
  * **API & Access Control:** `httpx_idor_diff` (dual-session differential IDOR/BOLA), `httpx_api_auth` (unauthenticated & malformed Bearer JWT rejection), `httpx_graphql` (`__schema` introspection & query batching), `httpx_path_confusion` (soft-404-aware URL normalization bypass), `nuclei_bfla` soft-404-aware admin panel fallback
  * **Attack Surface, Supply Chain & Injection:** `httpx_discovery`, `httpx_exposed_artifacts` (`.git`, `.env`, `.svn`, SQL dumps, source maps, Actuators), `httpx_source_metadata` (HTML/JS secrets & TODO comments), `httpx_client_assets` (mixed content & missing external script SRI), `httpx_cve_fingerprint` (EOL/vulnerable banner-to-CVE mapping), `httpx_arch_and_dns` (WAF/CDN fingerprinting, direct-IP origin bypass, shadow subdomains), `httpx_errors` (stack traces), `httpx_canary_inj` (reflection XSS & error-based SQLi canaries), `httpx_hpp_consistency` (duplicate query parameter precedence), and `httpx_open_redirect`
* **Multi-Stage Orchestration Pipeline (`tirweb/orchestrator.py`):** Performs Phase-0 one-hop surface discovery (`/robots.txt`, `/sitemap.xml`, landing `<a href>` and `<form action>` harvesting), bounded exponential-backoff retries, cross-tier privilege diffing (`unauthenticated` vs. `low_priv` vs. `high_priv`), and mid-scan session-expiry detection.
* **Consolidated Tooling Gaps & Environment Preflight (`tirweb doctor`):** Checks runtime and external CLI scanner availability (`nuclei`, `trivy`, `testssl.sh`) and consolidates missing optional scanners into a single **Tooling Gaps** report table instead of inflating failure counts.
* **Interactive Manual Verification Playbooks:** Generates structured step-by-step tester worksheets (Tester Name, Verdict, Observation Notes) for manual and hybrid controls.

---

## Installation & Quick Start

```powershell
# 1. Create virtual environment and install
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .

# 2. Verify environment and external tool readiness
tirweb doctor

# 3. Validate both YAML rulesets (42 compliance controls & 99 WSTG v4.2 controls)
tirweb validate --checklist rules/tirweb_checklist_v1.yaml
tirweb validate --checklist rules/tirweb_wstg_v42_full.yaml

# 4. Run an unauthenticated scan and export a standalone HTML compliance report
tirweb scan `
  --target http://demo.testfire.net `
  --checklist rules/tirweb_checklist_v1.yaml `
  --client "Altoro Mutual Demo" `
  --scan-timeout 900 `
  --max-requests 500 `
  --out testfire_report.html

Start-Process .\testfire_report.html
```

---

## Authenticated & Differential IDOR / Privilege-Tier Scans

Provide primary and secondary session contexts via `--auth-file` and `--secondary-auth-file` (JSON or YAML) to unlock `httpx_idor_diff`, `httpx_cache`, `httpx_jwt`, `httpx_api_auth`, and cross-tier privilege diffing:

```yaml
# auth_admin.yaml
headers:
  X-Tenant-ID: "tenant-alpha"
bearer_token: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
cookies:
  session_id: "primary-session-token"
```

```powershell
tirweb scan `
  --target https://staging.example.in `
  --checklist rules/tirweb_checklist_v1.yaml `
  --client "Acme Fintech Pvt Ltd" `
  --profile bfsi_fintech `
  --auth-file auth_admin.yaml `
  --secondary-auth-file auth_standard_user.yaml `
  --endpoint /api/v1/accounts/1001 `
  --endpoint /api/v1/admin/users `
  --out bfsi_audit_report.html
```

---

## Docker Usage (All External Scanners Pre-Installed)

The official `Dockerfile` ships with Python 3.12, `nuclei` + templates, `trivy`, `testssl.sh`, and WeasyPrint pre-installed:

```powershell
docker build -t tirweb:2.0.0 .
docker run --rm tirweb:2.0.0 doctor
docker run --rm -v "${PWD}:/out" tirweb:2.0.0 scan `
  --target https://staging.example.in `
  --checklist rules/tirweb_checklist_v1.yaml `
  --client "Acme Fintech Pvt Ltd" `
  --out /out/audit_report.html
```

---

## Running Unit Tests & Precision/Recall Benchmarks

```powershell
# Run offline unit tests, recorded HTTP fixtures, orchestrator tests & golden HTML snapshots
pytest -v

# Run local vulnerable-app benchmark suite (OWASP Juice Shop, DVWA, VAmPI)
docker compose -f benchmarks/docker-compose.benchmark.yml up -d --wait juice-shop dvwa vampi
python benchmarks/evaluate.py --target-filter "_local" --min-precision 0.90 --min-recall 0.90
docker compose -f benchmarks/docker-compose.benchmark.yml down -v
```