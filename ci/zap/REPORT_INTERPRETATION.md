# DAST Report Interpretation & Vulnerability Triage

This document establishes the triage methodology and vulnerability assessment applied to Dynamic Application Security Testing (DAST) scans conducted via OWASP ZAP against the Savannah Informatics API perimeter.

## Triage & Evaluation Methodology
1. **Coverage Verification.** Inspect the scan's *Sites / URLs* tree against the OpenAPI 3.0 specification. Ensure authenticated crawls traversed all declared endpoints with valid JWT Bearer tokens returning HTTP `200` rather than stopping at `401 Unauthorized` gates.
2. **Risk & Confidence Correlation.** Correlate ZAP *Risk* (High/Medium/Low/Informational) with *Confidence* (High/Medium/Low/False Positive). Prioritize high-confidence medium/high risks on authentication and PHI-processing routes.
3. **Reachability & Blast Radius.** Determine if the flagged route is exposed at the edge, whether it handles patient PHI, and what database grants are bound to the underlying service.
4. **Upstream Compensating Controls.** DAST alerts often evaluate raw backend responses; verify whether edge or gateway policies (e.g., Kong response-transformer security headers, ModSecurity WAF rules) neutralize the threat vector in production.

## DAST Vulnerability Triage Matrix
| Alert Finding | ZAP Risk | Confidence | Technical Assessment | Engineering & Remediation Action |
|---|---|---|---|---|
| SQL Injection on `GET /patients?limit=` | High | Medium | Investigated: Services enforce parameterised SQL queries exclusively via `psycopg` drivers. Scanner triggered false positive due to database timing/error variations. | Validated manually with curl; marked False Positive in ZAP baseline configuration (`api-scan-rules.tsv`). |
| Missing Anti-clickjacking header | Medium | Medium | JSON API with no browser rendering. Not exploitable. | Accept, document in rules file |
| Cache-control not set | Low | High | Kong adds `no-store`; the scan may have hit the service directly. | Verify via gateway path, close |
| Information disclosure: framework version in OpenAPI | Low | High | Real. `/openapi.json` is exposed. | Disable in production; ticket for platform team |
| BOLA/IDOR (manual test, ZAP cannot find these) | n/a | n/a | Alice reads patient 2 created by someone else. Passive scanners do not know your authorisation model. | Add authorisation tests to CI |

## What ZAP will not tell you
Business-logic and authorisation flaws (IDOR, role confusion, price or quota manipulation, workflow skipping). This is exactly where AI-generated code is weakest, which is why the pipeline also includes Semgrep rules and negative authorisation tests (see docs/02, question 6).
