# Section 1B: SIEM, DAST, SAST and a secure AI-assisted SDLC

Everything below is wired together in `.github/workflows/security.yml`, with the supporting files under `ci/`, `siem/` and `.pre-commit-config.yaml`.

## 1. Deployment plan: tools and integration points

| Capability   | Tool                                                       | Why this one                                                                                                                                   | Where it plugs in                                                                                          |
| ------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| SIEM and XDR | Wazuh (open source)                                        | Agents, file integrity monitoring, vulnerability detection, log analysis, and compliance tags (HIPAA, GDPR, PCI) in one product.               | Agents on hosts, syslog from the WAF, gateway, Keycloak, proxy, cloud audit logs via S3 or Event Hub pulls |
| SAST         | Semgrep (OSS) plus custom rules                            | Fast enough to run on every PR, rules are readable YAML so developers can contribute. CodeQL is a strong second option where licensing allows. | PR check, SARIF upload to the code-scanning tab                                                            |
| SCA          | pip-audit and OSV-Scanner, plus the custom dependency gate | Known-vulnerability data from OSV plus a check for packages that should not exist                                                              | PR check, nightly full audit                                                                               |
| Secrets      | Gitleaks                                                   | Fast, supports custom rules, works as hook and CI job                                                                                          | Pre-commit, PR check, full-history scan weekly                                                             |
| DAST         | OWASP ZAP                                                  | Mature OpenAPI import, authenticated scanning, scriptable                                                                                      | PR (passive), nightly (time-boxed active) against an ephemeral environment                                 |
| Containers   | Trivy                                                      | Image, filesystem and IaC scanning in one binary                                                                                               | Build stage                                                                                                |

**Phasing.** Weeks 1 to 2: log sources into Wazuh and the first ten detections. Weeks 2 to 4: Gitleaks and Semgrep in monitor mode (comment on PRs but do not fail), baseline existing findings so that only new ones block. Weeks 4 to 8: turn blocking on for High severity, add ZAP passive scans, then nightly active scans. Quarter two: tune, add cloud audit sources, formalise reporting.

**Sizing the SIEM.** Wazuh's single-node Docker deployment is fine for a lab and for a small estate. For production I would run a three-node indexer cluster and a manager pair, size storage from measured daily ingest times retention (90 days hot, 12 months cold for audit), and keep the SIEM in its own account with write-once log forwarding so an intruder cannot erase evidence.

## 2. Pre-commit secret scanning and AI-hallucinated dependency detection

### Credentials pasted into Copilot

A pre-commit hook inspects what is staged. It cannot see what a developer typed into an assistant's chat window. Treating the hook as the answer to the "pasting credentials into Copilot" problem would be a mistake, so I use layers that each cover a different moment:

1. **Prevent the habit.** Secrets live in a manager and are injected at runtime, so the developer rarely has a real credential on their screen. Local development uses short-lived, scoped credentials against synthetic data.
2. **Constrain the assistant.** Enterprise or Business Copilot tier with public-code suggestions blocked, content exclusion for sensitive paths (`.env`, `config/secrets/*`, infrastructure repositories), and prompts and code not retained for training under the enterprise terms.
3. **Catch it at the keyboard.** For sanctioned assistants routed through our proxy, the guardrail blocks secrets in prompts (the `DB_CONN_STRING`, `AWS_ACCESS_KEY`, `PRIVATE_KEY` and similar rules in `detectors.py`). For tools that cannot be routed through it, an endpoint DLP policy or browser extension that matches the same patterns is the next best control.
4. **Catch it in the commit.** `.pre-commit-config.yaml` runs Gitleaks with the repo's `.gitleaks.toml`, which adds rules for database URLs and OIDC client secrets on top of the built-in set. AI completions often suggest plausible-looking credentials or reproduce ones from the open file, so this layer matters even when the developer is careful.
5. **Catch it on the server.** Hooks are optional on a developer's machine, so the same scan runs in CI and push protection is enabled on the repository host. A secret that reaches the remote is treated as compromised even if the PR is closed.
6. **Make leaks cheap.** Any exposure triggers rotation first and investigation second. Short-lived credentials shrink the window in which a leaked value is useful.

Install: `pip install pre-commit && pre-commit install`.

### Hallucinated dependencies in CI/CD

Language models sometimes invent package names that sound right. Attackers register those names ("slopsquatting") and wait. The pipeline defends at four points:

- **Existence and age check.** `ci/scripts/check_dependencies.py` queries PyPI or npm for every declared dependency. A package that does not exist fails the build. A package whose first release is under 30 days old fails the build. A near-miss of a popular name (edit-distance heuristic) fails the build. I ran it against `demo/requirements-ai-generated.txt` and it rejected both invented names, while the project's real requirement files passed.
- **Pinning with hashes.** `pip-compile --generate-hashes` and `pip install --require-hashes` in CI mean a package swapped after review will not install.
- **Controlled registry.** In production, builds pull from an internal mirror (Artifactory or Nexus) that only serves approved packages, applies a cooling-off period for new releases, and reserves the company's internal package names so dependency confusion cannot occur.
- **Known-vulnerability and SBOM steps.** `pip-audit` fails on known CVEs and a CycloneDX SBOM is archived on every build, so when the next big advisory lands the question "where do we use this?" takes minutes.

Limits: the age threshold will occasionally flag a legitimate new library, so there is an allow-list override that needs a named reviewer. A malicious package that has existed quietly for a year would pass the age check, which is why the vulnerability database and the controlled registry remain in place.

## 3. SIEM configuration: ransomware, Shadow AI and onboarding a new log source

The rules are implemented in `siem/wazuh/local_rules.xml`, the decoder in `local_decoder.xml`, the agent configuration in `ossec_agent_snippet.xml`, and sample test lines in `siem/samples/`. The rule schema and decoder syntax are validated against the Wazuh engine specification, and rule-trigger testing steps are detailed in `siem/samples/wazuh_logtest.md`.

**Ransomware detections** map to what the malware actually does:

| Behaviour                   | Rule   | Signal                                                                                                                                     |
| --------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Rapid encryption of files   | 100100 | 60 or more file modifications on one host in 30 seconds (real-time FIM on shares)                                                          |
| Encrypted extensions appear | 100101 | New files ending `.locked`, `.lockbit`, `.encrypted` and similar                                                                     |
| Ransom note dropped         | 100102 | Files named like `README_TO_DECRYPT.txt`                                                                                                 |
| Backup destruction          | 100103 | `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit ... recoveryenabled no`, `wbadmin delete` from Sysmon process events |
| Hypervisor shutdown         | 100104 | `esxcli vm process kill` and `vim-cmd` power-off from a shell                                                                          |

The shadow copy rule is the most valuable one: it fires before encryption finishes. Response is through Wazuh active response to isolate the host (firewall drop) and disable the account, but only after a human confirms for servers, because a false positive that isolates a hospital file server is itself an outage.

**Shadow AI detections** (rules 100200 to 100204) use the web proxy log as the source of truth because it sees every employee regardless of device:

- A consumer chatbot domain from the corporate network (ChatGPT, Claude.ai, Gemini, Copilot web, Perplexity, DeepSeek and others) raises level 8.
- Fifteen or more hits from one source in ten minutes raises level 10: this is a habit, not a curiosity.
- A transfer of 1 MB or more raises level 12. Squid's byte count is response-side, so this is a rough proxy for heavy use rather than proof of upload. Where TLS inspection is lawful and in place, request-body size is the better signal.
- Calls to provider APIs from any address other than the guardrail proxy raise level 10: that is a developer script bypassing the sanctioned path.
- The guardrail proxy's own audit log feeds rules 100210 to 100213. Five sensitive-data blocks from one caller in five minutes raises level 11. That alert goes to a human who coaches, not to an HR file, in line with the Safe Harbor policy.

The block list is only a signal source. The enforcement is DNS and proxy blocking of the same domains, with a sanctioned alternative announced alongside it. Blocking without an alternative drives staff to personal phones, where nothing is visible at all.

**Onboarding a new log source (worked example: Squid proxy).**

1. Confirm the source and format with its owner (`/var/log/squid/access.log`, native format) and who may see the data.
2. Install the Wazuh agent on that host, and enrol it with a group name (`proxy`) so config is pushed centrally.
3. Add the `<localfile>` block (see the snippet) in the group's `agent.conf`.
4. Write or select a decoder. Wazuh ships a Squid decoder, but I wrote `squid-sil` to extract the fields the rules need (source IP, status, bytes, URL) and to avoid depending on built-in rule IDs.
5. Test with `wazuh-logtest` using real lines, and confirm the fields extracted.
6. Write the rules and test each with a positive and a negative sample.
7. Add a dashboard panel and an alert route, and document the source in the log-source register (owner, retention, data classification, parser version).
8. Add a "silence" alert: if this source sends nothing for 15 minutes, raise an event. A quiet log source is the first symptom of a blind spot.

## 4. Incomplete logs during an investigation

Gaps are normal. The discipline is to say what is known, what is inferred and what cannot be known.

1. **Establish the gap.** Which sources, which window, why: rotation, agent outage, retention, attacker deletion, never enabled. A gap that starts exactly when the incident starts is itself evidence.
2. **Preserve first.** Snapshot affected hosts and volumes, export what exists, take hashes, record chain of custody. Volatile memory goes first on live hosts if the host is not already being shut down.
3. **Find alternate witnesses.** The same activity usually leaves traces elsewhere: cloud control-plane audit logs, VPC flow logs, DNS resolver logs, proxy and firewall records, identity provider sign-in events, EDR telemetry, database audit tables, the SaaS vendor's admin log, email gateway logs, backup system logs, and file-system artefacts (Windows prefetch, Event Logs, shell history, `$MFT`). Correlating two partial sources often reconstructs what one complete source would have shown.
4. **Reconstruct with confidence levels.** The timeline marks each entry as observed, corroborated or inferred. Conclusions say "no evidence of exfiltration in the available data" rather than "no exfiltration occurred".
5. **Decide conservatively.** Where the gap overlaps the PHI systems, assume the worst case for notification and containment purposes. Under the Data Protection Act the 72-hour clock runs from awareness, and uncertainty is not a reason to wait.
6. **Fix the gap.** Every incident with a log gap produces a ticket with an owner: central forwarding, longer retention, write-once storage, audit policies on, and the "silent source" alert above.

## 5. Compliance reporting in a multi-cloud environment

The aim is one control set with evidence collected continuously, rather than separate reports per cloud.

- **A single control library.** Controls are written once in provider-neutral language, then mapped to ISO/IEC 27001 Annex A, the Kenya Data Protection Act 2019, HIPAA (for customers who need it) and GDPR (where relevant). One control, one owner, one test, several framework references.
- **Automated evidence.** Prowler (AWS, Azure, GCP, Kubernetes) and Steampipe or Cloud Custodian run on a schedule against every account and write results to one store. Wazuh's SCA module covers host benchmarks (CIS), and its compliance tags let the same alerts count toward several frameworks. Cloud-native tools (Security Hub, Defender for Cloud, Security Command Center) feed the same store where a customer already pays for them.
- **Normalised data.** Findings are normalised to a common schema (control id, resource, account, provider, status, timestamp, evidence link) so a single dashboard can say "MFA on all privileged identities: 97 of 100, three exceptions with owners".
- **Reports by audience.** Engineers get per-account failing resources. Management gets control pass rates by framework and trend. Auditors get an evidence pack per control: the policy, the test, the latest result, exceptions and approvals.
- **Exceptions are first-class.** Every deviation is a risk register entry with an owner, a compensating control and an expiry date. An exception that has expired shows red.
- **Kenya-specific.** Register as a data controller or processor with the ODPC, keep the record of processing activities, run DPIAs for high-risk processing (health data qualifies), keep the breach notification runbook rehearsed, and track cross-border transfers by provider and region.
- **Cadence.** Continuous collection, weekly operations review, monthly management report, quarterly risk committee, annual audit, with the pack assembled from the store rather than from memory.

## 6. DAST in CI/CD with minimal impact, report interpretation, and catching AI-introduced logic flaws

### Minimal-impact DAST

- **Ephemeral target.** The DAST job builds the stack in the runner with synthetic data. Nothing is scanned in shared environments, and no real data is at risk from active attack payloads.
- **Right scan, right moment.** Pull requests get a passive scan (`-S`): no attack traffic, roughly two minutes, and it fails only on High findings. A nightly job runs a time-boxed active scan (`-m 10`). A full scan before release runs against a staging replica.
- **Run after the cheap checks.** The DAST job `needs` SAST and SCA, so runner minutes are not spent attacking code that already failed static checks.
- **Authenticated.** A real token for a test user is injected into ZAP. Without it the scanner only ever sees `401` pages and reports a clean result for an application it never entered.
- **Noise control.** `ci/zap/api-scan-rules.tsv` records known non-issues with reasons. Medium and below create tickets rather than blocking builds, so developers keep trusting the gate.

### Interpreting a report

`ci/zap/REPORT_INTERPRETATION.md` provides the complete triage matrix and vulnerability assessment for the DAST scan against our API gateway and microservice endpoints. The review methodology follows four stages: confirming scan coverage against the OpenAPI specification, evaluating risk and confidence correlation, assessing endpoint reachability and PHI exposure, and accounting for upstream perimeter defenses (e.g., Kong security headers and ModSecurity CRS).

### Adapting SAST and DAST to AI-generated code

AI assistants write code that works on the happy path and is syntactically clean, which is why classical scanners rate it well. Their typical flaws are semantic: an endpoint that functions but has no authorisation, a check performed on the client only, a lookup by id with no ownership test, a race between check and use, an error branch that fails open, validation that covers the example input and nothing else. These need different tools.

1. **Custom Semgrep rules for the patterns assistants repeat.** `ci/semgrep/ai-logic-flaws.yml` flags FastAPI routes with no `Depends(...)` authorisation, SQL built with f-strings, JWT decoding with verification off, wildcard CORS with credentials, weak hashes, predictable token generation and disabled TLS verification. Against `demo/vulnerable_ai_generated.py` it reported six findings, and it reported none on the project's real services. Static AST matching alone is inherently unsuited for deep object-ownership (IDOR/BOLA) logic without business context; that vulnerability class is therefore addressed via the dynamic specification tests and stateful DAST matrix described below.
2. **Authorisation test matrix generated from the API spec.** For every operation in the OpenAPI document, CI calls it as each role and as an anonymous caller, then as user A on user B's object, and asserts the expected status. This is the single most effective control for broken access control, and it is something a DAST crawler does not know how to do because it does not know your rules. Schemathesis can generate the cases, and property-based tests express invariants such as "a receptionist response never contains `diagnosis`".
3. **Stateful DAST.** ZAP contexts with two users, plus Schemathesis stateful testing, exercise sequences (create, then read as another user, then delete) that expose workflow and object-level flaws.
4. **Taint-mode SAST for data flow.** Semgrep taint rules and CodeQL queries track untrusted input to sinks (SQL, shell, template, deserialisation, outbound requests) across functions, which catches cases where the generator spread the vulnerable pattern across helpers.
5. **Human review where it matters.** Commits assisted by AI carry a trailer or PR label. CODEOWNERS requires a security-aware reviewer on changes to authentication, authorisation, cryptography and PHI handling, regardless of who or what wrote them. A short threat model (who can call this, what can they see, what if they lie) is a PR template item for new endpoints.
6. **Close the loop.** Each missed bug becomes a new rule or test. Over time the rule set encodes Savannah's own failure patterns rather than generic ones.

None of this makes generated code safe by itself. SAST rules are heuristics, DAST sees only what it can reach, and business-logic flaws still need review by someone who understands the clinical workflow.
