# Section 2: Soft skills and policy enforcement

## a. The business refuses a control because of cost

I start by finding out what the objection is really about. "Too expensive" can mean the price, the budget cycle, the effort of rollout, doubt that the risk is real, or that the last security project disrupted work. Each calls for a different reply, so I ask before I argue.

Then I put the risk in the business's language. A control priced at KES 1.2 million a year looks different next to a plausible loss: a ransomware outage at a hospital customer, contract penalties, a regulator's attention. Under Section 63 of the Kenya Data Protection Act 2019, the Office of the Data Protection Commissioner (ODPC) may issue penalty notices of up to KES 5 million or up to 1% of annual turnover of the preceding financial year, whichever is lower. Beyond statutory fines, the larger costs are customer trust, indemnities under hospital SLAs, and the forensic/notification overhead. I use ranges and state my assumptions, because false precision loses credibility the moment someone questions it.

Next I look for a cheaper route to most of the risk reduction. Open-source tooling instead of a licence, a phased rollout that starts with the crown jewels (the PHI systems), configuration changes that cost nothing, or a compensating control such as stricter access plus better monitoring in place of a full redesign. Often 80% of the benefit costs 20% of the quote, and offering that shows I am working on their problem too.

If the business still declines, the decision becomes formal. The risk goes in the register with a named owner at the appropriate level, the exact scenario it accepts, a compensating control where possible, and a review date. The accepter signs it. Leaders tend to think harder when they must put their name beside the specific scenario. Risks beyond my authority to leave open go to the risk committee, and I do not agree to quietly drop it. Afterwards I keep the relationship in good order: if the scenario happens, I want to be the person who warned clearly and then helped, not the one who said "I told you so".

## b. Prioritising multiple simultaneous alerts

I score each alert on four questions asked quickly, in this order: what is the asset worth (PHI, authentication, backups, production), how confident am I that this is real, is it spreading or escalating, and is anything irreversible about to happen. Speed of spread and irreversibility outrank everything else, because they close the window for action.

In practice that gives a rough order. Active ransomware behaviour and backup deletion come first, followed by confirmed or likely exfiltration of patient data, then compromise of privileged or identity accounts, then a confirmed phishing credential entry, then policy violations such as Shadow AI use, and last the routine vulnerability and hygiene alerts. A low-confidence alert on a critical asset can outrank a high-confidence alert on a lab machine. Alert grouping matters too: five alerts from one host are one incident.

Mechanically, I take a two-minute pass over the queue before touching any single case. I assign an incident commander role for the top one, hand parallel work to colleagues with clear ownership, and write down the order and the reason in the ticket so the decision can be reviewed. If I am alone, I contain the fastest-spreading threat first, because containment is usually quicker than investigation. I tell stakeholders what is being worked, what is queued and when they will hear next. If the load exceeds what the team can handle, I escalate for help rather than let a high-severity alert wait silently. After the event I check whether the ranking was right and tune the rules and severities accordingly.

## c. One-page incident report (simulated)

> **SIMULATED EXERCISE.** Scenario: a developer pasted patient data into a public ChatGPT prompt.

**INCIDENT REPORT IR-2026-017: PHI submitted to a public generative AI service**

| | |
|---|---|
| Status | Contained, under review |
| Severity | High (PHI of identifiable patients sent to an unapproved third party) |
| Detected | 14 Oct 2026, 11:42 EAT, SIEM rule 100201 (consumer LLM access) and 100203 (large transfer) from a developer workstation |
| Reported by | SIEM first, developer self-reported 9 minutes later |
| Incident lead | Information Security Analyst |
| Notified | CISO, Data Protection Officer, Engineering Manager, Legal |

**Summary.** While debugging a failing patient import, a developer pasted 40 rows of a CSV into the free tier of a public chatbot. The rows included full names, national ID numbers, dates of birth and diagnosis codes for 40 patients of a customer hospital. The prompt left the network at 11:38.

**Timeline (EAT).**
- 11:38 Paste submitted through the browser to the public service.
- 11:42 SIEM raised a Shadow AI alert (large transfer to a consumer LLM domain).
- 11:51 Developer self-reported to security, citing the Safe Harbor policy.
- 11:55 Analyst confirmed in the proxy log the destination and time, and reviewed the CSV against the customer data inventory. 40 records, 5 data fields each.
- 12:10 Chat history deleted by the developer, and a data deletion request filed with the provider. Temporary-chat and training opt-out settings checked on the account.
- 12:30 Customer's DPO informed by Savannah's DPO (the customer is the data controller).
- 13:00 Real production export access suspended for this team pending review. Browser-level block applied for the provider's consumer domain on the corporate proxy.
- 16:00 Assessment meeting held. Notification decision recorded (below).

**Impact assessment.** Data type: special category (health) with direct identifiers. Volume: 40 individuals. Recipient: a third-party provider with no contract with Savannah or the hospital; free-tier terms may allow retention and model improvement use. Evidence of onward disclosure: none. Likelihood of harm to individuals: low to moderate, because the data was not published, but it cannot be fully recalled. Confidence: moderate, since the provider's retention behaviour cannot be verified directly.

**Regulatory position.** The customer hospital is the controller, so Savannah must notify it without delay. The controller then decides on notification to the Office of the Data Protection Commissioner, which under the Data Protection Act 2019 must happen within 72 hours of becoming aware where the breach is likely to put individuals at risk, with notice to the affected individuals when risk to them is high. The recommendation to the controller is to notify the ODPC. The processor must tell the controller without delay (done at 12:30 EAT on 14 Oct). The controller's 72 hours then run from when it became aware, so its deadline is about 12:30 EAT on 17 Oct 2026.

**Root cause.** The developer needed realistic data to debug and used production exports in the local environment. Contributing factors: no sanctioned AI assistant with data controls was available to them, production data was reachable from developer machines, and the consumer service was not blocked at the proxy.

**Actions.**

| # | Action | Owner | Due |
|---|---|---|---|
| 1 | Customer DPO to decide on ODPC and data-subject notification, with our support pack | Savannah DPO | 16 Oct |
| 2 | Provide synthetic, scrubbed datasets for import debugging | Platform Engineering | 23 Oct |
| 3 | Block consumer LLM domains at proxy and DNS, publish the sanctioned alternative | InfoSec | 17 Oct |
| 4 | Remove production data export rights from developer roles | IT | 21 Oct |
| 5 | Add PHI patterns to endpoint DLP | InfoSec | 30 Oct |
| 6 | Blameless review with the team, refresher training | InfoSec, Engineering | 31 Oct |

**Handling of the individual.** Reported within 9 minutes, so the Safe Harbor policy applies. No disciplinary action. The developer took part in the review and in drafting the new debugging guide.

## d. Translating SIEM, DAST and SAST findings for business stakeholders

Executives do not need CVE numbers. They need to know what could happen to the business, how likely, how much it costs to fix, and what decision they must make. For each finding I answer five questions in plain words: what is it, what could an attacker do with it, what would that cost us (patients, revenue, contracts, regulator), what does the fix take, and what happens if we wait.

An example. The raw ZAP finding says "SQL Injection, High, `/patients`." The business version reads: "A person with no account could read every patient record in the system through the search form. This would be a reportable breach affecting all of our hospital customers. The fix is a two-day change and has been tested. I recommend we hold Friday's release until it ships." The first version leads to a shrug. The second leads to a decision.

I use a few consistent measures rather than raw counts: open critical findings and their age against the agreed fix time, mean time to detect and to contain, percentage of repositories covered by scanning, and the trend over time. Alerts counted by the thousand tell the board nothing, because a noisy rule inflates them. A short list of the top risks, each with an owner and a date, tells them everything. For technical audiences the same finding goes with reproduction steps and a pull request. The facts do not change, only the framing.

## e. Collaboration between DevOps and Security when rolling out SAST and DAST

The rollout fails when security appears as a gate that someone else built. I aim for the opposite, and I would do it in this sequence.

Start by asking DevOps what they fear (slower pipelines, flaky builds, false positives, blame) and agree on goals together. Then run every scanner in monitor mode for several weeks: results visible, nothing blocking. We baseline the existing findings and agree that only new High findings will block, so nobody inherits a thousand-item backlog on day one. The rules live in the same repository as the code, reviewed through pull requests, so developers can propose a suppression or a new rule with the same workflow they already use.

Pipeline impact gets a published budget, for instance that PR checks add no more than five minutes, and the heavier scans run nightly. I appoint a security champion in each team, a developer with a few hours a month for security, and hold a short weekly slot for questions in the first month. Every false positive reported is fixed or explained within an agreed time, because the gate keeps credibility only if tuning is quick. Findings arrive where developers already work, as a PR comment with an example fix, not in a separate portal that nobody opens.

We track shared metrics (time to fix, scan duration, false positive rate, number of blocked builds) and look at them together. When something blocks a release, the question is "how do we fix this fast" and not "who broke it". Wins get credit in public. Over time the gates tighten as the team matures, and eventually the secure path is also the easiest one.

## f. Safe Harbor: self-report versus cover-up

The technical response is identical in both cases and begins at once, because a database credential in a third party's system is a live risk whoever put it there. The difference lies in how we treat the person and in what we say.

**The developer who reports immediately.**
1. Thank them, and say so in the first sentence of the conversation. The next developer who makes a mistake will look at how this one was treated, and that decides whether they report.
2. Contain: rotate the credential within minutes, revoke sessions, restrict the database user's network access, and review its authentication and query logs from the time of the paste onward to check for use.
3. Ask the provider to delete the conversation, switch off training use where the account allows it, and record what we did and the provider's response.
4. Assess the exposure: what the connection string reaches, whether the database holds PHI, whether any use of the credential from unexpected addresses appears in the logs. If PHI was reachable and there is any sign of access, the breach notification path begins, including the 72-hour assessment for the ODPC.
5. Run a blameless review. Why was a real string in code? Why could the developer reach a public LLM with it? Fix the system: secrets manager, a sanctioned assistant, proxy blocking.
6. Communicate proportionately. The people who need to act know the facts. The wider company gets an anonymised lesson, never a name. Policy says Safe Harbor applies, so no discipline for an honest accidental disclosure, and I keep that promise strictly.
7. Count it as a success in our metrics. A rise in self-reported incidents is a sign that the culture works.

**The developer who tries to cover it up.** Usually we find out through the SIEM (consumer LLM access, a block event from the guardrail, or a secret detected by scanning). The containment steps run exactly as above, without waiting for a confession, and I assume the credential is compromised. The human process changes: Safe Harbor protects honest reporting of accidents, and concealment falls outside it. I keep the technical and the personnel streams apart. Technical staff preserve evidence (proxy logs, timestamps, the developer's report if any) and hand the facts to HR and Legal, who run the fact-finding conversation. I do not interrogate. In that conversation the developer gets a fair chance to explain, because some people conceal out of panic rather than malice, and the outcome is proportionate to what we learn, from a documented warning to more formal measures if there was deliberate deception. The delay also matters operationally: every hour of concealment is an hour the credential was live and the 72-hour clock was running, and I note that in the incident record. Finally, I ask why the person did not feel safe reporting, because it may point to a gap in how the policy is communicated.

In both cases the incident report states the facts and the system fixes. It does not assign blame, and it never includes more personal detail than the readers need.

## g. Balancing user privacy and security monitoring

I apply three tests to every monitoring control: is it necessary for a specific, documented security purpose, is it proportionate (the least intrusive means that works), and have people been told about it. The Data Protection Act's principles of lawfulness, purpose limitation, data minimisation and transparency apply to employee data as much as to patient data, so a short DPIA is part of introducing any new monitoring.

In practice I monitor behaviour and metadata rather than content wherever I can. The SIEM needs to know that a workstation reached a consumer LLM and transferred 4 MB, not what was typed. Access to PHI is logged in detail, because patient privacy is the very thing the monitoring protects, and that is the strongest justification we have. User identities in dashboards are pseudonymised by default, and revealing a name requires a documented reason and a second approver. Access to the logs is restricted by role and itself logged. Retention is limited: 90 days of detailed logs and a year of summaries unless an investigation needs more.

Transparency is the other half. The acceptable use policy states what is monitored and why, staff sign it, and the security team publishes a plain-language summary. I avoid inspecting traffic to personal banking, personal email and healthcare sites where TLS inspection is in place, and I do not touch personal devices beyond what the BYOD agreement covers. Monitoring data is used for security. It does not go into performance reviews, and I would refuse a request to use it that way.

When privacy and security pull in opposite directions, I choose the less intrusive control that achieves the aim and say what risk remains. If it turns out the aim cannot be met without more intrusion, the decision goes to the DPO and management in writing, with the trade-off stated plainly.
