# Wazuh SIEM Rule Verification & Attack Simulation Runbook

This guide documents the procedures for testing custom detection rules and decoders defined in `siem/wazuh/local_rules.xml` and `siem/wazuh/local_decoder.xml`.


## 1. Shadow AI Detection Verification (`wazuh-logtest`)

Run the interactive log test utility on the Wazuh manager:
```bash
/var/ossec/bin/wazuh-logtest
```

Paste test log entries from `siem/samples/squid_access.log`:

### Case A: Consumer LLM Domain Access
* **Input:**
  ```text
  1760870400.123    245 10.0.4.23 TCP_TUNNEL/200 5120 CONNECT chat.openai.com:443 - HIER_DIRECT/104.18.32.47 -
  ```
* **Expected Output:**
  * **Decoder:** `squid-sil` (extracts `srcip: 10.0.4.23`, `action: CONNECT`, `url: chat.openai.com:443`)
  * **Rule:** `100201` (Level 8) &mdash; `Shadow AI: 10.0.4.23 accessed consumer LLM chat.openai.com:443`
  * **Compliance Tags:** `gdpr_IV_32.2`

### Case B: Benign External Web Traffic
* **Input:**
  ```text
  1760870411.554    120 10.0.4.23 TCP_TUNNEL/200 2048 CONNECT github.com:443 - HIER_DIRECT/140.82.121.4 -
  ```
* **Expected Output:**
  * **Decoder:** `squid-sil`
  * **Rule:** `100200` (Level 3) &mdash; Base egress proxy log event (no high-severity alert triggered).

### Case C: Large File/Prompt Exfiltration to Consumer LLM
* **Input:**
  ```text
  1760870415.900   3200 10.0.7.88 TCP_TUNNEL/200 4823991 CONNECT claude.ai:443 - HIER_DIRECT/160.79.104.10 -
  ```
* **Expected Output:**
  * **Decoder:** `squid-sil`
  * **Rule:** `100203` (Level 12) &mdash; `Shadow AI: Large transfer (4823991 bytes) to consumer LLM claude.ai:443`

### Case D: Direct API Call Outside Guardrail Proxy
* **Input:**
  ```text
  1760870420.010     90 10.0.7.90 TCP_TUNNEL/200 900 CONNECT api.openai.com:443 - HIER_DIRECT/104.18.7.192 -
  ```
* **Expected Output:**
  * **Decoder:** `squid-sil`
  * **Rule:** `100204` (Level 10) &mdash; `Shadow AI: Direct LLM API call from non-guardrail host 10.0.7.90`


## 2. Ransomware Behavioral Simulation (Lab / Sandbox Agent)

Execute the following simulated actions in an isolated testing environment to trigger FIM and process correlation alerts:

```bash
# A. Mass File Modification (Triggers Rule 100100 - Frequency >= 60 in 30s)
mkdir -p /srv/shares/test_canary && cd /srv/shares/test_canary
for i in $(seq 1 80); do echo "canary_data" > f$i.txt; done
for i in $(seq 1 80); do echo "encrypted_content" >> f$i.txt; done

# B. Known Encrypted Extension Generation (Triggers Rule 100101 - Level 12)
mv f1.txt f1.txt.locked

# C. Ransom Note Creation (Triggers Rule 100102 - Level 12)
echo "Your files have been encrypted. Contact support to recover." > README_TO_DECRYPT.txt
```

### Windows Host Simulation (Sysmon Process Creation)
* Execute command line:
  ```powershell
  vssadmin.exe delete shadows /all /quiet
  ```
* **Trigger:** Rule `100103` (Level 14) &mdash; MITRE ATT&CK T1490 (Inhibit System Recovery).

