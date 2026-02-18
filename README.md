PCAP IDS - Commands and Custom Rules Guide

1. What this guide covers
This guide explains:
- setup commands
- analyzer run commands
- how to create custom rule files
- how to use custom rules with the analyzer


2. Setup commands
2.1 Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

2.2 Linux (bash)
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt


3. Analyzer commands
3.1 Basic run
python pcap_ids.py <capture_file> --json-out alerts.json

Example:
python pcap_ids.py capture.pcapng --json-out alerts.json

3.2 Tune default built-in thresholds
python pcap_ids.py capture.pcapng --syn-scan-threshold 30 --rate-threshold 80 --rate-window 2.0

3.3 Use additional custom rules from a config file
python pcap_ids.py capture.pcapng --rules-config my_rules.json --json-out alerts.json

3.4 Combine default threshold tuning and custom rules
python pcap_ids.py capture.pcapng --syn-scan-threshold 25 --rate-threshold 60 --rate-window 1.5 --rules-config my_rules.json --json-out alerts.json


4. How rule loading works
- Default rules are always loaded:
  - tcp_syn_scan
  - high_rate_connection_attempts
- Rules from --rules-config are appended to defaults.
- Custom rules do not replace default rules.
- If the rule file is invalid, the analyzer prints a rules configuration error and exits.


5. Rule config file format
You can use either format:

Format A (object with "rules"):
{
  "rules": [
    { ... },
    { ... }
  ]
}

Format B (top-level array):
[
  { ... },
  { ... }
]


6. Rule fields
6.1 Common fields (both rule types)
- type (required)
- sid (optional positive integer; auto-assigned if missing)
- rev (optional positive integer)
- msg (optional non-empty string)
- priority (optional positive integer)
- proto (optional non-empty string)
- enabled (optional true/false, default true)

6.2 tcp_syn_scan rule fields
- type: "tcp_syn_scan"
- unique_syn_targets_threshold: positive integer

6.3 high_rate_connection_attempts rule fields
- type: "high_rate_connection_attempts"
- attempts_threshold: positive integer
- window_seconds: positive number


7. Create custom rules (step by step)
1) Copy the example file:
   - source: rules_config.example.json
   - target: my_rules.json
2) Edit my_rules.json and add/adjust rule entries.
3) Run analyzer with:
   python pcap_ids.py capture.pcapng --rules-config my_rules.json --json-out alerts.json
4) Verify output:
   - console shows Snort-style lines with SID and message
   - alerts.json contains alert objects with rule metadata


8. Example custom rule file
{
  "rules": [
    {
      "type": "tcp_syn_scan",
      "sid": 1100001,
      "rev": 1,
      "msg": "SYN scan strict threshold",
      "priority": 1,
      "proto": "TCP",
      "unique_syn_targets_threshold": 100
    },
    {
      "type": "high_rate_connection_attempts",
      "sid": 1100002,
      "rev": 1,
      "msg": "High-rate burst strict threshold",
      "priority": 1,
      "proto": "TCP",
      "attempts_threshold": 200,
      "window_seconds": 1.0
    }
  ]
}

    
9. Practical notes
- Use higher thresholds to reduce false positives in noisy networks.
- Use lower thresholds for stricter detection in controlled environments.
- Keep SIDs unique across custom rules to avoid config errors.
