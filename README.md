════════════════════════════════════ DOCUMENTATION ════════════════════════════════════

PCAP IDS Analyzer - Project Documentation

1. Overview
This project is a minimal offline IDS analyzer written in Python with Scapy.
It reads packets from a PCAP/PCAPNG file and detects:
- TCP SYN scan behavior
- High-rate TCP connection attempts per source IP

Alerts are produced in two outputs:
- Console: Snort-style alert lines
- File: JSON alert array

The script is designed to run unmodified on Windows and Linux.


2. Project Files
- pcap_ids.py
  Main analyzer implementation and CLI entrypoint.
- requirements.txt
  Python dependencies.
- rules_config.example.json
  Example config that adds extra detection rules.
- PROJECT_DOCUMENTATION.txt
  This documentation file.


3. Requirements
- Python 3.10 or newer recommended
- pip
- scapy>=2.5.0


4. Setup
4.1 Windows (PowerShell)
1) Create virtual environment:
   python -m venv .venv
2) Activate virtual environment:
   .venv\Scripts\Activate.ps1
3) Install dependencies:
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt

4.2 Linux (bash)
1) Create virtual environment:
   python3 -m venv .venv
2) Activate virtual environment:
   source .venv/bin/activate
3) Install dependencies:
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt


5. Running the Analyzer
Basic command:
python pcap_ids.py <input_capture.pcap> --json-out alerts.json

Example:
python pcap_ids.py capture.pcapng --json-out alerts.json

Optional tuning for built-in rules:
python pcap_ids.py capture.pcapng --syn-scan-threshold 30 --rate-threshold 80 --rate-window 2.0


6. Rule System
6.1 Built-in default rules
The analyzer always loads these two default rule types:
- tcp_syn_scan
- high_rate_connection_attempts

6.2 Adding rules from config
You can append more rules with:
python pcap_ids.py capture.pcapng --rules-config rules_config.example.json

Behavior:
- Built-in default rules stay active.
- Config rules are added in addition to defaults.
- Invalid/unsupported rules raise a configuration error.

Accepted config structures:
- Object form: { "rules": [ ... ] }
- Array form: [ ... ]

Supported rule types and fields:

tcp_syn_scan:
- type (required): "tcp_syn_scan"
- unique_syn_targets_threshold (positive integer)
- sid (optional positive integer; auto-assigned if omitted)
- rev (optional positive integer)
- msg (optional non-empty string)
- priority (optional positive integer)
- proto (optional non-empty string)
- enabled (optional boolean, default true)

high_rate_connection_attempts:
- type (required): "high_rate_connection_attempts"
- attempts_threshold (positive integer)
- window_seconds (positive number)
- sid (optional positive integer; auto-assigned if omitted)
- rev (optional positive integer)
- msg (optional non-empty string)
- priority (optional positive integer)
- proto (optional non-empty string)
- enabled (optional boolean, default true)


7. Alert Format
7.1 Console output (Snort style)
Example:
02/18-14:32:10.123456 [**] [1:1000001:1] Potential TCP SYN scan [**] [Priority: 2] {TCP} 10.0.0.5:45678 -> 192.168.1.10:80

7.2 JSON output
Each alert object contains:
- type
- timestamp (UTC ISO 8601)
- src_ip
- rule:
  - gid
  - sid
  - rev
  - msg
  - priority
  - proto
- details


8. Performance Characteristics
The analyzer is optimized for large capture files:
- Streaming packet read via Scapy `PcapReader`
- Streaming JSON writer (no full alert list in memory)
- Bounded per-source structures for rate tracking
- Periodic cleanup of stale per-source state
- SYN scan target tracking released after alert for a source


9. Validation Status
There are currently no unit tests included in this project tree.
Validation is done by running the analyzer against known PCAP inputs and reviewing console/JSON output.


10. Scope and Limitations
- Offline analysis only (no live capture)
- Detection focused on TCP SYN-based behavior only
- No deep payload inspection
- Threshold/rule based detection (not ML-based)

════════════════════════════════════ HOW TO USE ════════════════════════════════════

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
