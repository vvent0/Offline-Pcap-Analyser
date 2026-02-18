# PCAP IDS Analyzer

A lightweight, offline Intrusion Detection System (IDS) analyzer that detects TCP-based attacks from PCAP/PCAPNG files using Python and Scapy.

## Features

- **TCP SYN Scan Detection**: Identifies potential port scanning behavior
- **High-Rate Connection Detection**: Flags excessive connection attempts from single sources
- **Dual Output Format**: 
  - Console alerts in Snort-style format
  - JSON output for further processing
- **Custom Rule System**: Extend detection with configurable rules
- **Cross-Platform**: Works on Windows and Linux without modifications
- **Memory Efficient**: Streams large PCAP files without loading entirely into memory

## Quick Start

### Installation

#### Windows (PowerShell)
```
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
#### Linux (Bash)
````
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
````

#### Basic Usage
````
# Analyze a PCAP file and save alerts to JSON
python pcap_ids.py capture.pcapng --json-out alerts.json

# Adjust detection thresholds
python pcap_ids.py capture.pcapng --syn-scan-threshold 30 --rate-threshold 80 --rate-window 2.0

# Use custom rules
python pcap_ids.py capture.pcapng --rules-config my_rules.json --json-out alerts.json
````

## Documentation
### Project Structure
````
├── pcap_ids.py                  # Main analyzer implementation
├── alerts.json                  # Logs alerts after each scan
├── rules_config.example.json    # Example of custom rules
````
#### Built-in Detection Rules
You can extend detection capabilities by creating custom rule files.
**Option A**
Object with "rules" array
````
{
  "rules": [
    {
      "type": "tcp_syn_scan",
      "sid": 1100001,
      "rev": 1,
      "msg": "Custom SYN scan rule",
      "priority": 1,
      "proto": "TCP",
      "unique_syn_targets_threshold": 50
    }
  ]
}
````
**Option B**
Top-level array
````
[
  {
    "type": "tcp_syn_scan",
    "sid": 1100001,
    "rev": 1,
    "msg": "Custom SYN scan rule",
    "priority": 1,
    "proto": "TCP",
    "unique_syn_targets_threshold": 50
  }
]
````

### Rule Fields
**Common Fields (All rule types)**

| Field  | Required | Type | Description |
| ------------- | ------------- | ------------- | ------------- |
|  type  |  Yes  |  String  |  Rule type (tcp_syn_scan or high_rate_connection_attempts)  |
|  sid  |  No  |  Integer  |  Signature ID (auto-assigned if omitted)  |
|  rev  | No  | Integer  | Revision number  |
|  msg  | No  | String  | Alert message  |
|  priority  | No  | Integer  | Alert priority (1 = highest)  |
|  proto  | No  | String  | Protocol (e.g., "TCP")  |
|  enabled  | No  | Boolean  | Enable/disable rule (default: true)  |

**TCP SYN Scan Specific Fields**

| Field  | Required | Type | Description |
| ------------- | ------------- | ------------- | ------------- |
|  unique_syn_targets_threshold  |  Yes  |  Integer  |  Number of unique targets to trigger alert  |

**High-Rate Connection Specific Fields**

| Field  | Required | Type | Description |
| ------------- | ------------- | ------------- | ------------- |
|  attempts_threshold  |  Yes  |  Integer  |  Number of attempts to trigger alert  |
|  window_seconds  |  Yes  |  Float  |  Time window for counting attempts  |

### Output Formats
**Console Output (Snort-style)
```
02/18-14:32:10.123456 [**] [1:1000001:1] Potential TCP SYN scan [**] [Priority: 2] {TCP} 10.0.0.5:45678 -> 192.168.1.10:80
```
**JSON Output**
```
{
  "type": "tcp_syn_scan",
  "timestamp": "2024-02-18T14:32:10.123456Z",
  "src_ip": "10.0.0.5",
  "rule": {
    "gid": 1,
    "sid": 1000001,
    "rev": 1,
    "msg": "Potential TCP SYN scan",
    "priority": 2,
    "proto": "TCP"
  },
  "details": {
    "unique_targets": 25,
    "threshold": 20
  }
}
```

### Advanced Usage

**Complete Command Example**
```
# Basic analysis with custom rules and thresholds
python pcap_ids.py suspicious_traffic.pcapng \
  --syn-scan-threshold 25 \
  --rate-threshold 60 \
  --rate-window 1.5 \
  --rules-config my_rules.json \
  --json-out detailed_alerts.json

# Just analyze with default settings
python pcap_ids.py capture.pcap --json-out alerts.json
```

**Creating Custom Rules - Step by Step**
1. Copy the example file
```
   cp rules_config.example.json my_rules.json
```
2. Edit the rules
```
{
  "rules": [
    {
      "type": "tcp_syn_scan",
      "sid": 1100001,
      "rev": 1,
      "msg": "Aggressive SYN scan detection",
      "priority": 1,
      "proto": "TCP",
      "unique_syn_targets_threshold": 100
    },
    {
      "type": "high_rate_connection_attempts",
      "sid": 1100002,
      "rev": 1,
      "msg": "Burst connection detection",
      "priority": 1,
      "proto": "TCP",
      "attempts_threshold": 200,
      "window_seconds": 1.0
    }
  ]
}
```
3. Run with custom rules
```
   python pcap_ids.py capture.pcapng --rules-config my_rules.json --json-out alerts.json
```

**Performance Considerations**

    Streaming Architecture: Processes packets one at a time, ideal for large captures

    Memory Cleanup: Periodic cleanup of stale connection tracking data

    Bounded Storage: Per-source tracking structures have size limits

    Efficient JSON Writing: Streams alerts directly to file, no in-memory accumulation

**Limitations**

    Offline analysis only (no live capture support)

    TCP-based detection only (no UDP/ICMP analysis)

    No deep packet inspection

    Rule-based detection (no machine learning)

**Requirements**

    Python 3.10+

    scapy>=2.5.0

    pip

### Troubleshooting

Issue: "Rules configuration error"
Solution: Verify your JSON syntax and required fields in custom rules

Issue: No alerts generated
Solution: Adjust thresholds lower or verify PCAP contains TCP SYN traffic

Issue: Memory usage grows
Solution: Check if cleanup intervals are working; reduce rate window size
