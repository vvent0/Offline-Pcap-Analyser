#!/usr/bin/env python3
"""
Minimal offline PCAP IDS analyzer.

Detections:
1) TCP SYN scan activity
2) High-rate TCP connection attempts per source IP
"""

from __future__ import annotations

import argparse
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TextIO

from scapy.all import IP, TCP, PcapReader

SNORT_GID = 1
RATE_STATE_CLEANUP_INTERVAL = 200000
AUTO_SID_START = 2000000

RULE_DEFAULTS = {
    "tcp_syn_scan": {
        "sid": 1000001,
        "rev": 1,
        "msg": "Potential TCP SYN scan",
        "priority": 2,
        "proto": "TCP",
    },
    "high_rate_connection_attempts": {
        "sid": 1000002,
        "rev": 1,
        "msg": "High-rate TCP connection attempts",
        "priority": 2,
        "proto": "TCP",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline PCAP analyzer with minimal IDS alerts."
    )
    parser.add_argument("pcap", help="Path to input PCAP file")
    parser.add_argument(
        "--json-out",
        default="alerts.json",
        help="Path to output JSON alerts file (default: alerts.json)",
    )
    parser.add_argument(
        "--syn-scan-threshold",
        type=int,
        default=20,
        help="Unique SYN targets per source IP before SYN scan alert (default: 20)",
    )
    parser.add_argument(
        "--rate-threshold",
        type=int,
        default=50,
        help="SYN attempts per source IP in the window before rate alert (default: 50)",
    )
    parser.add_argument(
        "--rate-window",
        type=float,
        default=1.0,
        help="Sliding window in seconds for high-rate detection (default: 1.0)",
    )
    parser.add_argument(
        "--rules-config",
        help="Optional JSON config file with additional detection rules",
    )
    args = parser.parse_args()

    if args.syn_scan_threshold <= 0:
        parser.error("--syn-scan-threshold must be > 0")
    if args.rate_threshold <= 0:
        parser.error("--rate-threshold must be > 0")
    if args.rate_window <= 0:
        parser.error("--rate-window must be > 0")

    return args


def to_iso_utc(epoch_ts: float) -> str:
    return datetime.fromtimestamp(epoch_ts, tz=timezone.utc).isoformat()


def to_snort_time(epoch_ts: float) -> str:
    return datetime.fromtimestamp(epoch_ts, tz=timezone.utc).strftime("%m/%d-%H:%M:%S.%f")


def extract_syn_attempt_fields(pkt: Any) -> tuple[str, str, int, int, float] | None:
    ip = pkt.getlayer(IP)
    if ip is None:
        return None

    tcp = pkt.getlayer(TCP)
    if tcp is None:
        return None

    flags = int(tcp.flags)
    if (flags & 0x02) == 0 or (flags & 0x10) != 0:
        return None

    return ip.src, ip.dst, int(tcp.sport), int(tcp.dport), float(pkt.time)


@dataclass(frozen=True)
class RuleMeta:
    rule_type: str
    sid: int
    rev: int
    msg: str
    priority: int
    proto: str


@dataclass
class SynScanRule:
    meta: RuleMeta
    unique_targets_threshold: int
    syn_targets: dict[str, set[tuple[str, int]]] = field(default_factory=dict)
    alerted_sources: set[str] = field(default_factory=set)


@dataclass
class HighRateRule:
    meta: RuleMeta
    attempts_threshold: int
    window_seconds: float
    syn_times: dict[str, deque[float]] = field(default_factory=dict)
    rate_last_seen: dict[str, float] = field(default_factory=dict)
    last_alert_time: dict[str, float] = field(default_factory=dict)


def parse_positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def parse_positive_float(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or float(value) <= 0:
        raise ValueError(f"{name} must be a positive number")
    return float(value)


def parse_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def load_additional_rule_configs(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        rules = data
    elif isinstance(data, dict):
        rules = data.get("rules")
    else:
        raise ValueError("rules config must be a JSON object with 'rules' or a JSON array")

    if not isinstance(rules, list):
        raise ValueError("rules config must contain a 'rules' list")

    return rules


def build_default_rule_configs(args: argparse.Namespace) -> list[dict[str, Any]]:
    return [
        {
            "type": "tcp_syn_scan",
            "sid": RULE_DEFAULTS["tcp_syn_scan"]["sid"],
            "rev": RULE_DEFAULTS["tcp_syn_scan"]["rev"],
            "msg": RULE_DEFAULTS["tcp_syn_scan"]["msg"],
            "priority": RULE_DEFAULTS["tcp_syn_scan"]["priority"],
            "proto": RULE_DEFAULTS["tcp_syn_scan"]["proto"],
            "unique_syn_targets_threshold": args.syn_scan_threshold,
        },
        {
            "type": "high_rate_connection_attempts",
            "sid": RULE_DEFAULTS["high_rate_connection_attempts"]["sid"],
            "rev": RULE_DEFAULTS["high_rate_connection_attempts"]["rev"],
            "msg": RULE_DEFAULTS["high_rate_connection_attempts"]["msg"],
            "priority": RULE_DEFAULTS["high_rate_connection_attempts"]["priority"],
            "proto": RULE_DEFAULTS["high_rate_connection_attempts"]["proto"],
            "attempts_threshold": args.rate_threshold,
            "window_seconds": args.rate_window,
        },
    ]


def compile_rules(
    rule_configs: list[dict[str, Any]],
    fallback_syn_threshold: int,
    fallback_rate_threshold: int,
    fallback_rate_window: float,
) -> tuple[list[SynScanRule], list[HighRateRule]]:
    syn_rules: list[SynScanRule] = []
    high_rate_rules: list[HighRateRule] = []
    used_sids: set[int] = set()
    auto_sid = AUTO_SID_START

    for idx, raw_rule in enumerate(rule_configs):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"rule index {idx} must be an object")

        enabled = raw_rule.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(f"rule index {idx}: enabled must be boolean")
        if not enabled:
            continue

        rule_type = raw_rule.get("type")
        if rule_type not in RULE_DEFAULTS:
            raise ValueError(f"rule index {idx}: unsupported type '{rule_type}'")

        defaults = RULE_DEFAULTS[rule_type]

        sid_raw = raw_rule.get("sid")
        if sid_raw is None:
            while auto_sid in used_sids:
                auto_sid += 1
            sid = auto_sid
            auto_sid += 1
        else:
            sid = parse_positive_int(sid_raw, f"rule index {idx}: sid")

        if sid in used_sids:
            raise ValueError(f"rule index {idx}: duplicate sid {sid}")
        used_sids.add(sid)

        rev = parse_positive_int(raw_rule.get("rev", defaults["rev"]), f"rule index {idx}: rev")
        priority = parse_positive_int(
            raw_rule.get("priority", defaults["priority"]),
            f"rule index {idx}: priority",
        )
        msg = parse_nonempty_str(raw_rule.get("msg", defaults["msg"]), f"rule index {idx}: msg")
        proto = parse_nonempty_str(
            raw_rule.get("proto", defaults["proto"]),
            f"rule index {idx}: proto",
        )

        meta = RuleMeta(
            rule_type=rule_type,
            sid=sid,
            rev=rev,
            msg=msg,
            priority=priority,
            proto=proto,
        )

        if rule_type == "tcp_syn_scan":
            threshold = parse_positive_int(
                raw_rule.get("unique_syn_targets_threshold", fallback_syn_threshold),
                f"rule index {idx}: unique_syn_targets_threshold",
            )
            syn_rules.append(SynScanRule(meta=meta, unique_targets_threshold=threshold))
        elif rule_type == "high_rate_connection_attempts":
            attempts_threshold = parse_positive_int(
                raw_rule.get("attempts_threshold", fallback_rate_threshold),
                f"rule index {idx}: attempts_threshold",
            )
            window_seconds = parse_positive_float(
                raw_rule.get("window_seconds", fallback_rate_window),
                f"rule index {idx}: window_seconds",
            )
            high_rate_rules.append(
                HighRateRule(
                    meta=meta,
                    attempts_threshold=attempts_threshold,
                    window_seconds=window_seconds,
                )
            )

    return syn_rules, high_rate_rules


def load_rules(args: argparse.Namespace) -> tuple[list[SynScanRule], list[HighRateRule]]:
    all_rule_configs = build_default_rule_configs(args)
    if args.rules_config:
        all_rule_configs.extend(load_additional_rule_configs(args.rules_config))

    return compile_rules(
        all_rule_configs,
        fallback_syn_threshold=args.syn_scan_threshold,
        fallback_rate_threshold=args.rate_threshold,
        fallback_rate_window=args.rate_window,
    )


def make_alert(rule: RuleMeta, timestamp: float, src_ip: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": rule.rule_type,
        "timestamp": to_iso_utc(timestamp),
        "src_ip": src_ip,
        "rule": {
            "gid": SNORT_GID,
            "sid": rule.sid,
            "rev": rule.rev,
            "msg": rule.msg,
            "priority": rule.priority,
            "proto": rule.proto,
        },
        "details": details,
    }


def print_alert(alert: dict[str, Any], epoch_ts: float) -> None:
    rule = alert["rule"]
    details = alert["details"]
    src_ip = alert["src_ip"]
    src_port = details.get("src_port", 0)
    dst_ip = details.get("dst_ip", "0.0.0.0")
    dst_port = details.get("dst_port", 0)
    print(
        f"{to_snort_time(epoch_ts)} [**] "
        f"[{rule['gid']}:{rule['sid']}:{rule['rev']}] {rule['msg']} [**] "
        f"[Priority: {rule['priority']}] "
        f"{{{rule['proto']}}} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    )


class JsonAlertWriter:
    def __init__(self, path: str) -> None:
        self.path = path
        self._file: TextIO | None = None
        self._first = True

    def __enter__(self) -> "JsonAlertWriter":
        self._file = open(self.path, "w", encoding="utf-8", newline="\n")
        self._file.write("[")
        return self

    def write_alert(self, alert: dict[str, Any]) -> None:
        if self._file is None:
            raise RuntimeError("JsonAlertWriter is not open")
        if self._first:
            self._first = False
        else:
            self._file.write(",")
        self._file.write("\n")
        json.dump(alert, self._file, separators=(",", ":"))

    def __exit__(self, exc_type: Any, exc: Any, exc_tb: Any) -> None:
        if self._file is None:
            return
        if not self._first:
            self._file.write("\n")
        self._file.write("]\n")
        self._file.close()
        self._file = None


def analyze_pcap(
    pcap_path: str,
    json_out: str,
    syn_scan_rules: list[SynScanRule],
    high_rate_rules: list[HighRateRule],
) -> int:
    alert_count = 0
    max_seen_ts = 0.0
    packet_index = 0

    with PcapReader(pcap_path) as packets, JsonAlertWriter(json_out) as writer:
        for pkt in packets:
            packet_index += 1
            fields = extract_syn_attempt_fields(pkt)
            if fields is None:
                continue

            src_ip, dst_ip, src_port, dst_port, ts = fields
            if ts > max_seen_ts:
                max_seen_ts = ts

            for rule in syn_scan_rules:
                if src_ip in rule.alerted_sources:
                    continue

                targets = rule.syn_targets.get(src_ip)
                if targets is None:
                    targets = set()
                    rule.syn_targets[src_ip] = targets

                if len(targets) < rule.unique_targets_threshold:
                    targets.add((dst_ip, dst_port))

                unique_syn_targets = len(targets)
                if unique_syn_targets >= rule.unique_targets_threshold:
                    alert = make_alert(
                        rule=rule.meta,
                        timestamp=ts,
                        src_ip=src_ip,
                        details={
                            "unique_syn_targets": unique_syn_targets,
                            "threshold": rule.unique_targets_threshold,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                        },
                    )
                    writer.write_alert(alert)
                    print_alert(alert, ts)
                    alert_count += 1
                    rule.alerted_sources.add(src_ip)
                    rule.syn_targets.pop(src_ip, None)

            for rule in high_rate_rules:
                source_times = rule.syn_times.get(src_ip)
                if source_times is None:
                    source_times = deque()
                    rule.syn_times[src_ip] = source_times
                source_times.append(ts)

                if len(source_times) > rule.attempts_threshold:
                    source_times.popleft()

                window_start = ts - rule.window_seconds
                while source_times and source_times[0] < window_start:
                    source_times.popleft()

                rule.rate_last_seen[src_ip] = ts

                if len(source_times) < rule.attempts_threshold:
                    continue

                last_alert = rule.last_alert_time.get(src_ip)
                should_alert_rate = last_alert is None or ts - last_alert >= rule.window_seconds
                if should_alert_rate:
                    alert = make_alert(
                        rule=rule.meta,
                        timestamp=ts,
                        src_ip=src_ip,
                        details={
                            "attempts_in_window_gte": rule.attempts_threshold,
                            "window_seconds": rule.window_seconds,
                            "threshold": rule.attempts_threshold,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                        },
                    )
                    writer.write_alert(alert)
                    print_alert(alert, ts)
                    alert_count += 1
                    rule.last_alert_time[src_ip] = ts

            if packet_index % RATE_STATE_CLEANUP_INTERVAL == 0:
                for rule in high_rate_rules:
                    if not rule.rate_last_seen:
                        continue
                    stale_cutoff = max_seen_ts - rule.window_seconds
                    stale_sources = [ip for ip, seen in rule.rate_last_seen.items() if seen < stale_cutoff]
                    for stale_ip in stale_sources:
                        rule.syn_times.pop(stale_ip, None)
                        rule.rate_last_seen.pop(stale_ip, None)
                        last_alert_ts = rule.last_alert_time.get(stale_ip)
                        if last_alert_ts is not None and last_alert_ts < stale_cutoff:
                            rule.last_alert_time.pop(stale_ip, None)

    return alert_count


def main() -> int:
    args = parse_args()

    try:
        syn_scan_rules, high_rate_rules = load_rules(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Rules configuration error: {exc}")
        return 2

    alert_count = analyze_pcap(
        pcap_path=args.pcap,
        json_out=args.json_out,
        syn_scan_rules=syn_scan_rules,
        high_rate_rules=high_rate_rules,
    )

    if alert_count == 0:
        print("No alerts detected.")

    print(f"Wrote {alert_count} alert(s) to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
