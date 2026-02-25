#!/usr/bin/env python3
"""
Simurg IDS — SIEM Output Formatters
Writes alerts in multiple industry-standard formats:

  1. EVE JSON      — Suricata-compatible (already in log_monitor.py, referenced here)
  2. ECS JSON      — Elastic Common Schema (Kibana / Elasticsearch ready)
  3. CEF           — Common Event Format (ArcSight, IBM QRadar, Splunk)
  4. Syslog fwd    — Forward alerts to a remote syslog server (UDP)

All formatters append to files in the configured alert directory.
"""

import json
import os
import socket
import time
from datetime import datetime, timezone


# ─── ECS JSON (Elastic Common Schema v8) ─────────────────────────────────────

def write_ecs_json(alert_dir: str, alert: dict):
    """
    Write alert in Elastic Common Schema (ECS) v8 format.
    Output file: alerts/ecs.json  (JSON Lines / NDJSON)

    Reference: https://www.elastic.co/guide/en/ecs/current/index.html
    """
    filepath = os.path.join(alert_dir, "ecs.json")

    now_iso = datetime.now(timezone.utc).isoformat()

    ecs = {
        # ECS Base fields
        "@timestamp":  now_iso,
        "ecs":         {"version": "8.11.0"},
        "message":     alert.get("description", ""),
        "tags":        ["simurg-ids", "intrusion-detection"],
        "labels": {
            "rule_name":     alert.get("rule", ""),
            "signature_id":  str(alert.get("signature_id", "")),
            "mitre_attack":  alert.get("mitre", ""),
        },

        # Event fields
        "event": {
            "kind":       "alert",
            "category":   ["intrusion_detection"],
            "type":       ["info"],
            "severity":   alert.get("threat_level", 8),
            "risk_score": alert.get("threat_level", 8) * 6.66,  # 0-100 scale
            "action":     alert.get("action", ""),
            "dataset":    "simurg.ids",
            "module":     "simurg",
            "provider":   "simurg",
            "created":    now_iso,
            "original":   alert.get("raw", alert.get("evidence", "")),
            "classification": {
                "name":      alert.get("classification", "unknown"),
            },
        },

        # Source / network fields
        "source": {
            "ip":      alert.get("ip", ""),
            "address": alert.get("ip", ""),
        },
        "network": {
            "protocol": "http",
            "direction": "inbound",
        },

        # HTTP fields (if applicable)
        "http": {
            "request": {
                "method": alert.get("method", ""),
            },
            "response": {
                "status_code": alert.get("status", 0),
            },
        },
        "url": {
            "path":     alert.get("path", ""),
            "original": alert.get("path", ""),
        },

        # Rule fields
        "rule": {
            "id":          str(alert.get("signature_id", "")),
            "name":        alert.get("rule", ""),
            "description": alert.get("description", ""),
            "category":    alert.get("classification", ""),
        },

        # Threat / MITRE ATT&CK mapping
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": [
                {
                    "id":   alert.get("mitre", ""),
                    "name": alert.get("rule", "").replace("_", " ").title(),
                }
            ],
        },

        # Observer (Simurg itself)
        "observer": {
            "name":    "Simurg IDS",
            "type":    "ids",
            "version": "2.0",
            "vendor":  "simurg",
        },

        # Simurg-specific extensions
        "simurg": {
            "alert": {
                "severity":     alert.get("severity", ""),
                "threat_level": alert.get("threat_level", 0),
                "count":        alert.get("count", 0),
                "details":      alert.get("details", ""),
                "evidence":     alert.get("evidence", ""),
                "first_seen":   alert.get("first_seen", ""),
                "total_reqs":   alert.get("total_reqs_ip", 0),
            }
        },
    }

    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(ecs, ensure_ascii=False) + "\n")


# ─── CEF (Common Event Format) ───────────────────────────────────────────────

# CEF severity mapping (0-10 scale)
_SEVERITY_TO_CEF = {
    "CRITICAL": 10,
    "HIGH":      7,
    "MEDIUM":    5,
    "LOW":       3,
    "INFO":      1,
}

_CEF_ESCAPE = str.maketrans({
    "\\": "\\\\",
    "|":  "\\|",
    "\n": "\\n",
    "\r": "\\r",
})

_CEF_EXT_ESCAPE = str.maketrans({
    "\\": "\\\\",
    "=":  "\\=",
    "\n": "\\n",
    "\r": "\\r",
})


def _cef_escape(s: str) -> str:
    return str(s).translate(_CEF_ESCAPE)


def _cef_ext(s: str) -> str:
    return str(s).translate(_CEF_EXT_ESCAPE)


def write_cef(alert_dir: str, alert: dict):
    """
    Write alert in ArcSight Common Event Format (CEF:0).
    Output file: alerts/alerts.cef  (one CEF string per line)

    CEF format:
        CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension

    Reference: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/
    """
    filepath = os.path.join(alert_dir, "alerts.cef")

    severity     = alert.get("severity", "MEDIUM")
    cef_severity = _SEVERITY_TO_CEF.get(severity, 5)
    sig_id       = alert.get("signature_id", 0)
    rule_name    = _cef_escape(alert.get("rule", "UNKNOWN"))
    description  = _cef_escape(alert.get("description", ""))

    # CEF header
    header = (
        f"CEF:0"
        f"|Simurg"
        f"|Simurg IDS"
        f"|2.0"
        f"|{sig_id}"
        f"|{description}"
        f"|{cef_severity}"
    )

    # Extension key=value pairs
    ext_parts = [
        f"src={_cef_ext(alert.get('ip', ''))}",
        f"rt={_cef_ext(alert.get('timestamp', ''))}",
        f"act={_cef_ext(alert.get('action', ''))}",
        f"request={_cef_ext(alert.get('path', ''))}",
        f"requestMethod={_cef_ext(alert.get('method', ''))}",
        f"cs1Label=RuleName cs1={_cef_ext(rule_name)}",
        f"cs2Label=MITREAttack cs2={_cef_ext(alert.get('mitre', ''))}",
        f"cs3Label=Classification cs3={_cef_ext(alert.get('classification', ''))}",
        f"cnt={alert.get('count', 0)}",
        f"cn1Label=ThreatLevel cn1={alert.get('threat_level', 0)}",
    ]
    if alert.get("evidence"):
        ext_parts.append(f"cs4Label=Evidence cs4={_cef_ext(alert['evidence'])}")
    if alert.get("details"):
        ext_parts.append(f"msg={_cef_ext(alert['details'])}")

    extension = " ".join(ext_parts)
    cef_line  = f"{header}|{extension}"

    with open(filepath, "a", encoding="utf-8") as f:
        f.write(cef_line + "\n")


# ─── Remote Syslog Forwarding (UDP) ──────────────────────────────────────────

# Syslog facility / priority
_SYSLOG_FACILITY_SECURITY = 4   # security/authorization messages
_SYSLOG_SEVERITY_MAP = {
    "CRITICAL": 2,  # Critical
    "HIGH":     3,  # Error
    "MEDIUM":   4,  # Warning
    "LOW":      6,  # Informational
    "INFO":     7,  # Debug
}


def _build_syslog_message(alert: dict) -> bytes:
    """Build an RFC 3164 syslog payload from an alert dict."""
    facility = _SYSLOG_FACILITY_SECURITY
    sev      = _SYSLOG_SEVERITY_MAP.get(alert.get("severity", "MEDIUM"), 4)
    pri      = (facility * 8) + sev

    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname  = "simurg"
    tag       = f"simurg[{alert.get('signature_id', 0)}]"
    message   = (
        f"{alert.get('rule', 'UNKNOWN')} SRC={alert.get('ip', '-')} "
        f"MITRE={alert.get('mitre', '-')} "
        f"SEV={alert.get('severity', '-')} "
        f"DESC={alert.get('description', '')}"
    )

    return f"<{pri}>{timestamp} {hostname} {tag}: {message}".encode("utf-8")


class SyslogForwarder:
    """
    Forwards alerts to a remote syslog server via UDP.
    Instantiate once and call .send(alert) for each alert.

    Args:
        host:  Remote syslog server hostname/IP.
        port:  Remote syslog server port (default 514).
    """

    def __init__(self, host: str, port: int = 514):
        self.host = host
        self.port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, alert: dict):
        """Send a single alert as a UDP syslog message."""
        try:
            msg = _build_syslog_message(alert)
            self._sock.sendto(msg, (self.host, self.port))
        except OSError:
            pass   # Best-effort forwarding

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


# ─── Master write function ────────────────────────────────────────────────────

_syslog_forwarder: SyslogForwarder | None = None


def init_forwarder(host: str, port: int = 514):
    """Initialize the global syslog forwarder (call once at startup)."""
    global _syslog_forwarder
    _syslog_forwarder = SyslogForwarder(host, port)


def write_all_formats(alert_dir: str, alert: dict, output_cfg: dict):
    """
    Write alert to all enabled output formats.

    Args:
        alert_dir:  Directory for output files.
        alert:      Alert dict from DetectionEngine.
        output_cfg: Dict from config["output_formats"].
    """
    if output_cfg.get("ecs_json", False):
        write_ecs_json(alert_dir, alert)

    if output_cfg.get("cef", False):
        write_cef(alert_dir, alert)

    if _syslog_forwarder and output_cfg.get("syslog_forward", {}).get("enabled", False):
        _syslog_forwarder.send(alert)
