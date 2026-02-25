#!/usr/bin/env python3
"""
Simurg IDS — Multi-Format Log Parsers
Normalizes Apache CLF, Nginx, syslog, auth.log, firewall, and JSON logs
into a unified dict schema compatible with the DetectionEngine.

Unified output schema:
    {
        "ip"       : str,      # source IP address
        "user"     : str,      # user/process (or "-")
        "datetime" : str,      # original log datetime string
        "method"   : str,      # HTTP method or event type
        "path"     : str,      # URI path or resource
        "proto"    : str,      # HTTP protocol or log source
        "status"   : int,      # HTTP status or exit code
        "size"     : int,      # bytes or 0
        "raw"      : str,      # original raw log line
        "source"   : str,      # ingestion source label
        "log_format": str,     # clf / json / syslog / auth / firewall
    }
"""

import re
import json
from datetime import datetime

# ─── Combined Log Format (Apache / Nginx access log) ─────────────────────────

_CLF_PATTERN = re.compile(
    r'^(?P<ip>\S+)'
    r'\s+\S+'
    r'\s+(?P<user>\S+)'
    r'\s+\[(?P<datetime>[^\]]+)\]'
    r'\s+"(?P<method>\S+)'
    r'\s+(?P<path>\S+)'
    r'\s+(?P<proto>[^"]*)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\d+)'
)


def parse_clf(line: str, source: str = "file") -> dict | None:
    """Parse Apache/Nginx Combined Log Format."""
    m = _CLF_PATTERN.match(line)
    if not m:
        return None
    return {
        "ip":        m.group("ip"),
        "user":      m.group("user"),
        "datetime":  m.group("datetime"),
        "method":    m.group("method"),
        "path":      m.group("path"),
        "proto":     m.group("proto"),
        "status":    int(m.group("status")),
        "size":      int(m.group("size")),
        "raw":       line,
        "source":    source,
        "log_format": "clf",
    }


# ─── Syslog (RFC 3164 / RFC 5424) ────────────────────────────────────────────

# RFC 3164: <PRI>Mon DD HH:MM:SS hostname process[pid]: message
_SYSLOG_3164 = re.compile(
    r'^(?:<(?P<pri>\d+)>)?'
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<msg>.*)$'
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
_SYSLOG_5424 = re.compile(
    r'^<(?P<pri>\d+)>(?P<ver>\d)\s+'
    r'(?P<ts>\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<sd>\[.*?\]|-)\s*'
    r'(?P<msg>.*)$'
)

# Extract IP from syslog message body (common patterns)
_IP_IN_MSG = re.compile(r'(?:from|src|source|rhost|address)\s+(\d{1,3}(?:\.\d{1,3}){3})', re.IGNORECASE)
_BARE_IP    = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _extract_ip_from_msg(msg: str) -> str:
    m = _IP_IN_MSG.search(msg)
    if m:
        return m.group(1)
    m = _BARE_IP.search(msg)
    if m:
        return m.group(1)
    return "0.0.0.0"


def parse_syslog(line: str, source: str = "syslog") -> dict | None:
    """Parse RFC 3164 or RFC 5424 syslog messages."""
    line = line.strip()

    m5 = _SYSLOG_5424.match(line)
    if m5:
        pri  = int(m5.group("pri")) if m5.group("pri") else 0
        msg  = m5.group("msg")
        host = m5.group("host")
        app  = m5.group("app")
        ts   = m5.group("ts")
        ip   = _extract_ip_from_msg(msg) if host in ("-", "localhost") else host
        return {
            "ip":        ip,
            "user":      app,
            "datetime":  ts,
            "method":    "SYSLOG",
            "path":      f"/{app}",
            "proto":     "syslog/5424",
            "status":    pri % 8,       # Severity from PRI
            "size":      len(msg),
            "raw":       line,
            "source":    source,
            "log_format": "syslog",
            "_msg":      msg,
            "_facility": pri >> 3,
            "_severity": pri % 8,
            "_host":     host,
        }

    m3 = _SYSLOG_3164.match(line)
    if m3:
        msg  = m3.group("msg")
        proc = m3.group("proc").strip()
        host = m3.group("host")
        ts   = f"{m3.group('month')} {m3.group('day')} {m3.group('time')}"
        ip   = _extract_ip_from_msg(msg) if not _BARE_IP.match(host) else host
        return {
            "ip":        ip,
            "user":      proc,
            "datetime":  ts,
            "method":    "SYSLOG",
            "path":      f"/{proc}",
            "proto":     "syslog/3164",
            "status":    0,
            "size":      len(msg),
            "raw":       line,
            "source":    source,
            "log_format": "syslog",
            "_msg":      msg,
            "_host":     host,
        }

    return None


# ─── Auth Log (/var/log/auth.log, /var/log/secure) ───────────────────────────

# Failed SSH: sshd[PID]: Failed password for [invalid user] USER from IP port PORT ssh2
_SSH_FAIL = re.compile(
    r'Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) '
    r'from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+',
    re.IGNORECASE
)

# Accepted SSH
_SSH_ACCEPT = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) '
    r'from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+',
    re.IGNORECASE
)

# sudo: USER : ... COMMAND=CMD
_SUDO_CMD = re.compile(
    r'(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.+)$',
    re.IGNORECASE
)

# PAM auth failure
_PAM_FAIL = re.compile(
    r'pam_unix\S*:\s*authentication failure.*?user=(?P<user>\S+)',
    re.IGNORECASE
)

# Timestamp at start of auth line: "Jan 15 12:34:56"
_AUTH_TS = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')


def parse_auth(line: str, source: str = "auth.log") -> dict | None:
    """Parse Linux auth.log / /var/log/secure entries."""
    ts_m = _AUTH_TS.match(line)
    ts   = ts_m.group(1) if ts_m else datetime.now().strftime("%b %d %H:%M:%S")

    # SSH failed login → map to status 401
    m = _SSH_FAIL.search(line)
    if m:
        return {
            "ip":        m.group("ip"),
            "user":      m.group("user"),
            "datetime":  ts,
            "method":    "SSH_AUTH",
            "path":      "/ssh/login",
            "proto":     "ssh",
            "status":    401,
            "size":      0,
            "raw":       line,
            "source":    source,
            "log_format": "auth",
            "_event":    "SSH_FAIL",
        }

    # SSH accepted
    m = _SSH_ACCEPT.search(line)
    if m:
        return {
            "ip":        m.group("ip"),
            "user":      m.group("user"),
            "datetime":  ts,
            "method":    "SSH_AUTH",
            "path":      "/ssh/login",
            "proto":     "ssh",
            "status":    200,
            "size":      0,
            "raw":       line,
            "source":    source,
            "log_format": "auth",
            "_event":    "SSH_ACCEPT",
        }

    # PAM failure
    m = _PAM_FAIL.search(line)
    if m:
        ip = _extract_ip_from_msg(line)
        return {
            "ip":        ip,
            "user":      m.group("user"),
            "datetime":  ts,
            "method":    "PAM_AUTH",
            "path":      "/pam/auth",
            "proto":     "pam",
            "status":    401,
            "size":      0,
            "raw":       line,
            "source":    source,
            "log_format": "auth",
            "_event":    "PAM_FAIL",
        }

    # sudo command execution
    m = _SUDO_CMD.search(line)
    if m and "sudo:" in line:
        ip = _extract_ip_from_msg(line)
        return {
            "ip":        ip,
            "user":      m.group("user"),
            "datetime":  ts,
            "method":    "SUDO",
            "path":      m.group("cmd").strip(),
            "proto":     "sudo",
            "status":    200,
            "size":      0,
            "raw":       line,
            "source":    source,
            "log_format": "auth",
            "_event":    "SUDO_CMD",
        }

    return None


# ─── Firewall Log (iptables / UFW) ────────────────────────────────────────────

# UFW: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP DPT=22
_UFW_BLOCK = re.compile(
    r'\[UFW (?P<action>BLOCK|ALLOW|LIMIT)\].*?'
    r'SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3}).*?'
    r'DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3}).*?'
    r'PROTO=(?P<proto>\S+).*?'
    r'DPT=(?P<dpt>\d+)',
    re.IGNORECASE
)

# iptables: kernel: ... SRC=IP DST=IP ... PROTO=TCP DPT=PORT
_IPT_KERN = re.compile(
    r'SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3}).*?'
    r'DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3}).*?'
    r'PROTO=(?P<proto>\S+).*?'
    r'DPT=(?P<dpt>\d+)',
    re.IGNORECASE
)

_FW_TS = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')


def parse_firewall(line: str, source: str = "firewall") -> dict | None:
    """Parse iptables / UFW firewall log lines."""
    ts_m = _FW_TS.match(line)
    ts   = ts_m.group(1) if ts_m else datetime.now().strftime("%b %d %H:%M:%S")

    m = _UFW_BLOCK.search(line)
    pat = m or _IPT_KERN.search(line)
    if not pat:
        return None

    action = m.group("action") if m else ("BLOCK" if "DROP" in line.upper() else "ALLOW")
    dpt    = int(pat.group("dpt")) if pat.group("dpt").isdigit() else 0

    # Map blocked ports to status codes
    status = 403 if action.upper() in ("BLOCK", "DROP") else 200

    return {
        "ip":        pat.group("src"),
        "user":      "-",
        "datetime":  ts,
        "method":    f"FW_{action.upper()}",
        "path":      f"/port/{pat.group('proto')}/{dpt}",
        "proto":     pat.group("proto"),
        "status":    status,
        "size":      0,
        "raw":       line,
        "source":    source,
        "log_format": "firewall",
        "_dst":       pat.group("dst"),
        "_dpt":       dpt,
        "_action":    action.upper(),
    }


# ─── JSON Log ─────────────────────────────────────────────────────────────────

def parse_json_line(line: str, source: str = "json") -> dict | None:
    """
    Parse a structured JSON log line into unified schema.
    Supports common field naming conventions:
      - Elasticsearch / ECS fields
      - Fluentd / Logstash fields
      - Generic flat JSON
    """
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    # IP extraction — try common field names
    ip = (
        obj.get("src_ip") or obj.get("source.ip") or obj.get("client_ip") or
        obj.get("remote_addr") or obj.get("host") or obj.get("ip") or "0.0.0.0"
    )

    # Timestamp
    ts = (
        obj.get("@timestamp") or obj.get("timestamp") or obj.get("time") or
        datetime.now().isoformat()
    )

    # Method / event
    method = (
        obj.get("http.request.method") or obj.get("method") or
        obj.get("request_method") or obj.get("event.action") or "GET"
    )

    # Path / URL
    path = (
        obj.get("url.path") or obj.get("path") or
        obj.get("request") or obj.get("uri") or "/"
    )

    # Status
    status_raw = obj.get("http.response.status_code") or obj.get("status") or obj.get("response_code") or 0
    try:
        status = int(status_raw)
    except (ValueError, TypeError):
        status = 0

    # Size
    size_raw = obj.get("http.response.body.bytes") or obj.get("bytes") or obj.get("size") or 0
    try:
        size = int(size_raw)
    except (ValueError, TypeError):
        size = 0

    return {
        "ip":        str(ip),
        "user":      str(obj.get("user.name") or obj.get("user") or "-"),
        "datetime":  str(ts),
        "method":    str(method).upper(),
        "path":      str(path),
        "proto":     str(obj.get("network.protocol") or obj.get("proto") or "HTTP/1.1"),
        "status":    status,
        "size":      size,
        "raw":       line,
        "source":    source,
        "log_format": "json",
        "_raw_obj":  obj,
    }


# ─── Auto-detect Parser ───────────────────────────────────────────────────────

def parse_auto(line: str, hint: str = "clf", source: str = "auto") -> dict | None:
    """
    Auto-detect log format and parse accordingly.

    Args:
        line:   Raw log line string.
        hint:   Format hint from config ("clf", "json", "syslog", "auth", "firewall").
        source: Source label for the parsed record.

    Returns:
        Normalized dict or None if unparsable.
    """
    line = line.strip()
    if not line:
        return None

    parsers = {
        "clf":      parse_clf,
        "json":     parse_json_line,
        "syslog":   parse_syslog,
        "auth":     parse_auth,
        "firewall": parse_firewall,
    }

    # Try hinted parser first
    fn = parsers.get(hint)
    if fn:
        result = fn(line, source=source)
        if result:
            return result

    # Fallback: try each parser in order
    for fmt, fn in parsers.items():
        if fmt == hint:
            continue
        result = fn(line, source=source)
        if result:
            return result

    return None
