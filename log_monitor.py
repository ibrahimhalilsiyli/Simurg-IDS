#!/usr/bin/env python3
"""
Simurg IDS v3.0 — Enterprise Multi-Source Intrusion Detection Engine
Inspired by: Snort, Suricata, OSSEC, Wazuh, Elastic Security

Detection Rules:
  [SID:100001] Brute Force           (MITRE T1110)      — CRITICAL  (Level 14)
  [SID:100002] SQL Injection         (MITRE T1190)      — HIGH      (Level 12)
  [SID:100003] XSS Attempt           (MITRE T1059.007)  — HIGH      (Level 12)
  [SID:100004] Directory Traversal   (MITRE T1083)      — MEDIUM    (Level 8)
  [SID:100005] Scanner Detection     (MITRE T1595)      — MEDIUM    (Level 8)
  [SID:100006] DDoS / Rate Flood     (MITRE T1498)      — HIGH      (Level 12)
  [SID:100007] Sensitive File Access (MITRE T1005)      — MEDIUM    (Level 8)
  [SID:100008] Blacklisted IP        (MITRE T1071)      — CRITICAL  (Level 14)
  [SID:100009] SSH Brute Force       (MITRE T1110.001)  — CRITICAL  (Level 14)
  [SID:100010] Port Scan             (MITRE T1046)      — MEDIUM    (Level 8)
  [SID:100011] Statistical Traffic Deviation    (MITRE T1499)      — MEDIUM    (Level 8)

Correlation Rules:
  [SID:200001] Multi-Vector Attack   — CRITICAL (Level 15) — APT behavior
  [SID:200002] Recon-to-Exploit      — HIGH     (Level 13) — Scanner → Injection chain

Ingestion Sources: file tail, UDP syslog (RFC 3164/5424), auth.log, firewall, stdin
Output Formats:    EVE JSON (Suricata), Wazuh alerts.log, ECS JSON (Elastic), CEF
Only Python standard libraries are used.
"""

import re
import os
import sys
import json
import time
import uuid
import hashlib
from datetime import datetime
from collections import defaultdict, deque

# ─── Enterprise ingestion + output modules (optional, graceful fallback) ──────
try:
    from ingestion.pipeline   import Pipeline
    from output.formatters    import write_all_formats, init_forwarder
    _PIPELINE_AVAILABLE = True
except ImportError:
    _PIPELINE_AVAILABLE = False

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
COLORS = {
    "RED":      "\033[91m",
    "GREEN":    "\033[92m",
    "YELLOW":   "\033[93m",
    "BLUE":     "\033[94m",
    "MAGENTA":  "\033[95m",
    "CYAN":     "\033[96m",
    "WHITE":    "\033[97m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "RESET":    "\033[0m",
    "DARKRED":  "\033[38;5;88m",
    "BG_RED":   "\033[41m",
    "BG_YELLOW":"\033[43m",
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[97;41m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[96m",
    "INFO":     "\033[37m",
}

THREAT_LEVEL_MAP = {
    "CRITICAL": 14,
    "HIGH":     12,
    "MEDIUM":   8,
    "LOW":      4,
    "INFO":     2,
}

R  = COLORS["RED"]
G  = COLORS["GREEN"]
Y  = COLORS["YELLOW"]
B  = COLORS["BLUE"]
M  = COLORS["MAGENTA"]
C  = COLORS["CYAN"]
W  = COLORS["WHITE"]
BD = COLORS["BOLD"]
DM = COLORS["DIM"]
RS = COLORS["RESET"]
DR = COLORS["DARKRED"]

# ─── Rule SID Registry (Snort-style) ────────────────────────────────────────
RULE_SIDS = {
    "BRUTE_FORCE":          100001,
    "SQL_INJECTION":        100002,
    "XSS_ATTEMPT":          100003,
    "DIRECTORY_TRAVERSAL":  100004,
    "SCANNER_DETECTED":     100005,
    "DDOS_FLOOD":           100006,
    "SENSITIVE_FILE_ACCESS":100007,
    "BLACKLISTED_IP":       100008,
    "SSH_BRUTE_FORCE":      100009,
    "PORT_SCAN":            100010,
    "TRAFFIC_DEVIATION":   100011,
    # Correlation rules
    "MULTI_VECTOR_ATTACK":  200001,
    "RECON_TO_EXPLOIT":     200002,
}

RULE_CLASSIFICATIONS = {
    "BRUTE_FORCE":          "attempted-admin",
    "SQL_INJECTION":        "web-application-attack",
    "XSS_ATTEMPT":          "web-application-attack",
    "DIRECTORY_TRAVERSAL":  "attempted-recon",
    "SCANNER_DETECTED":     "attempted-recon",
    "DDOS_FLOOD":           "denial-of-service",
    "SENSITIVE_FILE_ACCESS":"attempted-recon",
    "BLACKLISTED_IP":       "trojan-activity",
    "SSH_BRUTE_FORCE":      "attempted-admin",
    "PORT_SCAN":            "attempted-recon",
    "TRAFFIC_DEVIATION":   "unusual-client-port-connection",
    "MULTI_VECTOR_ATTACK":  "targeted-activity",
    "RECON_TO_EXPLOIT":     "targeted-activity",
}

# ─── Log Line Regex (Combined Log Format) ────────────────────────────────────
LOG_PATTERN = re.compile(
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

# ─── Signature Patterns ─────────────────────────────────────────────────────

SQL_INJECTION_PATTERNS = re.compile(
    r"(?i)"
    r"(?:union\s+select|union\s+all\s+select)"
    r"|(?:select\s+.+\s+from\s+)"
    r"|(?:insert\s+into\s+)"
    r"|(?:delete\s+from\s+)"
    r"|(?:drop\s+table)"
    r"|(?:update\s+.+\s+set\s+)"
    r"|(?:or\s+1\s*=\s*1)"
    r"|(?:or\s+'1'\s*=\s*'1')"
    r"|(?:or\s+true)"
    r"|(?:'\s*or\s*')"
    r"|(?:;\s*--)"
    r"|(?:'\s*;\s*drop)"
    r"|(?:benchmark\s*\()"
    r"|(?:sleep\s*\()"
    r"|(?:waitfor\s+delay)"
    r"|(?:load_file\s*\()"
    r"|(?:into\s+outfile)"
    r"|(?:information_schema)"
    r"|(?:0x[0-9a-fA-F]+)"
)

XSS_PATTERNS = re.compile(
    r"(?i)"
    r"(?:<\s*script)"
    r"|(?:javascript\s*:)"
    r"|(?:on(?:error|load|click|mouseover|focus|blur)\s*=)"
    r"|(?:eval\s*\()"
    r"|(?:document\.(?:cookie|location|write))"
    r"|(?:window\.(?:location|open))"
    r"|(?:alert\s*\()"
    r"|(?:prompt\s*\()"
    r"|(?:confirm\s*\()"
    r"|(?:<\s*img[^>]+onerror)"
    r"|(?:<\s*iframe)"
    r"|(?:<\s*svg[^>]+onload)"
)

TRAVERSAL_PATTERNS = re.compile(
    r"(?:\.\./)+"
    r"|(?:\.\.\\\\)+"
    r"|(?:%2e%2e[%/\\\\])"
    r"|(?:/etc/(?:passwd|shadow|hosts|group))"
    r"|(?:/proc/self)"
    r"|(?:/var/log)"
    r"|(?:c:\\\\windows)"
    r"|(?:c:\\\\boot\.ini)"
)

SENSITIVE_FILES = re.compile(
    r"(?i)"
    r"(?:/\.env)"
    r"|(?:/\.git/)"
    r"|(?:/\.htaccess)"
    r"|(?:/\.htpasswd)"
    r"|(?:/wp-config\.php)"
    r"|(?:/config\.php)"
    r"|(?:/database\.yml)"
    r"|(?:/settings\.py)"
    r"|(?:/web\.config)"
    r"|(?:/etc/shadow)"
    r"|(?:/etc/passwd)"
    r"|(?:/id_rsa)"
    r"|(?:/\.ssh/)"
    r"|(?:/backup)"
    r"|(?:/phpinfo)"
    r"|(?:/server-status)"
    r"|(?:/\.DS_Store)"
    r"|(?:/\.bash_history)"
    r"|(?:/credentials)"
    r"|(?:/secret)"
)

# ─── Configuration ───────────────────────────────────────────────────────────

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "log_file": "access.log",
    "alert_dir": "alerts",
    "rules": {
        "brute_force":       {"enabled": True, "threshold": 50,  "window": 60, "severity": "CRITICAL", "mitre": "T1110"},
        "sql_injection":     {"enabled": True, "severity": "HIGH",     "mitre": "T1190"},
        "xss":               {"enabled": True, "severity": "HIGH",     "mitre": "T1059.007"},
        "directory_traversal": {"enabled": True, "severity": "MEDIUM", "mitre": "T1083"},
        "scanner":           {"enabled": True, "threshold": 100, "window": 60, "severity": "MEDIUM",   "mitre": "T1595"},
        "ddos":              {"enabled": True, "threshold": 200, "window": 10, "severity": "HIGH",     "mitre": "T1498"},
        "sensitive_file":    {"enabled": True, "severity": "MEDIUM",   "mitre": "T1005"},
    },
    "response": {"auto_ban": True, "ban_duration": 600, "alert_cooldown": 30},
    "blacklist": [],
}


def load_config():
    """Load configuration from config.json, fallback to defaults."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for key in DEFAULT_CONFIG:
                if key not in cfg:
                    cfg[key] = DEFAULT_CONFIG[key]
            return cfg
        except (json.JSONDecodeError, IOError) as e:
            print(f"{Y}[!] Config load error: {e}. Using defaults.{RS}")
    return DEFAULT_CONFIG.copy()


# ─── Line Parser ─────────────────────────────────────────────────────────────

def parse_log_line(line):
    """Parse a Combined Log Format line. Returns dict or None."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    return {
        "ip":       match.group("ip"),
        "user":     match.group("user"),
        "datetime": match.group("datetime"),
        "method":   match.group("method"),
        "path":     match.group("path"),
        "proto":    match.group("proto"),
        "status":   int(match.group("status")),
        "size":     int(match.group("size")),
    }


# ─── Alert Writer ────────────────────────────────────────────────────────────

def ensure_alert_dir(alert_dir):
    """Create alert directory if it doesn't exist."""
    if not os.path.exists(alert_dir):
        os.makedirs(alert_dir)


def generate_flow_id(ip, timestamp):
    """Generate a Suricata-style flow_id from IP and timestamp."""
    raw = f"{ip}-{timestamp}".encode()
    return int(hashlib.md5(raw).hexdigest()[:16], 16)


def write_alert_log(alert_dir, alert):
    """Append human-readable alert to alerts.log (Wazuh-style format)."""
    filepath = os.path.join(alert_dir, "alerts.log")
    sev = alert["severity"]
    sid = alert.get("signature_id", "N/A")
    threat_level = alert.get("threat_level", 0)
    line = (
        f"** Alert {sid} "
        f"- {alert['rule']} **\n"
        f"{alert['timestamp']} "
        f"{alert['ip']}  -> "
        f"Rule: {sid} (level {threat_level}) -> "
        f"'{alert['description']}'\n"
        f"Src IP: {alert['ip']}\n"
        f"Classification: {alert.get('classification', 'N/A')}\n"
        f"MITRE ATT&CK: {alert['mitre']}\n"
    )
    if alert.get("details"):
        line += f"Details: {alert['details']}\n"
    if alert.get("evidence"):
        line += f"Evidence: {alert['evidence']}\n"
    if alert.get("action"):
        line += f"Action: {alert['action']}\n"
    line += "\n"
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(line)


def write_eve_json(alert_dir, alert):
    """Write Suricata EVE JSON-style structured alert."""
    filepath = os.path.join(alert_dir, "eve.json")
    eve_event = {
        "timestamp": alert["timestamp"],
        "flow_id": generate_flow_id(alert["ip"], alert["timestamp"]),
        "event_type": "alert",
        "src_ip": alert["ip"],
        "http": {
            "hostname": "localhost",
            "url": alert.get("path", "/"),
            "http_method": alert.get("method", "GET"),
            "protocol": "HTTP/1.1",
            "status": alert.get("status", 0),
            "length": 0,
        },
        "alert": {
            "action": "allowed" if alert.get("action") == "LOG_ONLY" else "blocked",
            "gid": 1,
            "signature_id": alert.get("signature_id", 0),
            "rev": 1,
            "signature": alert["description"],
            "category": alert.get("classification", "unknown"),
            "severity": THREAT_LEVEL_MAP.get(alert["severity"], 8),
            "metadata": {
                "mitre_attack": [alert["mitre"]],
                "rule_name": alert["rule"],
                "severity_label": alert["severity"],
                "threat_level": alert.get("threat_level", 0),
            }
        },
        "app_proto": "http",
    }
    if alert.get("evidence"):
        eve_event["alert"]["metadata"]["evidence"] = alert["evidence"]
    if alert.get("count"):
        eve_event["alert"]["metadata"]["event_count"] = alert["count"]

    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(eve_event, ensure_ascii=False) + "\n")


def write_alert_json(alert_dir, alert):
    """Append structured JSON alert to alerts.json (JSON Lines)."""
    filepath = os.path.join(alert_dir, "alerts.json")
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def print_alert(alert):
    """Print a Wazuh/Suricata-style colored alert to terminal."""
    sev = alert["severity"]
    sev_color = SEVERITY_COLORS.get(sev, RS)
    sid = alert.get("signature_id", "N/A")
    threat_level = alert.get("threat_level", 0)
    classification = alert.get("classification", "N/A")

    threat_bar = "#" * min(threat_level, 15) + "-" * (15 - min(threat_level, 15))

    print(f"\n{sev_color}{BD}{'=' * 76}")
    print(f"  !  ALERT - SID:{sid}  [{alert['rule']}]    [{sev}]")
    print(f"{'=' * 76}{RS}")
    print(f"  {BD}Signature ID :{RS}  {C}{sid}{RS}  rev:1")
    print(f"  {BD}Classification:{RS}  {classification}")
    print(f"  {BD}MITRE ATT&CK :{RS}  {C}{alert['mitre']}{RS}")
    print(f"  {BD}Severity     :{RS}  {sev_color}{sev}{RS}")
    print(f"  {BD}Threat Level :{RS}  {R}{threat_bar}{RS}  ({threat_level}/15)")
    print(f"  {BD}Source IP    :{RS}  {R}{alert['ip']}{RS}")
    print(f"  {BD}Timestamp    :{RS}  {alert.get('log_datetime', alert['timestamp'])}")
    print(f"  {BD}Description  :{RS}  {alert['description']}")
    if alert.get("details"):
        print(f"  {BD}Details      :{RS}  {alert['details']}")
    if alert.get("evidence"):
        print(f"  {BD}Evidence     :{RS}  {Y}{alert['evidence']}{RS}")
    if alert.get("count"):
        print(f"  {BD}Count        :{RS}  {R}{alert['count']}{RS} events in window")
    if alert.get("action"):
        print(f"  {BD}Action       :{RS}  {M}{alert['action']}{RS}")
    print(f"{sev_color}{'=' * 76}{RS}\n")


# ─── Response Actions ────────────────────────────────────────────────────────

def ban_ip(ip, duration):
    """Ban IP via iptables (Linux only). Returns action string."""
    if os.name == "nt":
        return "LOG_ONLY (iptables not available on Windows)"

    import subprocess
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            subprocess.Popen(
                ["bash", "-c",
                 f"sleep {duration} && sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return f"BANNED via iptables for {duration // 60}min"
        else:
            return f"BAN_FAILED: {result.stderr.strip()}"
    except Exception as e:
        return f"BAN_ERROR: {e}"


# ─── Detection Engine ────────────────────────────────────────────────────────

class DetectionEngine:
    """Multi-rule intrusion detection engine with correlation (OSSEC/Wazuh-style)."""

    def __init__(self, config):
        self.config = config
        self.rules_cfg = config["rules"]
        self.response_cfg = config["response"]
        self.alert_dir = config["alert_dir"]
        self.blacklist = set(config.get("blacklist", []))

        ensure_alert_dir(self.alert_dir)

        # Per-IP tracking structures
        self.fail_times    = defaultdict(deque)   # brute force (HTTP)
        self.ssh_fail_times= defaultdict(deque)   # SSH brute force
        self.req_times     = defaultdict(deque)   # DDoS rate
        self.path_times    = defaultdict(deque)   # scanner unique paths
        self.fw_src_times  = defaultdict(deque)   # port scan (firewall DROP)
        self.first_seen    = {}
        self.total_reqs    = defaultdict(int)
        self.total_alerts  = defaultdict(int)

        # Statistical Traffic Deviation: per-IP rolling baseline (requests per minute)
        self.baseline_window  = config["rules"].get("deviation", {}).get("baseline_window", 600)
        self.deviation_factor = config["rules"].get("deviation", {}).get("deviation_factor", 3.0)
        self.deviation_req_times = defaultdict(deque)  # larger window for baseline
        self.deviation_baselines = {}                  # IP -> computed baseline rate

        # Cooldown tracking: (rule_name, ip) -> last_alert_time
        self.cooldown_tracker = {}

        # Banned IPs
        self.banned_ips = set()

        # Correlation: IP -> set of triggered rule names (within correlation window)
        self.correlation_window = 300  # 5 minute correlation window
        self.ip_alert_history = defaultdict(list)  # IP -> [(timestamp, rule_name)]

        # Output formats config
        self.output_cfg = config.get("output_formats", {})

        # Initialize syslog forwarder if enabled
        if _PIPELINE_AVAILABLE:
            fwd_cfg = self.output_cfg.get("syslog_forward", {})
            if fwd_cfg.get("enabled"):
                init_forwarder(fwd_cfg.get("host", "127.0.0.1"),
                               fwd_cfg.get("port", 514))

        # Stats
        self.stats = {
            "lines_processed": 0,
            "alerts_fired": 0,
            "start_time": time.time(),
            "alerts_per_rule": defaultdict(int),
            "top_attackers": defaultdict(int),
            "severity_dist": defaultdict(int),
        }

    def _is_cooled_down(self, rule_name, ip, now):
        """Check if enough time has passed since last alert for this rule+IP."""
        cooldown = self.response_cfg.get("alert_cooldown", 30)
        key = (rule_name, ip)
        last = self.cooldown_tracker.get(key, 0.0)
        if (now - last) >= cooldown:
            self.cooldown_tracker[key] = now
            return True
        return False

    def _check_correlation(self, ip, rule_name, now):
        """OSSEC-style multi-event correlation engine."""
        # Record this alert for correlation
        self.ip_alert_history[ip].append((now, rule_name))

        # Purge old correlation entries
        cutoff = now - self.correlation_window
        self.ip_alert_history[ip] = [
            (t, r) for t, r in self.ip_alert_history[ip] if t > cutoff
        ]

        recent_rules = set(r for _, r in self.ip_alert_history[ip])

        # Correlation rule 1: Multi-vector attack (3+ different attack types)
        attack_rules = recent_rules - {"SCANNER_DETECTED", "BLACKLISTED_IP"}
        if len(attack_rules) >= 3:
            if self._is_cooled_down("MULTI_VECTOR_ATTACK", ip, now):
                self._fire_correlated_alert(
                    rule_name="MULTI_VECTOR_ATTACK",
                    ip=ip,
                    severity="CRITICAL",
                    mitre="TA0001",
                    description=f"APT-style multi-vector attack: {len(attack_rules)} different techniques from single source",
                    details=f"Detected techniques: {', '.join(sorted(attack_rules))}",
                    threat_level=15,
                )

        # Correlation rule 2: Recon-to-exploit chain (scanner + injection)
        recon_rules = {"SCANNER_DETECTED", "SENSITIVE_FILE_ACCESS", "DIRECTORY_TRAVERSAL"}
        exploit_rules = {"SQL_INJECTION", "XSS_ATTEMPT", "BRUTE_FORCE"}
        if (recent_rules & recon_rules) and (recent_rules & exploit_rules):
            if self._is_cooled_down("RECON_TO_EXPLOIT", ip, now):
                self._fire_correlated_alert(
                    rule_name="RECON_TO_EXPLOIT",
                    ip=ip,
                    severity="HIGH",
                    mitre="TA0043",
                    description="Reconnaissance-to-exploitation chain detected",
                    details=f"Recon: {recent_rules & recon_rules} → Exploit: {recent_rules & exploit_rules}",
                    threat_level=13,
                )

    def _fire_correlated_alert(self, rule_name, ip, severity, mitre, description, details="", threat_level=15):
        """Fire a correlation-based alert (no parsed log line needed)."""
        sid = RULE_SIDS.get(rule_name, 0)
        classification = RULE_CLASSIFICATIONS.get(rule_name, "unknown")

        alert = {
            "timestamp":      datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            "rule":           rule_name,
            "signature_id":   sid,
            "classification": classification,
            "mitre":          mitre,
            "severity":       severity,
            "threat_level":   threat_level,
            "ip":             ip,
            "log_datetime":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "method":         "N/A",
            "path":           "N/A",
            "status":         0,
            "description":    description,
            "details":        details,
            "evidence":       "",
            "count":          0,
            "action":         "CORRELATED_ALERT",
            "total_reqs_ip":  self.total_reqs.get(ip, 0),
            "first_seen":     self.first_seen.get(ip, "N/A"),
        }

        print_alert(alert)
        write_alert_log(self.alert_dir, alert)
        write_eve_json(self.alert_dir, alert)
        write_alert_json(self.alert_dir, alert)
        if _PIPELINE_AVAILABLE:
            write_all_formats(self.alert_dir, alert, self.output_cfg)

        self.stats["alerts_fired"] += 1
        self.total_alerts[rule_name] += 1
        self.stats["alerts_per_rule"][rule_name] += 1
        self.stats["severity_dist"][severity] += 1

    def _fire_alert(self, rule_name, parsed, severity, mitre, description, details="", evidence="", count=0):
        """Create, print, and log a Suricata/Wazuh-style alert."""
        now = time.time()
        ip = parsed["ip"]

        if not self._is_cooled_down(rule_name, ip, now):
            return

        sid = RULE_SIDS.get(rule_name, 0)
        classification = RULE_CLASSIFICATIONS.get(rule_name, "unknown")
        threat_level = THREAT_LEVEL_MAP.get(severity, 8)

        action = "LOG_ONLY"
        if self.response_cfg.get("auto_ban") and severity in ("CRITICAL", "HIGH"):
            if ip not in self.banned_ips:
                duration = self.response_cfg.get("ban_duration", 600)
                action = ban_ip(ip, duration)
                if "BANNED" in action:
                    self.banned_ips.add(ip)

        alert = {
            "timestamp":      datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
            "rule":           rule_name,
            "signature_id":   sid,
            "classification": classification,
            "mitre":          mitre,
            "severity":       severity,
            "threat_level":   threat_level,
            "ip":             ip,
            "log_datetime":   parsed["datetime"],
            "method":         parsed["method"],
            "path":           parsed["path"],
            "status":         parsed["status"],
            "description":    description,
            "details":        details,
            "evidence":       evidence,
            "count":          count,
            "action":         action,
            "total_reqs_ip":  self.total_reqs[ip],
            "first_seen":     self.first_seen.get(ip, "N/A"),
        }

        print_alert(alert)
        write_alert_log(self.alert_dir, alert)
        write_eve_json(self.alert_dir, alert)
        write_alert_json(self.alert_dir, alert)
        if _PIPELINE_AVAILABLE:
            write_all_formats(self.alert_dir, alert, self.output_cfg)

        self.stats["alerts_fired"] += 1
        self.total_alerts[rule_name] += 1
        self.stats["alerts_per_rule"][rule_name] += 1
        self.stats["severity_dist"][severity] += 1
        self.stats["top_attackers"][ip] += 1

        # Feed into correlation engine
        self._check_correlation(ip, rule_name, now)

    # ─── Individual Rule Checks ──────────────────────────────────────────

    def check_blacklist(self, parsed):
        """Check if IP is in the blacklist."""
        ip = parsed["ip"]
        if ip in self.blacklist:
            self._fire_alert(
                rule_name="BLACKLISTED_IP",
                parsed=parsed,
                severity="CRITICAL",
                mitre="T1071",
                description="Traffic from blacklisted IP address",
                details=f"IP {ip} is in the configured blacklist",
            )

    def check_brute_force(self, parsed, now):
        """Rule SID:100001 — Brute force detection (multiple 401/403)."""
        cfg = self.rules_cfg.get("brute_force", {})
        if not cfg.get("enabled"):
            return

        status = parsed["status"]
        if status not in (401, 403):
            return

        ip = parsed["ip"]
        threshold = cfg.get("threshold", 50)
        window = cfg.get("window", 60)

        dq = self.fail_times[ip]
        dq.append(now)

        while dq and (now - dq[0]) > window:
            dq.popleft()

        count = len(dq)
        if count >= threshold:
            self._fire_alert(
                rule_name="BRUTE_FORCE",
                parsed=parsed,
                severity=cfg.get("severity", "CRITICAL"),
                mitre=cfg.get("mitre", "T1110"),
                description=f"{count} failed auth attempts in {window}s window",
                details=f"Threshold={threshold} | Status codes: 401, 403",
                count=count,
            )

    def check_sql_injection(self, parsed):
        """Rule SID:100002 — SQL injection in request path."""
        cfg = self.rules_cfg.get("sql_injection", {})
        if not cfg.get("enabled"):
            return

        path = parsed["path"]
        match = SQL_INJECTION_PATTERNS.search(path)
        if match:
            self._fire_alert(
                rule_name="SQL_INJECTION",
                parsed=parsed,
                severity=cfg.get("severity", "HIGH"),
                mitre=cfg.get("mitre", "T1190"),
                description="SQL injection payload detected in request URI",
                evidence=path,
            )

    def check_xss(self, parsed):
        """Rule SID:100003 — XSS attempt in request path."""
        cfg = self.rules_cfg.get("xss", {})
        if not cfg.get("enabled"):
            return

        path = parsed["path"]
        match = XSS_PATTERNS.search(path)
        if match:
            self._fire_alert(
                rule_name="XSS_ATTEMPT",
                parsed=parsed,
                severity=cfg.get("severity", "HIGH"),
                mitre=cfg.get("mitre", "T1059.007"),
                description="Cross-site scripting payload detected in request URI",
                evidence=path,
            )

    def check_directory_traversal(self, parsed):
        """Rule SID:100004 — Directory traversal attempt."""
        cfg = self.rules_cfg.get("directory_traversal", {})
        if not cfg.get("enabled"):
            return

        path = parsed["path"]
        match = TRAVERSAL_PATTERNS.search(path)
        if match:
            self._fire_alert(
                rule_name="DIRECTORY_TRAVERSAL",
                parsed=parsed,
                severity=cfg.get("severity", "MEDIUM"),
                mitre=cfg.get("mitre", "T1083"),
                description="Path traversal attempt detected",
                evidence=path,
            )

    def check_scanner(self, parsed, now):
        """Rule SID:100005 — Scanner: known UA match OR rapid path enumeration."""
        cfg = self.rules_cfg.get("scanner", {})
        if not cfg.get("enabled"):
            return

        ip = parsed["ip"]
        threshold = cfg.get("threshold", 100)
        window = cfg.get("window", 60)

        # Method 1: Known scanner User-Agent (instant detection, no threshold)
        raw_line    = (parsed.get("raw") or "").lower()
        user_field  = (parsed.get("user") or "").lower()
        combined    = raw_line + " " + user_field
        ua_blacklist = cfg.get("ua_blacklist", [
            "nikto", "nmap", "masscan", "zgrab", "sqlmap", "dirbuster",
            "gobuster", "wfuzz", "hydra", "metasploit", "nessus",
            "openvas", "burpsuite", "acunetix", "w3af", "appscan",
            "skipfish", "arachni", "commix", "dalfox", "nuclei",
        ])
        for ua in ua_blacklist:
            if ua in combined:
                self._fire_alert(
                    rule_name="SCANNER_DETECTED",
                    parsed=parsed,
                    severity=cfg.get("severity", "MEDIUM"),
                    mitre=cfg.get("mitre", "T1595"),
                    description=f"Known scanner tool detected: {ua}",
                    details=f"UA match: '{ua}' in request",
                    evidence=combined[:120],
                    count=1,
                )
                return  # one alert per request is enough

        # Method 2: Rapid path enumeration (rate-based)
        dq = self.path_times[ip]
        dq.append((now, parsed["path"]))

        while dq and (now - dq[0][0]) > window:
            dq.popleft()

        unique_paths = set(entry[1] for entry in dq)
        if len(unique_paths) >= threshold:
            self._fire_alert(
                rule_name="SCANNER_DETECTED",
                parsed=parsed,
                severity=cfg.get("severity", "MEDIUM"),
                mitre=cfg.get("mitre", "T1595"),
                description=f"{len(unique_paths)} unique paths probed in {window}s",
                details=f"Threshold={threshold} unique paths",
                count=len(unique_paths),
            )

    def check_ddos(self, parsed, now):
        """Rule SID:100006 — DDoS / rate flood."""
        cfg = self.rules_cfg.get("ddos", {})
        if not cfg.get("enabled"):
            return

        ip = parsed["ip"]
        threshold = cfg.get("threshold", 200)
        window = cfg.get("window", 10)

        dq = self.req_times[ip]
        dq.append(now)

        while dq and (now - dq[0]) > window:
            dq.popleft()

        count = len(dq)
        if count >= threshold:
            self._fire_alert(
                rule_name="DDOS_FLOOD",
                parsed=parsed,
                severity=cfg.get("severity", "HIGH"),
                mitre=cfg.get("mitre", "T1498"),
                description=f"{count} requests in {window}s from single IP",
                details=f"Threshold={threshold} requests in {window}s",
                count=count,
            )

    def check_sensitive_file(self, parsed):
        """Rule SID:100007 — Sensitive file access attempt."""
        cfg = self.rules_cfg.get("sensitive_file", {})
        if not cfg.get("enabled"):
            return

        path = parsed["path"]
        match = SENSITIVE_FILES.search(path)
        if match:
            self._fire_alert(
                rule_name="SENSITIVE_FILE_ACCESS",
                parsed=parsed,
                severity=cfg.get("severity", "MEDIUM"),
                mitre=cfg.get("mitre", "T1005"),
                description="Attempt to access sensitive/config file",
                evidence=path,
            )

    # ─── New Enterprise Rules ─────────────────────────────────────────────

    def check_ssh_brute_force(self, parsed, now):
        """Rule SID:100009 — SSH brute force via auth.log (multiple SSH_AUTH 401)."""
        cfg = self.rules_cfg.get("ssh_brute_force", {})
        if not cfg.get("enabled"):
            return
        # Accept both direct auth.log parse AND syslog-wrapped auth.log events
        # (syslog parser captures auth.log lines with log_format='syslog'; SSH failure
        # is identified by '_msg' containing known SSH failure keywords)
        _is_auth_fail = (
            (parsed.get("log_format") == "auth" and parsed.get("_event") == "SSH_FAIL")
            or (
                parsed.get("log_format") == "syslog"
                and any(k in (parsed.get("_msg") or "") for k in
                        ("Failed password", "Invalid user", "authentication failure"))
            )
        )
        if not _is_auth_fail:
            return

        ip        = parsed["ip"]
        threshold = cfg.get("threshold", 5)
        window    = cfg.get("window", 60)

        dq = self.ssh_fail_times[ip]
        dq.append(now)
        while dq and (now - dq[0]) > window:
            dq.popleft()

        count = len(dq)
        if count >= threshold:
            self._fire_alert(
                rule_name="SSH_BRUTE_FORCE",
                parsed=parsed,
                severity=cfg.get("severity", "CRITICAL"),
                mitre=cfg.get("mitre", "T1110.001"),
                description=f"{count} SSH authentication failures in {window}s window",
                details=f"User: {parsed.get('user', '-')} | Threshold={threshold}",
                count=count,
            )

    def check_port_scan(self, parsed, now):
        """Rule SID:100010 — Port scan via firewall DROP log (many DPTs from one IP)."""
        cfg = self.rules_cfg.get("port_scan", {})
        if not cfg.get("enabled"):
            return
        # Accept both direct firewall parse AND syslog-wrapped firewall events
        # (syslog parser wraps kernel UFW/iptables lines in log_format='syslog')
        _msg = parsed.get("_msg") or ""
        _is_fw_block = (
            (parsed.get("log_format") == "firewall" and parsed.get("_action") == "BLOCK")
            or (
                parsed.get("log_format") == "syslog"
                and any(k in _msg for k in ("UFW BLOCK", "UFW DROP", "DPT="))
            )
        )
        if not _is_fw_block:
            return

        ip        = parsed["ip"]
        threshold = cfg.get("threshold", 15)
        window    = cfg.get("window", 30)

        # Extract destination port — prefer parsed field, fall back to _msg regex
        dpt = parsed.get("_dpt", 0)
        if not dpt and _msg:
            import re as _re
            m = _re.search(r"DPT=(\d+)", _msg)
            if m:
                dpt = int(m.group(1))
        dq  = self.fw_src_times[ip]
        dq.append((now, dpt))
        while dq and (now - dq[0][0]) > window:
            dq.popleft()

        unique_ports = set(p for _, p in dq)
        if len(unique_ports) >= threshold:
            self._fire_alert(
                rule_name="PORT_SCAN",
                parsed=parsed,
                severity=cfg.get("severity", "MEDIUM"),
                mitre=cfg.get("mitre", "T1046"),
                description=f"{len(unique_ports)} distinct ports probed in {window}s window",
                details=f"Threshold={threshold} unique ports",
                count=len(unique_ports),
            )

    def check_traffic_deviation(self, ip: str, now: float, datetime_str: str):
        """Rule SID:100011 — Statistical Traffic Deviation: request rate exceeds learned baseline."""
        cfg = self.rules_cfg.get("deviation", {})
        if not cfg.get("enabled"):
            return

        baseline_window   = self.baseline_window
        deviation_factor  = self.deviation_factor
        dq = self.deviation_req_times[ip]
        dq.append(now)
        while dq and (now - dq[0]) > baseline_window:
            dq.popleft()

        # Need at least 30 samples to establish a meaningful baseline
        if len(dq) < 30:
            return

        # Compute baseline: average request rate over first 80% of the window
        split    = int(len(dq) * 0.8)
        baseline_samples = list(dq)[:split]
        recent_samples   = list(dq)[split:]
        if not baseline_samples or not recent_samples:
            return

        baseline_span = baseline_samples[-1] - baseline_samples[0]
        recent_span   = recent_samples[-1] - recent_samples[0]
        if baseline_span <= 0 or recent_span <= 0:
            return

        baseline_rate = len(baseline_samples) / baseline_span   # reqs/sec
        recent_rate   = len(recent_samples)   / recent_span

        if recent_rate >= baseline_rate * deviation_factor:
            self.deviation_baselines[ip] = baseline_rate
            parsed_stub = {
                "ip": ip, "user": "-", "datetime": datetime_str,
                "method": "deviation", "path": "/", "proto": "HTTP",
                "status": 0, "size": 0,
            }
            self._fire_alert(
                rule_name="TRAFFIC_DEVIATION",
                parsed=parsed_stub,
                severity=cfg.get("severity", "MEDIUM"),
                mitre=cfg.get("mitre", "T1499"),
                description=f"Request rate {recent_rate:.1f} req/s exceeds baseline {baseline_rate:.1f} req/s × {deviation_factor}",
                details=f"Baseline window={baseline_window}s | Factor={deviation_factor}",
            )

    # ─── Main Processing ─────────────────────────────────────────────────

    def process_line(self, parsed):
        """Run all enabled detection rules against a parsed log entry."""
        now = time.time()
        ip  = parsed["ip"]

        self.total_reqs[ip] += 1
        self.stats["lines_processed"] += 1

        if ip not in self.first_seen:
            self.first_seen[ip] = parsed["datetime"]

        # Track all requests for Statistical Traffic Deviation baseline
        self.deviation_req_times[ip].append(now)

        self.check_blacklist(parsed)
        self.check_brute_force(parsed, now)
        self.check_sql_injection(parsed)
        self.check_xss(parsed)
        self.check_directory_traversal(parsed)
        self.check_scanner(parsed, now)
        self.check_ddos(parsed, now)
        self.check_sensitive_file(parsed)
        # Enterprise rules
        self.check_ssh_brute_force(parsed, now)
        self.check_port_scan(parsed, now)
        self.check_traffic_deviation(ip, now, parsed["datetime"])

    def print_dashboard(self):
        """Print Wazuh-style real-time dashboard summary."""
        elapsed = time.time() - self.stats["start_time"]
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        alerts_per_min = self.stats["alerts_fired"] / max(elapsed / 60, 0.01)

        print(f"\n{C}{BD}{'=' * 76}")
        print(f"  ##  Simurg IDS - REAL-TIME DASHBOARD")
        print(f"{'=' * 76}{RS}")

        # General stats
        print(f"  {BD}Uptime          :{RS}  {mins}m {secs}s")
        print(f"  {BD}Lines Processed :{RS}  {self.stats['lines_processed']}")
        print(f"  {BD}Alerts Fired    :{RS}  {R}{self.stats['alerts_fired']}{RS}")
        print(f"  {BD}Alerts/min      :{RS}  {Y}{alerts_per_min:.1f}{RS}")
        print(f"  {BD}Unique IPs      :{RS}  {len(self.total_reqs)}")
        print(f"  {BD}Banned IPs      :{RS}  {M}{len(self.banned_ips)}{RS}")

        # Severity distribution
        if self.stats["severity_dist"]:
            print(f"\n  {BD}Threat Distribution:{RS}")
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for sev in sev_order:
                cnt = self.stats["severity_dist"].get(sev, 0)
                if cnt > 0:
                    bar = "=" * min(cnt, 30)
                    sev_color = SEVERITY_COLORS.get(sev, RS)
                    print(f"    {sev_color}{sev:<10}{RS} {bar} {cnt}")

        # Top attackers
        if self.stats["top_attackers"]:
            print(f"\n  {BD}Top Threat Sources:{RS}")
            sorted_attackers = sorted(self.stats["top_attackers"].items(), key=lambda x: -x[1])[:5]
            for ip, cnt in sorted_attackers:
                print(f"    {R}{ip:<20}{RS}  {Y}{cnt}{RS} alerts")

        # Alerts by rule
        if self.total_alerts:
            print(f"\n  {BD}Alerts by Rule (SID):{RS}")
            for rule, cnt in sorted(self.total_alerts.items(), key=lambda x: -x[1]):
                sid = RULE_SIDS.get(rule, "N/A")
                print(f"    {DM}|- {RS} SID:{C}{sid}{RS}  {rule}: {Y}{cnt}{RS}")

        print(f"\n{DR}  Developed by R.A{RS}")
        print(f"{C}{'=' * 76}{RS}\n")


# ─── Main Monitor ────────────────────────────────────────────────────────────

def monitor():
    """Main log monitoring loop."""
    config = load_config()
    log_file = config.get("log_file", "access.log")

    if not os.path.exists(log_file):
        print(f"{R}[!] Error: '{log_file}' not found. Run log_generator.py first.{RS}",
              file=sys.stderr)
        sys.exit(1)

    engine = DetectionEngine(config)

    enabled_rules = sum(1 for r in config["rules"].values() if r.get("enabled"))
    total_rules = len(config["rules"])

    output_cfg  = config.get("output_formats", {})
    active_fmts = [k for k, v in output_cfg.items()
                   if v is True or (isinstance(v, dict) and v.get("enabled"))]

    print(f"\n{C}{BD}{'=' * 76}")
    print(f"  ##  Simurg IDS v3.0 — Enterprise Intrusion Detection Engine")
    print(f"{'=' * 76}{RS}")
    print(f"{DM}    Engine       : Multi-Rule Signature + Correlation + Statistical Traffic Deviation")
    print(f"    Rules loaded : {enabled_rules}/{total_rules} enabled")
    print(f"    Correlation  : 2 rules active (5min window)")
    print(f"    Alert dir    : {config['alert_dir']}/")
    print(f"    Output fmts  : {', '.join(active_fmts) or 'eve_json, alerts_log'}")
    print(f"    Pipeline     : {'Multi-source (file + syslog + stdin)' if _PIPELINE_AVAILABLE else 'Single-file (legacy mode)'}")
    print(f"    Auto-ban     : {'ON' if config['response'].get('auto_ban') else 'OFF'}")
    print(f"    Cooldown     : {config['response'].get('alert_cooldown', 30)}s")
    if config.get("blacklist"):
        print(f"    Blacklist    : {len(config['blacklist'])} IPs")
    print(f"    Press Ctrl+C to stop.{RS}")
    print(f"\n{DR}    Developed by Voice of Ramses{RS}")
    print(f"{DM}{'-' * 76}{RS}\n")

    # Print enabled rules summary with SIDs
    print(f"{BD}  Loaded Detection Rules:{RS}")
    print(f"  {'SID':<12} {'Rule':<28} {'Severity':<12} {'MITRE':<12} {'Class'}")
    print(f"  {'-'*12} {'-'*28} {'-'*12} {'-'*12} {'-'*20}")
    for name, rule in config["rules"].items():
        if rule.get("enabled"):
            sev = rule.get("severity", "N/A")
            mitre = rule.get("mitre", "N/A")
            rule_upper = name.upper()
            sid = RULE_SIDS.get(rule_upper, "N/A")
            if sid == "N/A":
                # Try common mappings
                for key in RULE_SIDS:
                    if name.replace("_", "") in key.lower().replace("_", ""):
                        sid = RULE_SIDS[key]
                        rule_upper = key
                        break
            classification = RULE_CLASSIFICATIONS.get(rule_upper, "unknown")
            sev_color = SEVERITY_COLORS.get(sev, RS)
            print(f"  {C}{sid:<12}{RS} {rule_upper:<28} {sev_color}{sev:<12}{RS} {C}{mitre:<12}{RS} {DM}{classification}{RS}")

    # Correlation rules
    print(f"\n{BD}  Correlation Rules:{RS}")
    print(f"  {C}{'200001':<12}{RS} {'MULTI_VECTOR_ATTACK':<28} {SEVERITY_COLORS['CRITICAL']}{'CRITICAL':<12}{RS} {C}{'TA0001':<12}{RS} {DM}targeted-activity{RS}")
    print(f"  {C}{'200002':<12}{RS} {'RECON_TO_EXPLOIT':<28} {SEVERITY_COLORS['HIGH']}{'HIGH':<12}{RS} {C}{'TA0043':<12}{RS} {DM}targeted-activity{RS}")
    print(f"{DM}{'-' * 76}{RS}\n")

    last_stats_time = time.time()
    stats_interval  = 120

    if _PIPELINE_AVAILABLE and config.get("log_sources"):
        # ── Enterprise mode: multi-source pipeline ─────────────────────────
        print(f"{C}[*] Starting multi-source ingestion pipeline...{RS}")
        pipeline = Pipeline(config, engine, verbose=True)
        pipeline.start()
        try:
            while True:
                time.sleep(5)
                if (time.time() - last_stats_time) >= stats_interval:
                    engine.print_dashboard()
                    pstat = pipeline.status()
                    print(f"  {DM}Pipeline queue depth : {pstat['queue_depth']}{RS}")
                    print(f"  {DM}Pipeline total lines : {pstat['total_processed']}{RS}")
                    last_stats_time = time.time()
        except KeyboardInterrupt:
            print(f"\n{C}[*] Monitoring stopped.{RS}")
            pipeline.stop()
            engine.print_dashboard()
    else:
        # ── Legacy mode: single-file tail (backward compatible) ────────────
        print(f"{C}[*] Starting single-file monitor (legacy mode): {log_file}{RS}")
        if not os.path.exists(log_file):
            print(f"{R}[!] Error: '{log_file}' not found. Run log_generator.py first.{RS}",
                  file=sys.stderr)
            sys.exit(1)

        with open(log_file, "r", encoding="utf-8") as f:
            f.seek(0, 2)
            try:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        if (time.time() - last_stats_time) >= stats_interval:
                            engine.print_dashboard()
                            last_stats_time = time.time()
                        continue

                    line = line.strip()
                    if not line:
                        continue

                    parsed = parse_log_line(line)
                    if parsed is None:
                        continue

                    engine.process_line(parsed)

            except KeyboardInterrupt:
                print(f"\n{C}[*] Monitoring stopped.{RS}")
                engine.print_dashboard()


if __name__ == "__main__":
    monitor()

