#!/usr/bin/env python3
"""
Simurg IDS v3.0 — Interactive Launcher
Main menu for log monitoring, attack simulation, alert review, IP banning, and daemon control.
"""

import os
import sys
import subprocess
import time

# Fix for Windows encoding issues with ANSI banners
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        # Fallback for older Python versions
        import codecs
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
YELLOW  = "\033[93m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
   ███████╗██╗███╗   ███╗██╗   ██╗██████╗  ██████╗
   ██╔════╝██║████╗ ████║██║   ██║██╔══██╗██╔════╝
   ███████╗██║██╔████╔██║██║   ██║██████╔╝██║  ███╗
   ╚════██║██║██║╚██╔╝██║██║   ██║██╔══██╗██║   ██║
   ███████║██║██║ ╚═╝ ██║╚██████╔╝██║  ██║╚██████╔╝
   ╚══════╝╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
{RESET}{DIM}   Intrusion Detection System v3.0 — Enterprise Edition{RESET}
"""

ALERTS_FILE = "alerts.log"
BANNED_IPS_FILE = ".banned_ips"  # Tracks auto-banned IPs with unban times


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_menu():
    clear_screen()
    print(BANNER)
    print(f"  {BOLD}{'─' * 55}{RESET}")
    print(f"  {GREEN}[1]{RESET} Start Log Monitor  (multi-source pipeline)")
    print(f"  {GREEN}[2]{RESET} Start Attack Simulation (Test Generator)")
    print(f"  {GREEN}[3]{RESET} View Alert Log (alerts/alerts.log)")
    print(f"  {GREEN}[4]{RESET} Ban an IP Address (10 min — iptables)")
    print(f"  {GREEN}[5]{RESET} Clear All iptables Bans")
    print(f"  {GREEN}[6]{RESET} Show Currently Banned IPs")
    print(f"  {CYAN}[7]{RESET} Daemon / Service Control")
    print(f"  {CYAN}[8]{RESET} Show Pipeline & Output Format Status")
    print(f"  {RED}[0]{RESET} Exit")
    print(f"  {BOLD}{'─' * 55}{RESET}")


def start_monitor():
    clear_screen()
    print(f"\n  {CYAN}[*] Launching Log Monitor (Enterprise Pipeline)...{RESET}")
    print(f"  {DIM}    Reads from all sources in config.json → log_sources{RESET}")
    print(f"  {DIM}    Press Ctrl+C to stop and return to menu.{RESET}\n")
    time.sleep(0.5)
    try:
        subprocess.run([sys.executable, "log_monitor.py"])
    except KeyboardInterrupt:
        pass
    input(f"\n  {DIM}Press Enter to return to menu...{RESET}")


def start_generator():
    clear_screen()
    print(f"\n  {CYAN}[*] Launching Attack Simulator...{RESET}")
    print(f"  {DIM}    Press Ctrl+C to stop and return to menu.{RESET}\n")
    time.sleep(0.5)
    try:
        subprocess.run([sys.executable, "log_generator.py"])
    except KeyboardInterrupt:
        pass
    input(f"\n  {DIM}Press Enter to return to menu...{RESET}")


def view_alerts():
    clear_screen()
    print(f"\n  {CYAN}{BOLD}═══ ALERT LOG ═══{RESET}\n")

    alerts_file = os.path.join("alerts", "alerts.log")
    if not os.path.exists(alerts_file):
        # Also check legacy location
        alerts_file = "alerts.log"
    if not os.path.exists(alerts_file):
        print(f"  {YELLOW}[!] No alerts.log found. No attacks detected yet.{RESET}")
    else:
        with open(alerts_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            print(f"  {GREEN}[✓] Alert log is empty. No attacks detected.{RESET}")
        else:
            lines = content.split("\n")
            print(f"  {YELLOW}Total alerts: {len(lines)}{RESET}\n")
            display = lines[-30:] if len(lines) > 30 else lines
            if len(lines) > 30:
                print(f"  {DIM}... showing last 30 of {len(lines)} alerts ...{RESET}\n")
            for line in display:
                print(f"  {RED}{line}{RESET}")

    # Also show EVE JSON count
    eve_file = os.path.join("alerts", "eve.json")
    if os.path.exists(eve_file):
        with open(eve_file, "r", encoding="utf-8") as f:
            eve_count = sum(1 for l in f if l.strip())
        print(f"\n  {DIM}EVE JSON events: {eve_count}  ({eve_file}){RESET}")

    print()
    input(f"  {DIM}Press Enter to return to menu...{RESET}")


def ban_ip():
    clear_screen()
    print(f"\n  {CYAN}{BOLD}═══ BAN IP ADDRESS ═══{RESET}\n")

    if os.name == "nt":
        print(f"  {YELLOW}[!] iptables is not available on Windows.{RESET}")
        print(f"  {DIM}    This feature requires Linux with root privileges.{RESET}")
        input(f"\n  {DIM}Press Enter to return to menu...{RESET}")
        return

    ip = input(f"  {BOLD}Enter IP to ban (10 min): {RESET}").strip()
    if not ip:
        return

    duration = 600  # 10 minutes in seconds
    print(f"\n  {YELLOW}[*] Banning {ip} for 10 minutes...{RESET}")

    try:
        # Add iptables DROP rule
        result = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  {RED}[✗] Failed to ban: {result.stderr.strip()}{RESET}")
            print(f"  {DIM}    Make sure you are running as root.{RESET}")
        else:
            print(f"  {GREEN}[✓] {ip} has been BANNED (DROP) via iptables.{RESET}")

            # Schedule automatic unban
            unban_time = time.time() + duration
            with open(BANNED_IPS_FILE, "a", encoding="utf-8") as f:
                f.write(f"{ip}|{unban_time}\n")

            # Try to schedule unban via 'at' command or background process
            try:
                subprocess.Popen(
                    ["bash", "-c",
                     f"sleep {duration} && sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null "
                     f"&& echo '[AutoUnban] {ip} unbanned' >> alerts.log"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                print(f"  {DIM}    Auto-unban scheduled in 10 minutes.{RESET}")
            except Exception:
                print(f"  {YELLOW}    [!] Could not schedule auto-unban. Manual unban may be needed.{RESET}")

    except FileNotFoundError:
        print(f"  {RED}[✗] sudo/iptables not found.{RESET}")

    input(f"\n  {DIM}Press Enter to return to menu...{RESET}")


def clear_bans():
    clear_screen()
    print(f"\n  {CYAN}{BOLD}═══ CLEAR ALL IPTABLES BANS ═══{RESET}\n")

    if os.name == "nt":
        print(f"  {YELLOW}[!] iptables is not available on Windows.{RESET}")
        print(f"  {DIM}    This feature requires Linux with root privileges.{RESET}")
        input(f"\n  {DIM}Press Enter to return to menu...{RESET}")
        return

    confirm = input(f"  {YELLOW}Are you sure? This will flush all INPUT rules. (y/N): {RESET}").strip().lower()
    if confirm != "y":
        print(f"  {DIM}    Cancelled.{RESET}")
        input(f"\n  {DIM}Press Enter to return to menu...{RESET}")
        return

    try:
        result = subprocess.run(
            ["sudo", "iptables", "-F", "INPUT"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"  {GREEN}[✓] All INPUT rules flushed successfully.{RESET}")
            # Clear banned IPs file
            if os.path.exists(BANNED_IPS_FILE):
                os.remove(BANNED_IPS_FILE)
        else:
            print(f"  {RED}[✗] Failed: {result.stderr.strip()}{RESET}")
    except FileNotFoundError:
        print(f"  {RED}[✗] sudo/iptables not found.{RESET}")

    input(f"\n  {DIM}Press Enter to return to menu...{RESET}")


def show_banned():
    clear_screen()
    print(f"\n  {CYAN}{BOLD}═══ CURRENTLY BANNED IPs ═══{RESET}\n")

    if os.name == "nt":
        # On Windows, just show the tracked file
        if not os.path.exists(BANNED_IPS_FILE):
            print(f"  {GREEN}[✓] No IPs are currently banned.{RESET}")
        else:
            with open(BANNED_IPS_FILE, "r", encoding="utf-8") as f:
                lines = f.read().strip().split("\n")
            now = time.time()
            active = []
            for line in lines:
                if "|" in line:
                    ip, unban = line.split("|", 1)
                    remaining = float(unban) - now
                    if remaining > 0:
                        mins = int(remaining // 60)
                        secs = int(remaining % 60)
                        active.append((ip, f"{mins}m {secs}s"))
            if active:
                print(f"  {'IP Address':<20} {'Time Remaining':<15}")
                print(f"  {'─' * 35}")
                for ip, rem in active:
                    print(f"  {RED}{ip:<20}{RESET} {YELLOW}{rem}{RESET}")
            else:
                print(f"  {GREEN}[✓] No IPs are currently banned.{RESET}")
    else:
        # On Linux, query iptables directly
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                drop_lines = [l for l in output.split("\n") if "DROP" in l]
                if drop_lines:
                    print(f"  {YELLOW}Active DROP rules in INPUT chain:{RESET}\n")
                    for line in drop_lines:
                        print(f"  {RED}{line}{RESET}")
                else:
                    print(f"  {GREEN}[✓] No IPs are currently banned.{RESET}")
            else:
                print(f"  {RED}[✗] Could not query iptables: {result.stderr.strip()}{RESET}")
        except FileNotFoundError:
            print(f"  {RED}[✗] sudo/iptables not found.{RESET}")

    print()
    input(f"  {DIM}Press Enter to return to menu...{RESET}")


def start_daemon():
    """Open daemon.py in a subprocess for daemon control commands."""
    clear_screen()
    print(f"\n  {CYAN}{BOLD}═══ DAEMON / SERVICE CONTROL ═══{RESET}\n")
    print(f"  {DIM}Manage Simurg as a background daemon with crash recovery.{RESET}\n")
    print(f"  {GREEN}[1]{RESET} Start daemon (background + watchdog)")
    print(f"  {GREEN}[2]{RESET} Stop daemon")
    print(f"  {GREEN}[3]{RESET} Restart daemon")
    print(f"  {GREEN}[4]{RESET} Daemon status")
    print(f"  {GREEN}[5]{RESET} Install as system service (systemd / NSSM)")
    print(f"  {GREEN}[6]{RESET} Uninstall service")
    print(f"  {RED}[0]{RESET} Back")
    print()
    choice = input(f"  {BOLD}Select: {RESET}").strip()
    cmds = {"1": "start", "2": "stop", "3": "restart",
            "4": "status", "5": "install", "6": "uninstall"}
    if choice in cmds:
        try:
            subprocess.run([sys.executable, "daemon.py", cmds[choice]])
        except Exception as e:
            print(f"  {RED}[✗] Error: {e}{RESET}")
    input(f"\n  {DIM}Press Enter to return to menu...{RESET}")


def show_pipeline_status():
    """Display current pipeline configuration and output format status."""
    clear_screen()
    import json as _json
    print(f"\n  {CYAN}{BOLD}═══ PIPELINE & OUTPUT STATUS ═══{RESET}\n")

    cfg_file = "config.json"
    if not os.path.exists(cfg_file):
        print(f"  {YELLOW}[!] config.json not found.{RESET}")
        input(f"\n  {DIM}Press Enter to return...{RESET}")
        return

    with open(cfg_file, "r", encoding="utf-8") as f:
        cfg = _json.load(f)

    # Sources
    sources = cfg.get("log_sources", [])
    if sources:
        print(f"  {BOLD}Ingestion Sources ({len(sources)}):{RESET}")
        for src in sources:
            kind  = src.get("type", "file")
            label = src.get("label") or src.get("path") or f"{src.get('host')}:{src.get('port')}"
            fmt   = src.get("format", "")
            extra = f"  format={fmt}" if fmt else ""
            print(f"    {GREEN}●{RESET}  [{kind.upper():<6}] {label}{extra}")
    else:
        log_file = cfg.get("log_file", "access.log")
        print(f"  {BOLD}Ingestion Source:{RESET}")
        print(f"    {GREEN}●{RESET}  [FILE  ] {log_file}  (legacy single-file mode)")

    # Output formats
    out_cfg = cfg.get("output_formats", {})
    if out_cfg:
        print(f"\n  {BOLD}Output Formats:{RESET}")
        fmt_descriptions = {
            "eve_json":       "EVE JSON   (Suricata / SIEM universal)",
            "alerts_log":     "Alerts.log (Wazuh-style text)",
            "ecs_json":       "ECS JSON   (Elastic Common Schema / Kibana)",
            "cef":            "CEF        (ArcSight / IBM QRadar)",
            "syslog_forward": "Syslog Fwd (remote UDP syslog server)",
        }
        for key, desc in fmt_descriptions.items():
            val = out_cfg.get(key, False)
            if isinstance(val, dict):
                enabled = val.get("enabled", False)
                detail  = f" → {val.get('host')}:{val.get('port')}" if enabled else ""
            else:
                enabled = bool(val)
                detail  = ""
            status_sym = f"{GREEN}✓ ON {RESET}" if enabled else f"{DIM}✗ off{RESET}"
            print(f"    {status_sym}  {desc}{detail}")

    # Alert dir contents
    alert_dir = cfg.get("alert_dir", "alerts")
    print(f"\n  {BOLD}Alert Directory ({alert_dir}/):{RESET}")
    if os.path.isdir(alert_dir):
        files = os.listdir(alert_dir)
        for fname in sorted(files):
            fpath = os.path.join(alert_dir, fname)
            size  = os.path.getsize(fpath)
            lines = sum(1 for _ in open(fpath, "r", encoding="utf-8", errors="ignore"))
            print(f"    {DIM}{fname:<20}{RESET}  {lines} lines  ({size:,} bytes)")
    else:
        print(f"    {DIM}(not created yet — start the monitor first){RESET}")

    print()
    input(f"  {DIM}Press Enter to return to menu...{RESET}")


def main():
    try:
        while True:
            print_menu()
            choice = input(f"  {BOLD}Select option: {RESET}").strip()

            if choice == "1":
                start_monitor()
            elif choice == "2":
                start_generator()
            elif choice == "3":
                view_alerts()
            elif choice == "4":
                ban_ip()
            elif choice == "5":
                clear_bans()
            elif choice == "6":
                show_banned()
            elif choice == "7":
                start_daemon()
            elif choice == "8":
                show_pipeline_status()
            elif choice == "0":
                clear_screen()
                print(f"\n  {CYAN}[*] Simurg IDS shutting down. Stay safe.{RESET}\n")
                break
            else:
                print(f"  {RED}[!] Invalid option.{RESET}")
                time.sleep(0.8)

    except KeyboardInterrupt:
        clear_screen()
        print(f"\n  {CYAN}[*] Simurg IDS shutting down. Stay safe.{RESET}\n")


if __name__ == "__main__":
    main()

