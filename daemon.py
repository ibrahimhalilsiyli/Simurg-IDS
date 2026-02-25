#!/usr/bin/env python3
"""
Simurg IDS — Daemon / Service Mode
Cross-platform background process manager with crash-recovery watchdog.

Commands:
    python daemon.py start        — Start Simurg in background
    python daemon.py stop         — Stop running daemon
    python daemon.py restart      — Restart daemon
    python daemon.py status       — Show daemon status
    python daemon.py install      — Generate & optionally install systemd unit (Linux)
    python daemon.py uninstall    — Remove systemd unit (Linux)

Linux:  Uses PID file + subprocess watchdog. Generates systemd unit file.
Windows: Runs as background subprocess. Prints NSSM/sc.exe instructions.
"""

import os
import sys
import time
import signal
import subprocess
import textwrap
from pathlib import Path

# ─── Config ──────────────────────────────────────────────────────────────────

BASE_DIR      = Path(__file__).resolve().parent
MONITOR_SCRIPT = BASE_DIR / "log_monitor.py"
PID_FILE      = BASE_DIR / "Simurg.pid"
LOG_FILE      = BASE_DIR / "daemon.log"
SERVICE_FILE  = BASE_DIR / "Simurg.service"

WATCHDOG_INTERVAL  = 5   # Seconds between watchdog checks
MAX_RESTART_COUNT  = 10  # Max consecutive restarts before giving up
RESTART_BACKOFF    = [1, 2, 5, 10, 30]  # Backoff seconds per restart

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ─── PID File Management ─────────────────────────────────────────────────────

def _write_pid(pid: int):
    PID_FILE.write_text(str(pid), encoding="utf-8")


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def _remove_pid():
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


def _is_running(pid: int) -> bool:
    """Check if a process with given PID is alive."""
    if os.name == "nt":
        # Windows: tasklist check
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True
            )
            return str(pid) in result.stdout
        except Exception:
            return False
    else:
        # POSIX: send signal 0
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False


# ─── Watchdog ────────────────────────────────────────────────────────────────

def _watchdog():
    """
    Supervisor loop: starts log_monitor.py as a subprocess and restarts it
    if it crashes. Writes watchdog's own PID to PID_FILE.
    """
    _write_pid(os.getpid())

    log_fd = open(LOG_FILE, "a", encoding="utf-8", buffering=1)

    def _log(msg: str):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        log_fd.write(f"[{ts}] {msg}\n")
        log_fd.flush()

    _log(f"Simurg watchdog started (PID {os.getpid()})")
    restart_count = 0
    proc = None

    def _sigterm_handler(signum, frame):
        _log("SIGTERM received — shutting down")
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        _remove_pid()
        log_fd.close()
        sys.exit(0)

    if os.name != "nt":
        signal.signal(signal.SIGTERM, _sigterm_handler)

    while restart_count <= MAX_RESTART_COUNT:
        _log(f"Starting log_monitor.py (attempt {restart_count + 1})")
        try:
            proc = subprocess.Popen(
                [sys.executable, str(MONITOR_SCRIPT)],
                stdout=log_fd,
                stderr=log_fd,
                cwd=str(BASE_DIR),
            )
        except Exception as e:
            _log(f"Failed to start monitor: {e}")
            break

        # Wait for process to exit
        exit_code = proc.wait()
        _log(f"log_monitor.py exited with code {exit_code}")

        if exit_code == 0:
            _log("Clean exit — watchdog stopping.")
            break

        restart_count += 1
        if restart_count > MAX_RESTART_COUNT:
            _log(f"Exceeded {MAX_RESTART_COUNT} restarts — giving up.")
            break

        backoff = RESTART_BACKOFF[min(restart_count - 1, len(RESTART_BACKOFF) - 1)]
        _log(f"Restarting in {backoff}s...")
        time.sleep(backoff)

    _remove_pid()
    log_fd.close()


# ─── Commands ────────────────────────────────────────────────────────────────

def cmd_start():
    pid = _read_pid()
    if pid and _is_running(pid):
        print(f"{YELLOW}[!] Simurg daemon already running (PID {pid}){RESET}")
        return

    print(f"{CYAN}[*] Starting Simurg daemon...{RESET}")

    if os.name == "nt":
        # On Windows: spawn watchdog as a detached subprocess
        proc = subprocess.Popen(
            [sys.executable, __file__, "_watchdog"],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP |
                          subprocess.DETACHED_PROCESS,
            stdout=open(LOG_FILE, "a"),
            stderr=subprocess.STDOUT,
            cwd=str(BASE_DIR),
        )
        time.sleep(1)
        print(f"{GREEN}[✓] Daemon started (PID {proc.pid}){RESET}")
        print(f"{DIM}    Logs: {LOG_FILE}{RESET}")
    else:
        # POSIX: double-fork to properly daemonize
        pid = os.fork()
        if pid > 0:
            sys.exit(0)      # Parent exits

        os.setsid()          # New session

        pid2 = os.fork()
        if pid2 > 0:
            sys.exit(0)      # First fork exits

        # Grandchild: the actual daemon
        sys.stdout.flush()
        sys.stderr.flush()

        with open("/dev/null", "rb", 0) as f:
            os.dup2(f.fileno(), sys.stdin.fileno())

        _watchdog()


def cmd_stop():
    pid = _read_pid()
    if not pid:
        print(f"{YELLOW}[!] No PID file found — daemon may not be running.{RESET}")
        return
    if not _is_running(pid):
        print(f"{YELLOW}[!] Process {pid} not found — cleaning up stale PID file.{RESET}")
        _remove_pid()
        return

    print(f"{CYAN}[*] Stopping Simurg daemon (PID {pid})...{RESET}")
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True,
                           capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception as e:
        print(f"{RED}[✗] Failed to stop: {e}{RESET}")
        return

    # Wait for it to exit
    for _ in range(20):
        time.sleep(0.5)
        if not _is_running(pid):
            break

    _remove_pid()
    print(f"{GREEN}[✓] Daemon stopped.{RESET}")


def cmd_restart():
    cmd_stop()
    time.sleep(1)
    cmd_start()


def cmd_status():
    pid = _read_pid()
    print(f"\n  {BOLD}Simurg IDS Daemon Status{RESET}")
    print(f"  {'─' * 40}")
    if pid and _is_running(pid):
        print(f"  Status  : {GREEN}{BOLD}RUNNING{RESET}")
        print(f"  PID     : {CYAN}{pid}{RESET}")
    elif pid:
        print(f"  Status  : {RED}STALE PID (process not found){RESET}")
        print(f"  PID     : {pid}")
    else:
        print(f"  Status  : {YELLOW}STOPPED{RESET}")

    if LOG_FILE.exists():
        print(f"  Log     : {LOG_FILE}")
        # Show last 5 lines of daemon log
        lines = LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            print(f"\n  {DIM}Last log entries:{RESET}")
            for line in lines[-5:]:
                print(f"  {DIM}{line}{RESET}")
    print()


# ─── Systemd Unit File ────────────────────────────────────────────────────────

SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=Simurg IDS — Intrusion Detection System
Documentation=https://github.com/yourorg/Simurg
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
User=Simurg
Group=Simurg
WorkingDirectory={work_dir}
ExecStart={python} {monitor_script}
Restart=always
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=Simurg
KillMode=mixed
TimeoutStopSec=10s

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths={work_dir}

[Install]
WantedBy=multi-user.target
"""


def cmd_install():
    """Generate systemd service unit file (Linux only) or print Windows instructions."""
    if os.name == "nt":
        print(f"\n  {CYAN}{BOLD}Windows Service Installation{RESET}")
        print(f"  {'─' * 50}")
        print(f"  Option A — NSSM (Non-Sucking Service Manager):")
        print(f"  {DIM}  1. Download nssm from https://nssm.cc{RESET}")
        print(f"  {DIM}  2. nssm install Simurg {sys.executable} {MONITOR_SCRIPT}{RESET}")
        print(f"  {DIM}  3. nssm start Simurg{RESET}")
        print()
        print(f"  Option B — sc.exe (basic, no auto-restart):")
        print(f"  {DIM}  sc create Simurg binPath= \"{sys.executable} {MONITOR_SCRIPT}\"{RESET}")
        print(f"  {DIM}  sc start Simurg{RESET}")
        print()
        return

    unit = SYSTEMD_UNIT_TEMPLATE.format(
        work_dir=str(BASE_DIR),
        python=sys.executable,
        monitor_script=str(MONITOR_SCRIPT),
    )

    SERVICE_FILE.write_text(unit, encoding="utf-8")
    print(f"\n  {GREEN}[✓] systemd unit file written: {SERVICE_FILE}{RESET}")
    print(f"\n  To install and enable the service:")
    print(f"  {DIM}  sudo cp {SERVICE_FILE} /etc/systemd/system/{RESET}")
    print(f"  {DIM}  sudo useradd -r -s /sbin/nologin Simurg{RESET}")
    print(f"  {DIM}  sudo chown -R simurg:Simurg {BASE_DIR}{RESET}")
    print(f"  {DIM}  sudo systemctl daemon-reload{RESET}")
    print(f"  {DIM}  sudo systemctl enable Simurg{RESET}")
    print(f"  {DIM}  sudo systemctl start Simurg{RESET}")
    print(f"  {DIM}  sudo systemctl status Simurg{RESET}\n")


def cmd_uninstall():
    if os.name == "nt":
        print(f"  {DIM}  sc stop Simurg{RESET}")
        print(f"  {DIM}  sc delete Simurg{RESET}")
        return

    print(f"\n  To uninstall the systemd service:")
    print(f"  {DIM}  sudo systemctl stop Simurg{RESET}")
    print(f"  {DIM}  sudo systemctl disable Simurg{RESET}")
    print(f"  {DIM}  sudo rm /etc/systemd/system/Simurg.service{RESET}")
    print(f"  {DIM}  sudo systemctl daemon-reload{RESET}\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

COMMANDS = {
    "start":     cmd_start,
    "stop":      cmd_stop,
    "restart":   cmd_restart,
    "status":    cmd_status,
    "install":   cmd_install,
    "uninstall": cmd_uninstall,
    "_watchdog": _watchdog,  # Internal: called by Windows Popen branch
}

USAGE = f"""
  {CYAN}{BOLD}Simurg IDS — Daemon Control{RESET}

  {BOLD}Usage:{RESET}  python daemon.py <command>

  {BOLD}Commands:{RESET}
    {GREEN}start{RESET}      Start Simurg as a background daemon (with watchdog)
    {GREEN}stop{RESET}       Stop the running daemon
    {GREEN}restart{RESET}    Restart the daemon
    {GREEN}status{RESET}     Show daemon status and recent log entries
    {GREEN}install{RESET}    Generate systemd unit file (Linux) / NSSM instructions (Windows)
    {GREEN}uninstall{RESET}  Show uninstall instructions
"""


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(USAGE)
        sys.exit(1)

    COMMANDS[sys.argv[1]]()


if __name__ == "__main__":
    main()
