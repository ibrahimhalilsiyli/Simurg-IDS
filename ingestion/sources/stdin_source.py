#!/usr/bin/env python3
"""
Simurg IDS — Stdin Source
Reads log lines from stdin (pipe mode). Useful for:
    tail -f /var/log/nginx/access.log | python Simurg_daemon.py --stdin
    cat access.log | python Simurg_daemon.py --stdin
"""

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ingestion.parsers import parse_auto


class StdinSource(threading.Thread):
    """
    Background thread that reads log lines from sys.stdin and
    pushes parsed records into the pipeline queue.

    Args:
        queue:  thread-safe queue.Queue to put parsed dicts into.
        fmt:    Format hint ("clf", "json", "syslog", "auth", "firewall").
        label:  Source label for parsed records.
    """

    def __init__(self, queue, fmt: str = "clf", label: str = "stdin"):
        super().__init__(daemon=True, name="StdinSource")
        self.queue  = queue
        self.fmt    = fmt
        self.label  = label
        self._stop  = threading.Event()
        self._lines = 0

    def stop(self):
        self._stop.set()

    @property
    def lines_read(self):
        return self._lines

    def run(self):
        try:
            for raw_line in sys.stdin:
                if self._stop.is_set():
                    break
                line = raw_line.rstrip("\n\r")
                if not line:
                    continue
                parsed = parse_auto(line, hint=self.fmt, source=self.label)
                if parsed:
                    self.queue.put(parsed)
                    self._lines += 1
        except (EOFError, KeyboardInterrupt):
            pass
