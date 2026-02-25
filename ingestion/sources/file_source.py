#!/usr/bin/env python3
"""
Simurg IDS — File Source
Tails one or more log files concurrently, supports file rotation detection.
"""

import os
import sys
import time
import threading
from pathlib import Path

# Make sibling imports work when run directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ingestion.parsers import parse_auto


class FileSource(threading.Thread):
    """
    Background thread that tails a log file and pushes parsed records
    into a shared queue. Handles file rotation (inode change / truncation).

    Args:
        path:     Path to the log file.
        queue:    thread-safe queue.Queue to put parsed dicts into.
        fmt:      Format hint  ("clf", "json", "syslog", "auth", "firewall").
        label:    Source label embedded in every parsed record.
        poll_ms:  How often to poll for new data (milliseconds).
    """

    def __init__(self, path: str, queue, fmt: str = "clf",
                 label: str = None, poll_ms: int = 100):
        super().__init__(daemon=True, name=f"FileSource[{path}]")
        self.path     = path
        self.queue    = queue
        self.fmt      = fmt
        self.label    = label or os.path.basename(path)
        self.poll_ms  = poll_ms / 1000.0
        self._stop    = threading.Event()
        self._inode   = None
        self._lines_read = 0
        self._errs       = 0

    def stop(self):
        self._stop.set()

    @property
    def lines_read(self):
        return self._lines_read

    def run(self):
        while not self._stop.is_set():
            if not os.path.exists(self.path):
                # Wait for file to appear
                time.sleep(1.0)
                continue

            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                    # Seek to end on first open (tail -f behavior)
                    fh.seek(0, 2)
                    self._inode = os.fstat(fh.fileno()).st_ino

                    while not self._stop.is_set():
                        line = fh.readline()

                        if not line:
                            time.sleep(self.poll_ms)

                            # Check for rotation (new inode / truncation)
                            try:
                                stat = os.stat(self.path)
                                if stat.st_ino != self._inode or stat.st_size < fh.tell():
                                    # File rotated — reopen
                                    break
                            except OSError:
                                break
                            continue

                        line = line.rstrip("\n\r")
                        if not line:
                            continue

                        parsed = parse_auto(line, hint=self.fmt, source=self.label)
                        if parsed:
                            self.queue.put(parsed)
                            self._lines_read += 1

            except OSError as e:
                self._errs += 1
                time.sleep(2.0)
