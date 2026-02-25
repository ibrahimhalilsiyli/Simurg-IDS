#!/usr/bin/env python3
"""
Simurg IDS — Ingestion Pipeline
Central coordinator that starts all configured sources as threads,
drains the shared queue, and feeds parsed records into the DetectionEngine.

Usage:
    from ingestion.pipeline import Pipeline
    pipeline = Pipeline(config, engine)
    pipeline.start()
    pipeline.join()   # blocks until stopped
"""

import queue
import time
import threading
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ingestion.sources.file_source   import FileSource
from ingestion.sources.syslog_source import SyslogSource
from ingestion.sources.stdin_source  import StdinSource


class Pipeline:
    """
    Multi-source ingestion pipeline.

    Reads the `log_sources` array from config and starts one background
    thread per source. A drainer thread pulls parsed records from the
    shared queue and passes them to the DetectionEngine.

    Supported source types:
        file     — tail a log file (with rotation support)
        syslog   — UDP syslog listener (RFC 3164 / 5424)
        stdin    — pipe from stdin

    Config example:
        "log_sources": [
            {"type": "file",   "path": "access.log",       "format": "clf"},
            {"type": "file",   "path": "/var/log/auth.log", "format": "auth"},
            {"type": "syslog", "host": "0.0.0.0",           "port": 5140},
            {"type": "stdin",  "format": "clf"}
        ]
    """

    def __init__(self, config: dict, engine, verbose: bool = True):
        self.config   = config
        self.engine   = engine
        self.verbose  = verbose
        self._q       = queue.Queue(maxsize=50_000)
        self._sources = []
        self._drainer = None
        self._stop    = threading.Event()
        self._total   = 0

    # ── Source factory ────────────────────────────────────────────────────────

    def _build_sources(self):
        sources_cfg = self.config.get("log_sources", [])

        # Fallback: if no log_sources defined, use legacy log_file key
        if not sources_cfg:
            log_file = self.config.get("log_file", "access.log")
            sources_cfg = [{"type": "file", "path": log_file, "format": "clf"}]

        for src in sources_cfg:
            kind = src.get("type", "file").lower()

            if kind == "file":
                path = src.get("path", "access.log")
                fmt  = src.get("format", "clf")
                label = src.get("label", path)
                s = FileSource(path=path, queue=self._q, fmt=fmt, label=label)
                self._sources.append(s)
                if self.verbose:
                    print(f"  [Pipeline] File source: {path}  format={fmt}")

            elif kind == "syslog":
                host  = src.get("host", "0.0.0.0")
                port  = src.get("port", 5140)
                label = src.get("label", "syslog_udp")
                s = SyslogSource(queue=self._q, host=host, port=port, label=label)
                self._sources.append(s)
                if self.verbose:
                    print(f"  [Pipeline] Syslog UDP source: {host}:{port}")

            elif kind == "stdin":
                fmt   = src.get("format", "clf")
                label = src.get("label", "stdin")
                s = StdinSource(queue=self._q, fmt=fmt, label=label)
                self._sources.append(s)
                if self.verbose:
                    print(f"  [Pipeline] Stdin source  format={fmt}")

            else:
                print(f"  [Pipeline] Unknown source type '{kind}' — skipped",
                      file=sys.stderr)

    # ── Drainer thread ────────────────────────────────────────────────────────

    def _drain_loop(self):
        """Pull records from queue and pass to DetectionEngine."""
        while not self._stop.is_set():
            try:
                record = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.engine.process_line(record)
                self._total += 1
            except Exception as e:
                pass   # Gracefully skip malformed records

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Build and start all sources + drainer thread."""
        self._build_sources()
        self._drainer = threading.Thread(
            target=self._drain_loop,
            daemon=True,
            name="PipelineDrainer"
        )
        self._drainer.start()
        for src in self._sources:
            src.start()

    def stop(self):
        """Signal all threads to stop."""
        self._stop.set()
        for src in self._sources:
            src.stop()

    def join(self, timeout: float = None):
        """Block until drainer exits (pipeline fully stopped)."""
        if self._drainer:
            self._drainer.join(timeout=timeout)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Return pipeline status for dashboard display."""
        source_stats = []
        for s in self._sources:
            info = {"name": s.name, "alive": s.is_alive()}
            if hasattr(s, "lines_read"):
                info["lines"] = s.lines_read
            if hasattr(s, "packets_received"):
                info["packets"] = s.packets_received
                info["parsed"]  = s.records_parsed
            source_stats.append(info)

        return {
            "queue_depth": self._q.qsize(),
            "total_processed": self._total,
            "sources": source_stats,
        }
