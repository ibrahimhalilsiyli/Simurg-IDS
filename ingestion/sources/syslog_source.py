#!/usr/bin/env python3
"""
Simurg IDS — UDP Syslog Source (RFC 3164 / RFC 5424)
Listens on a UDP port and feeds incoming syslog messages into the pipeline.
"""

import socket
import threading
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ingestion.parsers import parse_syslog


class SyslogSource(threading.Thread):
    """
    UDP syslog receiver. Binds to host:port, receives datagrams,
    parses them (RFC 3164 or RFC 5424), and pushes to pipeline queue.

    Default port 5140: allows non-root operation (514 requires root on Linux).

    Args:
        queue:      thread-safe queue.Queue to put parsed dicts into.
        host:       Bind address (default "0.0.0.0").
        port:       UDP port (default 5140).
        buf_size:   Datagram buffer size in bytes.
        label:      Source label for parsed records.
    """

    def __init__(self, queue, host: str = "0.0.0.0", port: int = 5140,
                 buf_size: int = 65535, label: str = "syslog_udp"):
        super().__init__(daemon=True, name=f"SyslogSource[{host}:{port}]")
        self.queue    = queue
        self.host     = host
        self.port     = port
        self.buf_size = buf_size
        self.label    = label
        self._stop    = threading.Event()
        self._sock    = None
        self._packets = 0
        self._parsed  = 0
        self._errs    = 0

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    @property
    def packets_received(self):
        return self._packets

    @property
    def records_parsed(self):
        return self._parsed

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(1.0)   # Allow stop event to be checked
        except OSError as e:
            print(f"[SyslogSource] Cannot bind {self.host}:{self.port} — {e}",
                  file=sys.stderr)
            return

        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(self.buf_size)
            except socket.timeout:
                continue
            except OSError:
                break

            self._packets += 1
            try:
                line = data.decode("utf-8", errors="replace").strip()
            except Exception:
                continue

            parsed = parse_syslog(line, source=f"{self.label}:{addr[0]}")
            if parsed:
                # Override IP with sender address if message had no IP
                if parsed["ip"] == "0.0.0.0":
                    parsed["ip"] = addr[0]
                self.queue.put(parsed)
                self._parsed += 1
            else:
                self._errs += 1
