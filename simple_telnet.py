"""Simple Telnet client for environments without telnetlib.

This module implements a minimal subset of the standard library's
``telnetlib`` interface required by the TMOHS1 exploit utilities. It is
*not* a full featured Telnet implementation, but provides the small
feature set used by ``utils.py``:

* open(host, port, timeout)
* write(data)
* read_until(expected, timeout)
* read_very_eager()
* mt_interact() for an interactive shell

The code relies only on the standard ``socket`` and ``select`` modules
so it works on Python versions where ``telnetlib`` has been removed.
"""

from __future__ import annotations

import select
import socket
import sys
import threading
import time
from typing import Optional

# Telnet command bytes used for keepalive messages
IAC = b"\xff"  # Interpret As Command
NOP = b"\xf1"  # No Operation


class Telnet:
    """Minimal telnet client with a subset of ``telnetlib``'s API."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 23,
        timeout: Optional[float] = socket._GLOBAL_DEFAULT_TIMEOUT,
    ) -> None:
        self.sock: Optional[socket.socket] = None
        if host:
            self.open(host, port, timeout)

    # Connection handling -------------------------------------------------
    def open(
        self,
        host: str,
        port: int = 23,
        timeout: Optional[float] = socket._GLOBAL_DEFAULT_TIMEOUT,
    ) -> None:
        """Open a connection to *host*:*port*."""
        self.sock = socket.create_connection((host, port), timeout)
        self.sock.setblocking(False)

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    # Sending and receiving -----------------------------------------------
    def write(self, buffer: bytes) -> None:
        if self.sock is None:
            raise OSError("Socket is not connected")
        self.sock.sendall(buffer)

    def _read(self, timeout: Optional[float]) -> bytes:
        if self.sock is None:
            raise OSError("Socket is not connected")
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return b""
        return self.sock.recv(4096)

    def read_until(self, expected: bytes, timeout: Optional[float] = None) -> bytes:
        """Read until *expected* bytes are seen or timeout expires."""
        buf = b""
        end = None if timeout is None else time.time() + timeout
        while True:
            remaining = None if end is None else max(0, end - time.time())
            chunk = self._read(remaining)
            if not chunk:
                break
            buf += chunk
            if expected in buf:
                break
            if end is not None and time.time() >= end:
                break
        return buf

    def read_very_eager(self) -> bytes:
        """Read as much data as is readily available."""
        buf = b""
        while True:
            chunk = self._read(0)
            if not chunk:
                break
            buf += chunk
        return buf

    # Interactive shell ---------------------------------------------------
    def mt_interact(self) -> None:
        """Simple multithreaded interactive shell."""

        def writer() -> None:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                self.write(line.encode())

        def reader() -> None:
            while True:
                data = self.read_very_eager()
                if data:
                    try:
                        sys.stdout.write(data.decode(errors="ignore"))
                        sys.stdout.flush()
                    except Exception:
                        pass
                time.sleep(0.1)

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            writer()
        except KeyboardInterrupt:
            pass


__all__ = ["Telnet", "IAC", "NOP"]

