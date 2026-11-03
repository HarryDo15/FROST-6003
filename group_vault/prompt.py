"""Deadline-aware terminal input; no background stdin readers survive expiry."""

from __future__ import annotations

import os
import selectors
import sys
import time
from collections.abc import Callable
from typing import Literal

Decision = Literal["approved", "rejected", "expired"]


def _windows_line(deadline: float, clock: Callable[[], float]) -> str | None:
    import msvcrt

    chars: list[str] = []
    while msvcrt.kbhit():
        msvcrt.getwch()
    while clock() < deadline:
        if not msvcrt.kbhit():
            time.sleep(min(0.05, max(0.0, deadline - clock())))
            continue
        char = msvcrt.getwch()
        if char == "\x03":
            raise KeyboardInterrupt
        if char in ("\x00", "\xe0"):
            msvcrt.getwch()
            continue
        if char in ("\r", "\n"):
            print(flush=True)
            return "".join(chars)
        if char in ("\x04", "\x1a"):
            return ""
        if char == "\b" and chars:
            chars.pop()
            print("\b \b", end="", flush=True)
        elif char.isprintable() and len(chars) < 64:
            chars.append(char)
            print(char, end="", flush=True)
    while msvcrt.kbhit():
        msvcrt.getwch()
    return None


def _flush_terminal(descriptor: int) -> None:
    if sys.platform != "win32":
        import termios

        termios.tcflush(descriptor, termios.TCIFLUSH)


def _posix_line(deadline: float, clock: Callable[[], float]) -> str | None:
    descriptor = sys.stdin.fileno()
    _flush_terminal(descriptor)
    buffer = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while clock() < deadline:
                if not selector.select(max(0.0, deadline - clock())):
                    continue
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    return ""
                buffer.extend(chunk)
                if b"\n" in buffer:
                    return bytes(buffer).split(b"\n", 1)[0].decode("utf-8", errors="replace")
                if len(buffer) > 4096:
                    return ""
        return None
    finally:
        # Clear unfinished or queued lines so late input cannot approve another request.
        _flush_terminal(descriptor)


def timed_approval(deadline: float, *, clock: Callable[[], float] = time.monotonic) -> Decision:
    if clock() >= deadline:
        return "expired"
    if not sys.stdin.isatty():
        print("No interactive terminal. Use --auto-approve for unattended operation.")
        return "rejected"
    print("Approve? [y/N] ", end="", flush=True)
    answer = _windows_line(deadline, clock) if os.name == "nt" else _posix_line(deadline, clock)
    if answer is None or clock() >= deadline:
        print(flush=True)
        return "expired"
    return "approved" if answer.strip().casefold() in ("y", "yes") else "rejected"
