"""Terminal polish: ANSI colour and progress rendering, with no dependencies.

Colour follows the NO_COLOR convention (https://no-color.org) and is disabled
for piped output and ``TERM=dumb``. Machine-readable stdout (the JSON result
contract) is never coloured.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import TextIO

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
RED = "\x1b[31m"
CYAN = "\x1b[36m"


def color_enabled(stream: TextIO | None = None) -> bool:
    stream = stream or sys.stderr
    if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def colorize(text: str, *codes: str, enabled: bool | None = None) -> str:
    if enabled is None:
        enabled = color_enabled()
    if not enabled or not codes:
        return text
    return "".join(codes) + text + RESET


def progress_bar(done: int, total: int, width: int = 24) -> str:
    fraction = 1.0 if total <= 0 else min(1.0, done / total)
    filled = round(fraction * width)
    return "█" * filled + "·" * (width - filled)


class ProgressRenderer:
    """Renders a single in-place stderr progress line.

    Inactive unless the stream is a TTY (or ``force`` is set); degrades to a
    no-op so piped output stays clean.
    """

    def __init__(self, stream: TextIO | None = None, *, force: bool = False, width: int = 24) -> None:
        self.stream = stream or sys.stderr
        self.force = force
        self.width = width
        interactive = bool(getattr(self.stream, "isatty", lambda: False)()) and os.environ.get("TERM") != "dumb"
        self.active = force or interactive
        self.last_length = 0

    def __call__(self, done: int, total: int, message: str) -> None:
        if not self.active:
            return
        percent = 100 if total <= 0 else round(100 * min(done, total) / total)
        bar = colorize(progress_bar(done, total, self.width), BLUE, enabled=color_enabled(self.stream))
        line = f"{bar} {done}/{total} {percent:3d}%  {colorize(message, DIM, enabled=color_enabled(self.stream))}"
        self.stream.write("\r" + line.ljust(self.last_length))
        self.last_length = len(line) + 1
        self.stream.flush()

    def finish(self) -> None:
        if self.active:
            self.stream.write("\r" + " " * max(self.last_length - 1, 0) + "\r")
            self.stream.flush()
        self.last_length = 0


def step(label: str, detail: str = "", *, enabled: bool | None = None) -> str:
    """A coloured '✓ label detail' line for human-facing command output."""
    mark = colorize("✓", GREEN, enabled=enabled)
    tail = colorize(f"  {detail}", CYAN, enabled=enabled) if detail else ""
    return f"  {mark} {label}{tail}"


def line_printer(*, enabled: bool | None = None) -> Callable[[int, int, str], None]:
    """A progress callback that prints plain verbose lines instead of a bar."""

    def print_line(done: int, total: int, message: str) -> None:
        print(colorize(f"· [{done}/{total}] {message}", DIM, enabled=enabled), file=sys.stderr)

    return print_line
