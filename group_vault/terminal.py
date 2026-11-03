"""Consistent CLI status formatting."""

from typing import Literal

from rich.console import Console

Status = Literal["SUCCESS", "SYNCED", "PENDING", "RETRY", "REJECTED", "EXPIRED"]

console = Console()

STYLES: dict[str, str] = {
    "SUCCESS": "bold green",
    "SYNCED": "green",
    "PENDING": "yellow",
    "RETRY": "yellow",
    "REJECTED": "red",
    "EXPIRED": "bright_red",
}


def show_status(status: Status, message: str) -> None:
    """Print plain message text using the status color."""
    console.print(
        f"{status}: {message}",
        style=STYLES[status],
        markup=False,
        highlight=False,
    )
