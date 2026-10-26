"""Keep writable data outside the application package."""

import os
import sys
from pathlib import Path


def data_directory() -> Path:
    project = Path(__file__).resolve().parents[2]
    if not getattr(sys, "frozen", False) and (project / "pyproject.toml").is_file():
        return project
    return Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / (
        "NetworkPacketSniffer"
    )
