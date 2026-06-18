"""Main.py entry point for the csharp-sast engine."""

from __future__ import annotations

import logging
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from config.settings import Settings
from cli.scanner import main as scanner_main


def main(argv: list[str] | None = None) -> int:
    """Bootstrap configuration and delegate to the scanner pipeline."""
    Settings.initialize_directories()

    level = getattr(logging, Settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
    )

    return scanner_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())