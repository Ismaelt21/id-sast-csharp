from __future__ import annotations

import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"

for candidate in (str(SRC_DIR), str(ROOT_DIR)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)
