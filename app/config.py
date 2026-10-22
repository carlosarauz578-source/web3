from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("AEGIS_DB_PATH", ROOT / "aegis.db"))
MAX_SOURCE_BYTES = 200_000
SESSION_TTL_SECONDS = 12 * 60 * 60
