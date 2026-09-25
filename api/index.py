"""Vercel entrypoint. Only /tmp is writable on Vercel, and it is ephemeral per instance."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
os.environ.setdefault("TAMPER_SCANNER_DATA_DIR", "/tmp/tamper-scanner")

from tamper_scanner.web import app  # noqa: E402,F401
