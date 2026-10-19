"""Vercel entrypoint — exposes SentinelVault's FastAPI app as one serverless function.

The React SPA is built by vercel.json's buildCommand and served by the app itself
(see app/main.py: /assets mount + SPA fallback), so everything shares one origin
and the frontend keeps using the relative `/api` base URL.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"

sys.path.insert(0, str(BACKEND))

# --- Writable SQLite database (serverless FS is read-only except /tmp) --------
if not os.environ.get("DATABASE_PATH"):
    tmp_db = Path(tempfile.gettempdir()) / "sentinelvault.db"
    bundled = BACKEND / "data" / "sentinelvault.db"
    if bundled.is_file() and not tmp_db.is_file():
        try:
            tmp_db.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bundled, tmp_db)
        except OSError:
            pass
    os.environ["DATABASE_PATH"] = str(tmp_db)

# --- Environment defaults -----------------------------------------------------
allowed = ["http://localhost:5176", "http://localhost:5173", "http://localhost:3000"]
public_host = os.environ.get("VERCEL_PROJECT_PRODUCTION_URL") or os.environ.get("VERCEL_URL")
for var in ("VERCEL_PROJECT_PRODUCTION_URL", "VERCEL_URL"):
    host = os.environ.get(var)
    if host:
        allowed.append(f"https://{host}")
os.environ.setdefault("CORS_ORIGINS", ",".join(allowed))
os.environ.setdefault("JWT_SECRET", "sentinelvault-vercel-demo-secret-2026")
os.environ.setdefault("PUBLIC_BASE_URL", f"https://{public_host}" if public_host else "http://localhost:5176")
os.environ.setdefault("APP_ENV", "production")

os.chdir(BACKEND)  # relative paths resolve against the backend package

from app.main import app  # noqa: E402  (import after environment setup)
