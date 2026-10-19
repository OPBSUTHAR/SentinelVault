"""Application configuration loaded from environment (.env supported)."""
import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_DIR / ".env")


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class Settings:
    APP_NAME: str = _env("APP_NAME", "SentinelVault")
    APP_ENV: str = _env("APP_ENV", "development")

    API_HOST: str = _env("API_HOST", "127.0.0.1")
    API_PORT: int = _env_int("API_PORT", 8000)

    JWT_SECRET: str = _env("JWT_SECRET", "change-me-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = _env_int("JWT_EXPIRY_MINUTES", 60)
    SESSION_TTL_MINUTES: int = _env_int("SESSION_TTL_MINUTES", 30)

    CORS_ORIGINS: list = [
        o.strip()
        for o in _env(
            "CORS_ORIGINS",
            "http://localhost:5176,http://localhost:5173,http://localhost:3000",
        ).split(",")
        if o.strip()
    ]

    DATABASE_PATH: str = _env("DATABASE_PATH", str(BACKEND_DIR / "data" / "sentinelvault.db"))

    # Breach monitoring
    HIBP_API_KEY: str = _env("HIBP_API_KEY", "")
    HIBP_PWNED_URL: str = _env("HIBP_PWNED_URL", "https://api.pwnedpasswords.com")
    HIBP_API_URL: str = _env("HIBP_API_URL", "https://haveibeenpwned.com/api/v3")

    PUBLIC_BASE_URL: str = _env("PUBLIC_BASE_URL", "http://localhost:5176")


settings = Settings()
