"""Application configuration settings."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache


# Determine base directory (parent of backend/)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
MAPPINGS_DIR = BASE_DIR / "mappings"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database path
DB_PATH = DATA_DIR / "csf_attack_mapper.db"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # App settings
    APP_NAME: str = "CSF×ATT&CK Mapper"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Database - absolute path
    DATABASE_URL: str = f"sqlite:///{DB_PATH}"

    # Security
    SECRET_KEY: str = "dev-secret-key-change-in-production-abc123xyz789"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Encryption key for Splunk secrets (must be 32 url-safe base64 chars for Fernet)
    # In production, set this via ENCRYPTION_KEY env var
    ENCRYPTION_KEY: str = "dev-encryption-key-32-chars-abc"  # Will be derived if not valid

    # Default admin user
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_EMAIL: str = "admin@localhost"
    DEFAULT_ADMIN_PASSWORD: str = "changeme123"

    # Paths
    BASE_DIR: Path = BASE_DIR
    MAPPINGS_DIR: Path = MAPPINGS_DIR
    DATA_DIR: Path = DATA_DIR

    # CORS
    CORS_ORIGINS: list = ["http://localhost:5173", "http://127.0.0.1:5173"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
