"""
CodeShield Configuration System
Loads config from environment variables (primary) and TOML file (secondary).
Validates all values at startup and never logs secrets.
"""

import os
import sys
import logging
import toml
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

logger = logging.getLogger("codeshield.config")

# Environment variable prefix for all config overrides
_ENV_PREFIX = "CODESHIELD_"

# Keys that contain sensitive values — never logged
_SECRET_KEYS = frozenset({
    "nvd_api_key", "api_key", "secret", "password", "token",
})


def _is_secret(key: str) -> bool:
    """Check if a config key name refers to a secret value."""
    lower = key.lower()
    return any(s in lower for s in _SECRET_KEYS)


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False


@dataclass
class DatabaseConfig:
    path: str = "./codeshield_data/codeshield.db"


@dataclass
class ScanConfig:
    max_zip_size: int = 524_288_000          # 500 MB
    max_uncompressed_size: int = 2_147_483_648  # 2 GB
    max_file_count: int = 50_000
    max_nesting_depth: int = 20
    plugin_timeout: int = 300
    temp_directory: str = ""
    thread_pool_size: int = 4


@dataclass
class PluginConfig:
    directory: str = "./codeshield/plugins"


@dataclass
class SyncConfig:
    enabled: bool = True
    osv_api_url: str = "https://api.osv.dev/v1"
    nvd_api_key: str = ""
    spdx_url: str = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
    sast_rules_url: str = ""
    secrets_patterns_url: str = ""
    sync_timeout: int = 60
    sync_concurrency: int = 4


@dataclass
class LicenseComplianceConfig:
    allowed_licenses: List[str] = field(default_factory=list)
    denied_licenses: List[str] = field(default_factory=lambda: [
        "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"
    ])


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "./codeshield_data/codeshield.log"


@dataclass
class AppConfig:
    """Root configuration container. Assembled from TOML + environment overrides."""
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    sync: SyncConfig = field(default_factory=SyncConfig)
    license_compliance: LicenseComplianceConfig = field(default_factory=LicenseComplianceConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def _apply_env_overrides(config: AppConfig) -> None:
    """
    Override config values from environment variables.
    Format: CODESHIELD_<SECTION>_<KEY>=value
    Example: CODESHIELD_DATABASE_PATH=/my/db.sqlite
    """
    env_mappings = {
        "SERVER_HOST": ("server", "host", str),
        "SERVER_PORT": ("server", "port", int),
        "SERVER_DEBUG": ("server", "debug", lambda v: v.lower() in ("1", "true", "yes")),
        "DB_PATH": ("database", "path", str),
        "DATABASE_PATH": ("database", "path", str),
        "SCAN_MAX_ZIP_SIZE": ("scan", "max_zip_size", int),
        "SCAN_MAX_UNCOMPRESSED_SIZE": ("scan", "max_uncompressed_size", int),
        "SCAN_MAX_FILE_COUNT": ("scan", "max_file_count", int),
        "SCAN_PLUGIN_TIMEOUT": ("scan", "plugin_timeout", int),
        "SCAN_TEMP_DIRECTORY": ("scan", "temp_directory", str),
        "SCAN_THREAD_POOL_SIZE": ("scan", "thread_pool_size", int),
        "PLUGIN_DIRECTORY": ("plugins", "directory", str),
        "SYNC_ENABLED": ("sync", "enabled", lambda v: v.lower() in ("1", "true", "yes")),
        "SYNC_OSV_API_URL": ("sync", "osv_api_url", str),
        "NVD_API_KEY": ("sync", "nvd_api_key", str),
        "SYNC_SPDX_URL": ("sync", "spdx_url", str),
        "SYNC_SAST_RULES_URL": ("sync", "sast_rules_url", str),
        "SYNC_SECRETS_PATTERNS_URL": ("sync", "secrets_patterns_url", str),
        "LOG_LEVEL": ("logging", "level", str),
        "LOG_FILE": ("logging", "file", str),
    }

    for env_suffix, (section, attr, converter) in env_mappings.items():
        env_key = f"{_ENV_PREFIX}{env_suffix}"
        env_val = os.environ.get(env_key)
        if env_val is not None:
            section_obj = getattr(config, section)
            try:
                setattr(section_obj, attr, converter(env_val))
                if not _is_secret(attr):
                    logger.debug("Config override: %s.%s = %s (from %s)",
                                 section, attr, getattr(section_obj, attr), env_key)
                else:
                    logger.debug("Config override: %s.%s = [REDACTED] (from %s)",
                                 section, attr, env_key)
            except (ValueError, TypeError) as exc:
                logger.warning("Invalid env var %s=%s: %s", env_key, env_val, exc)


def _load_toml(path: str) -> dict:
    """Load and return TOML config, or empty dict if file missing."""
    config_path = Path(path)
    if not config_path.is_file():
        logger.info("Config file not found at %s, using defaults", path)
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            data = toml.load(fh)
        logger.info("Loaded config from %s", path)
        return data
    except toml.TomlDecodeError as exc:
        logger.error("Failed to parse config file %s: %s", path, exc)
        sys.exit(1)


def _apply_toml(config: AppConfig, data: dict) -> None:
    """Apply parsed TOML data onto the config dataclasses."""
    section_map = {
        "server": config.server,
        "database": config.database,
        "scan": config.scan,
        "plugins": config.plugins,
        "sync": config.sync,
        "license_compliance": config.license_compliance,
        "logging": config.logging,
    }
    for section_name, section_obj in section_map.items():
        section_data = data.get(section_name, {})
        for key, value in section_data.items():
            if hasattr(section_obj, key):
                setattr(section_obj, key, value)


def _validate(config: AppConfig) -> None:
    """Validate configuration values at startup. Exit on critical errors."""
    errors = []

    if config.server.port < 1 or config.server.port > 65535:
        errors.append(f"server.port must be 1-65535, got {config.server.port}")

    if config.scan.max_zip_size < 1_048_576:
        errors.append("scan.max_zip_size must be at least 1MB")

    if config.scan.thread_pool_size < 1:
        errors.append("scan.thread_pool_size must be >= 1")

    if config.scan.plugin_timeout < 10:
        errors.append("scan.plugin_timeout must be >= 10 seconds")

    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if config.logging.level.upper() not in valid_levels:
        errors.append(f"logging.level must be one of {valid_levels}")

    if errors:
        for err in errors:
            logger.error("Config validation error: %s", err)
        sys.exit(1)


def load_config() -> AppConfig:
    """
    Load configuration with priority: env vars > TOML file > defaults.
    The config file path is itself configurable via CODESHIELD_CONFIG_FILE.
    """
    config = AppConfig()

    # Determine config file path
    config_path = os.environ.get(
        f"{_ENV_PREFIX}CONFIG_FILE",
        str(Path(__file__).resolve().parent.parent / "config.toml")
    )

    # Load TOML (secondary)
    toml_data = _load_toml(config_path)
    _apply_toml(config, toml_data)

    # Apply env overrides (primary — takes precedence)
    _apply_env_overrides(config)

    # Validate
    _validate(config)

    return config


def setup_logging(config: LoggingConfig) -> None:
    """Configure structured logging based on config."""
    log_level = getattr(logging, config.level.upper(), logging.INFO)

    root_logger = logging.getLogger("codeshield")
    root_logger.setLevel(log_level)

    # Console handler — always present
    console_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_fmt)
    root_logger.addHandler(console_handler)

    # File handler — if configured
    if config.file:
        log_dir = Path(config.file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(config.file, encoding="utf-8")
        file_handler.setFormatter(console_fmt)
        root_logger.addHandler(file_handler)
