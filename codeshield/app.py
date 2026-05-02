"""
CodeShield Flask Application
Main entry point for the web application.
Initializes config, database, sync, plugins, and starts the server.
"""

import os
import sys
import logging
from pathlib import Path

from flask import Flask

from .config import load_config, setup_logging
from .database.connection import init_db
from .database.schema import initialize_schema
from .sync.engine import run_sync
from .plugins.registry import PluginRegistry
from .engine import ScanEngine
from .web.routes import create_routes

logger = logging.getLogger("codeshield")


def create_app() -> Flask:
    """
    Application factory — creates and configures the Flask app.
    Performs startup sequence: config → logging → DB → sync → plugins.
    """
    # 1. Load configuration
    config = load_config()
    setup_logging(config.logging)

    logger.info("=" * 60)
    logger.info("  CodeShield v3.0 — Starting up")
    logger.info("=" * 60)

    # 2. Initialize database
    db = init_db(config.database.path)
    initialize_schema(db)
    logger.info("Database ready at %s", config.database.path)

    # 3. Run startup data sync
    logger.info("Running startup data sync...")
    sync_report = run_sync(config.sync)

    # 4. Discover and load plugins
    logger.info("Loading scanner plugins...")
    registry = PluginRegistry()

    # Resolve plugin directory relative to project root
    plugin_dir = config.plugins.directory
    if not os.path.isabs(plugin_dir):
        project_root = Path(__file__).resolve().parent.parent
        plugin_dir = str(project_root / plugin_dir)

    registry.discover_and_load(plugin_dir)

    if registry.count == 0:
        logger.warning("No scanner plugins loaded!")
    else:
        logger.info("Loaded %d plugins: %s",
                     registry.count, ", ".join(registry.plugin_names))

    if registry.load_errors:
        for err in registry.load_errors:
            logger.warning("Plugin load error: %s", err)

    # 5. Create scan engine
    engine = ScanEngine(config, registry)

    # 6. Create Flask app
    template_dir = Path(__file__).resolve().parent / "templates"
    static_dir = Path(__file__).resolve().parent / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )

    # Security settings
    app.config["MAX_CONTENT_LENGTH"] = config.scan.max_zip_size
    app.config["SECRET_KEY"] = os.urandom(32).hex()
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    # Jinja2 autoescape is enabled by default for .html templates
    # preventing XSS in all rendered output

    # Register routes
    create_routes(app, config, engine, registry)

    logger.info("CodeShield ready — listening on %s:%d",
                config.server.host, config.server.port)

    # Store config on app for access
    app.codeshield_config = config

    return app


def main():
    """CLI entry point."""
    app = create_app()
    config = app.codeshield_config

    app.run(
        host=config.server.host,
        port=config.server.port,
        debug=config.server.debug,
        threaded=True,
        use_reloader=False,  # Avoid double-init of sync
    )


if __name__ == "__main__":
    main()
