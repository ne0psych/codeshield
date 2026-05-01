"""
CodeShield Plugin Registry
Dynamic plugin discovery and loading via filesystem scanning.
Validates all plugins conform to the ScannerPlugin interface at startup.
"""

import os
import sys
import importlib
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Optional

from .base import ScannerPlugin

logger = logging.getLogger("codeshield.plugins")


class PluginRegistry:
    """
    Discovers, validates, and manages scanner plugins.

    Plugins are loaded dynamically from the plugins directory at runtime.
    No hardcoded plugin references exist in the engine.
    Adding a new plugin requires only dropping a .py file implementing
    ScannerPlugin into the plugins directory.
    """

    def __init__(self):
        self._plugins: Dict[str, ScannerPlugin] = {}
        self._load_errors: List[str] = []

    def discover_and_load(self, plugin_dir: str) -> None:
        """
        Scan the plugin directory for .py files, import them,
        and register any ScannerPlugin subclasses found.
        """
        plugin_path = Path(plugin_dir).resolve()
        if not plugin_path.is_dir():
            logger.warning("Plugin directory does not exist: %s", plugin_dir)
            return

        logger.info("Discovering plugins in: %s", plugin_path)

        # Add plugin directory to sys.path if not present
        plugin_dir_str = str(plugin_path.parent)
        if plugin_dir_str not in sys.path:
            sys.path.insert(0, plugin_dir_str)

        for filepath in sorted(plugin_path.glob("*.py")):
            if filepath.name.startswith("_") or filepath.name == "base.py":
                continue

            # Use the full package path so relative imports resolve correctly
            module_name = f"codeshield.plugins.{filepath.stem}"
            try:
                spec = importlib.util.spec_from_file_location(
                    module_name, str(filepath),
                    submodule_search_locations=[]
                )
                if spec is None or spec.loader is None:
                    continue

                module = importlib.util.module_from_spec(spec)
                # Set package so relative imports (from ..database) work
                module.__package__ = "codeshield.plugins"
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # Find all ScannerPlugin subclasses in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (inspect.isclass(attr) and
                            issubclass(attr, ScannerPlugin) and
                            attr is not ScannerPlugin and
                            not inspect.isabstract(attr)):
                        self._register_plugin(attr, filepath.name)

            except Exception as exc:
                error_msg = f"Failed to load plugin {filepath.name}: {exc}"
                logger.error(error_msg)
                self._load_errors.append(error_msg)

    def _register_plugin(self, plugin_class: type,
                         filename: str) -> None:
        """Validate and register a single plugin class."""
        try:
            instance = plugin_class()
            # Verify the plugin conforms to the interface
            self._validate_plugin(instance, filename)

            if instance.name in self._plugins:
                logger.warning(
                    "Plugin name '%s' from %s conflicts with existing plugin. "
                    "Skipping duplicate.",
                    instance.name, filename
                )
                return

            # Initialize the plugin
            instance.initialize()
            self._plugins[instance.name] = instance
            logger.info("Registered plugin: '%s' v%s from %s",
                        instance.name, instance.version, filename)

        except Exception as exc:
            error_msg = f"Plugin validation failed for {filename}: {exc}"
            logger.error(error_msg)
            self._load_errors.append(error_msg)

    def _validate_plugin(self, plugin: ScannerPlugin,
                         filename: str) -> None:
        """
        Verify a plugin implements the required interface.
        Automated check enforced on startup per the extensibility contract.
        """
        if not isinstance(plugin.name, str) or not plugin.name.strip():
            raise ValueError(f"Plugin in {filename} has empty or invalid name")

        if not isinstance(plugin.description, str):
            raise ValueError(
                f"Plugin '{plugin.name}' has invalid description"
            )

        if not callable(getattr(plugin, "execute", None)):
            raise ValueError(
                f"Plugin '{plugin.name}' missing execute() method"
            )

    def get_plugin(self, name: str) -> Optional[ScannerPlugin]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_all_plugins(self) -> List[ScannerPlugin]:
        """Get all registered plugins, sorted by priority."""
        return sorted(self._plugins.values(),
                      key=lambda p: p.priority)

    @property
    def plugin_names(self) -> List[str]:
        return list(self._plugins.keys())

    @property
    def load_errors(self) -> List[str]:
        return list(self._load_errors)

    @property
    def count(self) -> int:
        return len(self._plugins)

    def cleanup_all(self) -> None:
        """Call cleanup() on all plugins during shutdown."""
        for plugin in self._plugins.values():
            try:
                plugin.cleanup()
            except Exception as exc:
                logger.error("Plugin cleanup error for '%s': %s",
                             plugin.name, exc)
