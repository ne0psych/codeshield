"""
CodeShield Plugin Interface (Abstract Base Class)

Every scanner plugin must implement this interface. The core engine
uses it to invoke plugins uniformly without knowing their internals.
"""

import abc
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("codeshield.plugins")


@dataclass
class Finding:
    """Standardized finding returned by any scanner plugin."""
    plugin_name: str
    severity: str              # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    remediation: str = ""
    rule_id: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    owasp_category: str = ""
    package_name: str = ""
    package_version: str = ""
    fixed_version: str = ""
    license_id: str = ""
    # Enrichment fields (populated by mappings.enrich_finding)
    mitre_id: str = ""
    mitre_label: str = ""
    pci_dss: str = ""
    hipaa: str = ""
    exploit_available: str = "unknown"
    false_positive: bool = False
    confidence: float = 0.85
    fix_effort_hours: float = 2.0
    trend_status: str = "new"       # new / recurring / fixed
    cwe_label: str = ""
    owasp_label: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class PluginResult:
    """Standardized result returned by a plugin after scanning."""
    plugin_name: str
    status: str = "complete"      # complete / failed / timeout
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_sec: float = 0.0
    error_message: str = ""
    metadata: dict = field(default_factory=dict)


class ScannerPlugin(abc.ABC):
    """
    Abstract base class that every scanner plugin must implement.

    To create a new plugin:
    1. Create a .py file in the plugins directory
    2. Subclass ScannerPlugin
    3. Implement name(), description(), and execute()
    4. The plugin will be auto-discovered and loaded at startup

    No other code changes required.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique plugin name (e.g., 'sast', 'sca', 'secrets', 'license')."""
        ...

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable description of what this plugin scans for."""
        ...

    @property
    def version(self) -> str:
        """Plugin version string."""
        return "1.0.0"

    @property
    def priority(self) -> int:
        """Execution priority (lower = runs first). Default: 100."""
        return 100

    @abc.abstractmethod
    def execute(self, context) -> PluginResult:
        """
        Execute the scan against the provided ScanContext.

        Args:
            context: ScanContext with file tree, config, and DB access

        Returns:
            PluginResult with findings list and metadata

        The plugin must:
        - Never execute or eval code from scanned files
        - Use streaming/generators for large files
        - Return results even on partial failure
        - Handle all internal exceptions gracefully
        """
        ...

    def initialize(self) -> None:
        """
        Optional: called once at startup after discovery.
        Use for loading patterns from DB, building data structures, etc.
        """
        pass

    def cleanup(self) -> None:
        """Optional: called during shutdown for resource cleanup."""
        pass

    def run(self, context) -> PluginResult:
        """
        Wrapper that runs execute() with timing and error handling.
        Called by the engine — plugins should not override this.
        """
        start = time.time()
        try:
            result = self.execute(context)
            result.duration_sec = round(time.time() - start, 3)
            result.plugin_name = self.name
            return result
        except Exception as exc:
            logger.error("Plugin '%s' failed: %s", self.name, exc,
                         exc_info=True)
            return PluginResult(
                plugin_name=self.name,
                status="failed",
                duration_sec=round(time.time() - start, 3),
                error_message=str(exc)
            )
