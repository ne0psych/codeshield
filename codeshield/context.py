"""
CodeShield Scan Context
Standardized context object passed to every scanner plugin.
Contains file tree, dependency map, configuration, and database access.
"""

import os
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("codeshield.context")

# Language detection by file extension
EXTENSION_TO_LANGUAGE = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "c", ".h": "c",
    ".swift": "swift",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala",
    ".r": "r",
    ".sh": "shell", ".bash": "shell",
    ".ps1": "powershell",
    ".tf": "terraform",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".toml": "toml",
    ".cfg": "config", ".ini": "config", ".conf": "config",
    ".dockerfile": "docker",
}

# Known dependency manifest files
MANIFEST_FILES = {
    "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
    "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "Gemfile", "Gemfile.lock",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock",
    "pubspec.yaml", "pubspec.lock",
    "*.csproj", "*.fsproj", "packages.config",
}

# Binary file extensions to skip
BINARY_EXTENSIONS = frozenset({
    ".pyc", ".pyo", ".class", ".o", ".obj", ".exe", ".dll", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".lock",
})

# Directories to always skip
SKIP_DIRECTORIES = frozenset({
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", "vendor", "dist", "build",
    ".next", ".nuxt", "target", "bin", "obj",
})


@dataclass
class FileInfo:
    """Metadata about a single file in the scanned codebase."""
    path: str              # Relative path within the codebase
    absolute_path: str     # Absolute path on disk
    language: str          # Detected language
    size: int              # File size in bytes
    is_binary: bool        # Whether the file is binary
    is_manifest: bool      # Whether it's a dependency manifest
    is_minified: bool      # Whether it appears to be minified
    is_test: bool          # Whether it appears to be a test file


@dataclass
class ScanContext:
    """
    Standardized context object provided to every scanner plugin.
    Contains everything a plugin needs to perform its analysis.
    """
    scan_id: str
    code_dir: str                             # Root extraction directory
    files: List[FileInfo] = field(default_factory=list)
    file_tree: Dict[str, List[str]] = field(default_factory=dict)
    languages: Set[str] = field(default_factory=set)
    manifests: List[FileInfo] = field(default_factory=list)
    config: Optional[object] = None           # AppConfig reference

    @property
    def source_files(self) -> List[FileInfo]:
        """Get only source code files (non-binary, non-manifest)."""
        return [f for f in self.files if not f.is_binary]

    @property
    def text_files(self) -> List[FileInfo]:
        """Get all text files for scanning."""
        return [f for f in self.files if not f.is_binary]


def _is_minified(path: str, content_sample: str) -> bool:
    """Heuristic: file is likely minified if avg line length > 500 chars."""
    lines = content_sample.split("\n")[:5]
    if not lines:
        return False
    avg_len = sum(len(l) for l in lines) / len(lines)
    return avg_len > 500


def _is_test_file(path: str) -> bool:
    """Heuristic: file is a test if path contains test indicators."""
    lower = path.lower()
    indicators = ("test_", "_test.", "tests/", "test/", "spec/",
                  "__tests__/", ".spec.", ".test.", "fixtures/",
                  "testdata/", "mock_", "_mock.")
    return any(ind in lower for ind in indicators)


def build_scan_context(scan_id: str, code_dir: str,
                       config=None) -> ScanContext:
    """
    Walk the extracted codebase and build a complete ScanContext.
    Uses streaming directory walk — does not load file contents into memory.
    """
    ctx = ScanContext(scan_id=scan_id, code_dir=code_dir, config=config)
    file_tree: Dict[str, List[str]] = {}

    for root, dirs, filenames in os.walk(code_dir):
        # Prune directories we should skip
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

        rel_dir = os.path.relpath(root, code_dir)
        dir_files = []

        for fname in filenames:
            abs_path = os.path.join(root, fname)
            rel_path = os.path.relpath(abs_path, code_dir)

            # Skip symlinks pointing outside extraction dir (security)
            if os.path.islink(abs_path):
                real = os.path.realpath(abs_path)
                if not real.startswith(os.path.realpath(code_dir)):
                    logger.warning("Skipping symlink escaping extraction dir: %s", rel_path)
                    continue

            ext = Path(fname).suffix.lower()
            language = EXTENSION_TO_LANGUAGE.get(ext, "unknown")
            is_binary = ext in BINARY_EXTENSIONS
            is_manifest = fname in MANIFEST_FILES

            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue

            # Check minification for non-binary files (read first 2KB only)
            is_minified = False
            if not is_binary and size > 0:
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                        sample = fh.read(2048)
                    is_minified = _is_minified(rel_path, sample)
                except Exception:
                    is_binary = True

            # Dockerfile detection
            if fname.lower().startswith("dockerfile"):
                language = "docker"

            fi = FileInfo(
                path=rel_path,
                absolute_path=abs_path,
                language=language,
                size=size,
                is_binary=is_binary,
                is_manifest=is_manifest,
                is_minified=is_minified,
                is_test=_is_test_file(rel_path),
            )
            ctx.files.append(fi)
            dir_files.append(rel_path)

            if not is_binary:
                ctx.languages.add(language)
            if is_manifest:
                ctx.manifests.append(fi)

        file_tree[rel_dir] = dir_files

    ctx.file_tree = file_tree
    logger.info("Scan context built: %d files, %d languages, %d manifests",
                len(ctx.files), len(ctx.languages), len(ctx.manifests))

    return ctx
