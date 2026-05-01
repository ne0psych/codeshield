"""
Interval Tree for Version Range Matching

Used by SCA scanner to efficiently match a package version against all known
vulnerable version ranges. Instead of checking each range individually O(N),
the interval tree enables O(log N + K) lookups where K = overlapping intervals.

Each interval represents a vulnerable version range [introduced, fixed).
"""

from typing import List, Optional, Tuple, Any
from dataclasses import dataclass
from packaging.version import Version, InvalidVersion


@dataclass
class VersionInterval:
    """A version range interval with associated vulnerability data."""
    low: Version           # Introduced version (inclusive)
    high: Version          # Fixed version (exclusive), or MAX_VERSION if unfixed
    vuln_id: str           # CVE/GHSA identifier
    metadata: dict         # Additional vulnerability data

    def contains(self, version: Version) -> bool:
        return self.low <= version < self.high


# Sentinel for unfixed vulnerabilities
MAX_VERSION = Version("99999.99999.99999")


def parse_version_safe(v: str) -> Optional[Version]:
    """Parse a version string safely, returning None for unparseable versions."""
    if not v or not v.strip():
        return None
    try:
        return Version(v.strip())
    except InvalidVersion:
        return None


class _IntervalNode:
    """Internal node of the augmented interval tree."""
    __slots__ = ("center", "left", "right",
                 "s_left", "s_right")

    def __init__(self, center: Version):
        self.center = center
        self.left: Optional["_IntervalNode"] = None
        self.right: Optional["_IntervalNode"] = None
        # Intervals containing center, sorted by low endpoint (ascending)
        self.s_left: List[VersionInterval] = []
        # Same intervals sorted by high endpoint (descending)
        self.s_right: List[VersionInterval] = []


class IntervalTree:
    """
    Augmented interval tree for efficient version range lookups.

    Construction: O(N log N)
    Point query: O(log N + K) where K = number of overlapping intervals
    """

    def __init__(self):
        self._root: Optional[_IntervalNode] = None
        self._count = 0

    def build(self, intervals: List[VersionInterval]) -> None:
        """Build the interval tree from a list of version intervals."""
        self._count = len(intervals)
        if not intervals:
            self._root = None
            return
        self._root = self._build_recursive(intervals)

    def _build_recursive(self, intervals: List[VersionInterval], depth: int = 0) -> Optional[_IntervalNode]:
        """Recursively build a balanced interval tree."""
        if not intervals:
            return None

        # Safety: prevent infinite recursion if center doesn't partition
        if depth > 50:
            # Fall back: store all remaining intervals at this node
            center = intervals[0].low
            node = _IntervalNode(center)
            node.s_left = sorted(intervals, key=lambda iv: iv.low)
            node.s_right = sorted(intervals, key=lambda iv: iv.high, reverse=True)
            return node

        # Find median endpoint as the center point
        endpoints = sorted(set(
            [iv.low for iv in intervals] + [iv.high for iv in intervals]
        ))
        center = endpoints[len(endpoints) // 2]
        node = _IntervalNode(center)

        left_intervals = []
        right_intervals = []

        for iv in intervals:
            if iv.high <= center:
                left_intervals.append(iv)
            elif iv.low > center:
                right_intervals.append(iv)
            else:
                node.s_left.append(iv)
                node.s_right.append(iv)

        # Sort for efficient pruning during queries
        node.s_left.sort(key=lambda iv: iv.low)
        node.s_right.sort(key=lambda iv: iv.high, reverse=True)

        # Only recurse if we actually partitioned some intervals
        if left_intervals and len(left_intervals) < len(intervals):
            node.left = self._build_recursive(left_intervals, depth + 1)
        if right_intervals and len(right_intervals) < len(intervals):
            node.right = self._build_recursive(right_intervals, depth + 1)

        return node

    def query(self, version: Version) -> List[VersionInterval]:
        """
        Find all intervals containing the given version.
        Returns list of matching VersionInterval objects.
        """
        results = []
        self._query_recursive(self._root, version, results)
        return results

    def _query_recursive(self, node: Optional[_IntervalNode],
                         version: Version,
                         results: List[VersionInterval]) -> None:
        """Recursively search the tree for intervals containing version."""
        if node is None:
            return

        if version < node.center:
            # Check intervals starting before or at version
            for iv in node.s_left:
                if iv.low <= version:
                    results.append(iv)
                else:
                    break  # s_left sorted by low: no more matches
            self._query_recursive(node.left, version, results)

        elif version > node.center:
            # Check intervals ending after version
            for iv in node.s_right:
                if iv.high > version:
                    results.append(iv)
                else:
                    break  # s_right sorted by high desc: no more matches
            self._query_recursive(node.right, version, results)

        else:
            # version == center: all intervals at this node match
            results.extend(node.s_left)

    def query_str(self, version_str: str) -> List[VersionInterval]:
        """Query with a version string, returns empty list for unparseable versions."""
        ver = parse_version_safe(version_str)
        if ver is None:
            return []
        return self.query(ver)

    @property
    def size(self) -> int:
        return self._count
