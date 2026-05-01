"""
Dependency Graph (DAG) for Transitive Dependency Analysis

Models package dependency relationships as a directed acyclic graph.
Used by SCA scanner to identify transitive vulnerabilities — a package
may not be directly vulnerable, but may depend on one that is.

Topological sort provides evaluation order for the dependency chain.
"""

from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class PackageNode:
    """A node in the dependency graph representing a package."""
    name: str
    version: str
    ecosystem: str = ""
    is_direct: bool = True
    metadata: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


class DependencyGraph:
    """
    Directed acyclic graph for modeling package dependencies.

    Supports:
    - Adding packages and dependency edges
    - Topological sort for evaluation order
    - Transitive dependency resolution
    - Cycle detection
    """

    def __init__(self):
        # Adjacency list: package_key -> set of dependency keys
        self._edges: Dict[str, Set[str]] = defaultdict(set)
        # Reverse edges for finding dependents
        self._reverse_edges: Dict[str, Set[str]] = defaultdict(set)
        # Package metadata
        self._nodes: Dict[str, PackageNode] = {}

    def add_package(self, package: PackageNode) -> None:
        """Add a package node to the graph."""
        self._nodes[package.key] = package
        if package.key not in self._edges:
            self._edges[package.key] = set()

    def add_dependency(self, from_key: str, to_key: str) -> None:
        """Add a directed edge: from_key depends on to_key."""
        self._edges[from_key].add(to_key)
        self._reverse_edges[to_key].add(from_key)

    def get_dependencies(self, package_key: str) -> Set[str]:
        """Get direct dependencies of a package."""
        return self._edges.get(package_key, set())

    def get_dependents(self, package_key: str) -> Set[str]:
        """Get packages that depend on this package."""
        return self._reverse_edges.get(package_key, set())

    def get_transitive_dependencies(self, package_key: str) -> Set[str]:
        """
        Get all transitive dependencies via BFS.
        Used to find all packages reachable from a given root.
        """
        visited = set()
        queue = deque([package_key])
        while queue:
            current = queue.popleft()
            for dep in self._edges.get(current, set()):
                if dep not in visited:
                    visited.add(dep)
                    queue.append(dep)
        return visited

    def get_transitive_dependents(self, package_key: str) -> Set[str]:
        """Find all packages that transitively depend on this package."""
        visited = set()
        queue = deque([package_key])
        while queue:
            current = queue.popleft()
            for dep in self._reverse_edges.get(current, set()):
                if dep not in visited:
                    visited.add(dep)
                    queue.append(dep)
        return visited

    def topological_sort(self) -> List[str]:
        """
        Kahn's algorithm for topological ordering.
        Returns packages in dependency-first order.
        Raises ValueError if cycles are detected.
        """
        in_degree: Dict[str, int] = defaultdict(int)
        for node in self._edges:
            if node not in in_degree:
                in_degree[node] = 0
            for dep in self._edges[node]:
                in_degree[dep] = in_degree.get(dep, 0) + 1

        # Start with nodes having no incoming edges
        queue = deque(
            [n for n in in_degree if in_degree[n] == 0]
        )
        result = []

        while queue:
            node = queue.popleft()
            result.append(node)
            for dep in self._edges.get(node, set()):
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    queue.append(dep)

        if len(result) != len(in_degree):
            raise ValueError("Dependency cycle detected in package graph")

        return result

    def get_node(self, key: str) -> Optional[PackageNode]:
        return self._nodes.get(key)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(deps) for deps in self._edges.values())

    def get_all_packages(self) -> List[PackageNode]:
        return list(self._nodes.values())
