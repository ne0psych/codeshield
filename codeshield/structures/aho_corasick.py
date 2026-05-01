"""
Aho-Corasick Automaton for Multi-Pattern Text Matching

Used by SAST and Secrets scanners to match all rule patterns against each
source line in a single pass, rather than running O(P) regex matches per line.

Time complexity: O(N + M) where N = text length, M = total matches
Space complexity: O(sum of pattern lengths)

This replaces the naive O(N * P) approach of iterating each pattern per line.
"""

from collections import deque
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class AhoCorasickMatch:
    """A match found by the automaton."""
    pattern_id: str        # Identifier for the matched pattern
    pattern_text: str      # The original pattern string
    position: int          # Start position in the text
    metadata: dict = field(default_factory=dict)  # Associated rule data


class _TrieNode:
    """Internal node of the Aho-Corasick trie (keyword tree)."""
    __slots__ = ("children", "fail", "output", "depth")

    def __init__(self):
        self.children: Dict[str, "_TrieNode"] = {}
        self.fail: Optional["_TrieNode"] = None
        # output stores (pattern_id, pattern_text, metadata) for completed patterns
        self.output: List[Tuple[str, str, dict]] = []
        self.depth: int = 0


class AhoCorasickAutomaton:
    """
    Aho-Corasick finite automaton for efficient multi-pattern string matching.

    Build once with all patterns, then search any number of texts.
    Each search runs in O(n + m) time where n = text length, m = matches found.
    """

    def __init__(self):
        self._root = _TrieNode()
        self._built = False

    def add_pattern(self, pattern_id: str, pattern: str,
                    metadata: Optional[dict] = None) -> None:
        """
        Add a literal keyword pattern to the automaton.
        Must be called before build(). Case-insensitive matching is achieved
        by lowering both patterns and search text.
        """
        if self._built:
            raise RuntimeError("Cannot add patterns after build()")

        node = self._root
        for char in pattern.lower():
            if char not in node.children:
                child = _TrieNode()
                child.depth = node.depth + 1
                node.children[char] = child
            node = node.children[char]

        node.output.append((pattern_id, pattern, metadata or {}))

    def build(self) -> None:
        """
        Build failure links using BFS (Aho-Corasick construction).
        Must be called once after all patterns are added, before searching.

        The failure function connects each node to the longest proper suffix
        that is also a prefix of some pattern, enabling O(1) state transitions
        on mismatches.
        """
        queue = deque()
        # Initialize failure links for depth-1 nodes
        for child in self._root.children.values():
            child.fail = self._root
            queue.append(child)

        # BFS to build failure links for deeper nodes
        while queue:
            current = queue.popleft()
            for char, child in current.children.items():
                queue.append(child)

                # Walk up failure chain to find longest suffix match
                fail_node = current.fail
                while fail_node is not None and char not in fail_node.children:
                    fail_node = fail_node.fail

                child.fail = fail_node.children[char] if fail_node and char in fail_node.children else self._root
                if child.fail is child:
                    child.fail = self._root

                # Merge output from failure node (dictionary suffix links)
                child.output = child.output + child.fail.output

        self._built = True

    def search(self, text: str) -> List[AhoCorasickMatch]:
        """
        Search text for all pattern matches in a single pass.
        Returns list of AhoCorasickMatch objects with positions.
        """
        if not self._built:
            raise RuntimeError("Must call build() before search()")

        matches = []
        node = self._root
        lower_text = text.lower()

        for i, char in enumerate(lower_text):
            # Follow failure links until we find a matching child or reach root
            while node is not self._root and char not in node.children:
                node = node.fail

            if char in node.children:
                node = node.children[char]
            else:
                node = self._root
                continue

            # Collect all outputs at this node (includes suffix matches)
            for pattern_id, pattern_text, metadata in node.output:
                start_pos = i - len(pattern_text) + 1
                matches.append(AhoCorasickMatch(
                    pattern_id=pattern_id,
                    pattern_text=pattern_text,
                    position=start_pos,
                    metadata=metadata
                ))

        return matches

    @property
    def pattern_count(self) -> int:
        """Count total patterns in the automaton via BFS."""
        count = 0
        queue = deque([self._root])
        while queue:
            node = queue.popleft()
            count += len([o for o in node.output
                          if o not in (node.fail.output if node.fail else [])])
            for child in node.children.values():
                queue.append(child)
        return count
