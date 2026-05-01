"""
Inverted Index for Fast Rule Lookup

Enables O(1) lookup of SAST rules by language, severity, or CWE category
instead of scanning the entire rule set. Used during scanning to quickly
retrieve only the relevant rules for a given file's language.
"""

from collections import defaultdict
from typing import Dict, List, Set, Any, Optional


class InvertedIndex:
    """
    Maps attribute values to sets of item IDs for fast reverse lookup.

    Example usage:
        index = InvertedIndex()
        index.add("SAST-001", "language", "python")
        index.add("SAST-001", "severity", "CRITICAL")
        index.add("SAST-001", "cwe", "CWE-89")

        python_rules = index.lookup("language", "python")  # {"SAST-001"}
    """

    def __init__(self):
        # Structure: {field_name: {field_value: {item_ids}}}
        self._index: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._items: Dict[str, dict] = {}

    def add(self, item_id: str, field: str, value: str) -> None:
        """Index an item under a specific field+value pair."""
        self._index[field][value.lower()].add(item_id)

    def add_item(self, item_id: str, item_data: dict,
                 index_fields: List[str]) -> None:
        """
        Add an item and automatically index specified fields.
        Handles both scalar and list field values.
        """
        self._items[item_id] = item_data
        for field_name in index_fields:
            value = item_data.get(field_name, "")
            if isinstance(value, list):
                for v in value:
                    self.add(item_id, field_name, str(v))
            elif value:
                self.add(item_id, field_name, str(value))

    def lookup(self, field: str, value: str) -> Set[str]:
        """Look up all item IDs matching a field+value pair. O(1) average."""
        return self._index.get(field, {}).get(value.lower(), set())

    def lookup_multi(self, criteria: Dict[str, str]) -> Set[str]:
        """
        Look up items matching ALL criteria (intersection).
        Returns item IDs that match every field+value pair.
        """
        result_sets = []
        for field_name, value in criteria.items():
            result_sets.append(self.lookup(field_name, value))

        if not result_sets:
            return set()
        return set.intersection(*result_sets)

    def lookup_any(self, criteria: Dict[str, str]) -> Set[str]:
        """
        Look up items matching ANY criteria (union).
        Returns item IDs that match at least one field+value pair.
        """
        result = set()
        for field_name, value in criteria.items():
            result.update(self.lookup(field_name, value))
        return result

    def get_item(self, item_id: str) -> Optional[dict]:
        """Retrieve stored item data by ID."""
        return self._items.get(item_id)

    def get_all_values(self, field: str) -> Set[str]:
        """Get all indexed values for a given field."""
        return set(self._index.get(field, {}).keys())

    @property
    def field_count(self) -> int:
        return len(self._index)

    @property
    def item_count(self) -> int:
        return len(self._items)
