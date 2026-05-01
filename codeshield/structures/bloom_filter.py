"""
Bloom Filter for Fast Known-Safe Package Version Pre-Check

Used by SCA scanner as a probabilistic pre-filter: if a (package, version)
is NOT in the bloom filter, it is definitely not known-safe and needs full
vulnerability lookup. If it IS in the filter, it is probably safe (with a
small false-positive rate), skipping the more expensive interval tree query.

Space: O(m) bits where m is filter size
Lookup: O(k) where k = number of hash functions
False positive rate: ~(1 - e^(-kn/m))^k
"""

import hashlib
import math
from typing import Tuple


class BloomFilter:
    """
    Space-efficient probabilistic set membership test.
    Uses multiple hash functions via double-hashing scheme.
    """

    def __init__(self, expected_items: int = 10000,
                 false_positive_rate: float = 0.01):
        """
        Initialize bloom filter with target capacity and false-positive rate.

        Args:
            expected_items: Expected number of items to insert
            false_positive_rate: Desired false positive probability (0.01 = 1%)
        """
        # Calculate optimal filter size: m = -(n * ln(p)) / (ln(2)^2)
        self._size = max(64, int(
            -(expected_items * math.log(false_positive_rate)) /
            (math.log(2) ** 2)
        ))
        # Calculate optimal number of hash functions: k = (m/n) * ln(2)
        self._num_hashes = max(1, int(
            (self._size / max(1, expected_items)) * math.log(2)
        ))
        # Bit array stored as bytearray for space efficiency
        self._bits = bytearray(math.ceil(self._size / 8))
        self._count = 0

    def _get_hashes(self, item: str) -> Tuple[int, int]:
        """
        Generate two independent hash values using SHA-256.
        All subsequent hashes are derived via double-hashing:
          h_i(x) = (h1(x) + i * h2(x)) mod m
        """
        h = hashlib.sha256(item.encode("utf-8")).digest()
        h1 = int.from_bytes(h[:8], "big")
        h2 = int.from_bytes(h[8:16], "big")
        return h1, h2

    def _bit_positions(self, item: str):
        """Generate k bit positions for an item using double hashing."""
        h1, h2 = self._get_hashes(item)
        for i in range(self._num_hashes):
            yield (h1 + i * h2) % self._size

    def add(self, item: str) -> None:
        """Add an item to the bloom filter."""
        for pos in self._bit_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            self._bits[byte_idx] |= (1 << bit_idx)
        self._count += 1

    def add_package(self, package_name: str, version: str) -> None:
        """Add a known-safe package+version pair."""
        self.add(f"{package_name.lower()}@{version}")

    def might_contain(self, item: str) -> bool:
        """
        Check if item might be in the set.
        Returns False = definitely not present (100% certain).
        Returns True = possibly present (may be false positive).
        """
        for pos in self._bit_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def might_contain_package(self, package_name: str, version: str) -> bool:
        """Check if a package+version pair might be known-safe."""
        return self.might_contain(f"{package_name.lower()}@{version}")

    @property
    def count(self) -> int:
        return self._count

    @property
    def size_bytes(self) -> int:
        return len(self._bits)
