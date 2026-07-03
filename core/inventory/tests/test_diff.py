"""Tests for core/inventory/diff.py — inventory comparison."""

from __future__ import annotations

import unittest

from core.inventory.diff import compare_inventories


class TestCompareInventories(unittest.TestCase):

    def _inv(self, files, binary_sha=None):
        inv = {"files": [{"path": p, "sha256": s} for p, s in files]}
        if binary_sha is not None:
            inv["binary"] = {"sha256": binary_sha}
        return inv

    def test_identical_inventories_return_none(self):
        old = self._inv([("a.c", "abc123"), ("b.c", "def456")])
        new = self._inv([("a.c", "abc123"), ("b.c", "def456")])
        self.assertIsNone(compare_inventories(old, new))

    def test_added_file_detected(self):
        old = self._inv([("a.c", "abc123")])
        new = self._inv([("a.c", "abc123"), ("b.c", "def456")])
        diff = compare_inventories(old, new)
        self.assertIsNotNone(diff)
        self.assertIn("b.c", diff["added"])
        self.assertTrue(diff["source_changed"])

    def test_removed_file_detected(self):
        old = self._inv([("a.c", "abc123"), ("b.c", "def456")])
        new = self._inv([("a.c", "abc123")])
        diff = compare_inventories(old, new)
        self.assertIsNotNone(diff)
        self.assertIn("b.c", diff["removed"])
        self.assertTrue(diff["source_changed"])

    def test_modified_file_detected(self):
        old = self._inv([("a.c", "abc123")])
        new = self._inv([("a.c", "xyz789")])
        diff = compare_inventories(old, new)
        self.assertIsNotNone(diff)
        self.assertIn("a.c", diff["modified"])
        self.assertTrue(diff["source_changed"])

    def test_binary_changed(self):
        old = self._inv([("a.c", "abc")], binary_sha="bin_old")
        new = self._inv([("a.c", "abc")], binary_sha="bin_new")
        diff = compare_inventories(old, new)
        self.assertIsNotNone(diff)
        self.assertTrue(diff["binary_changed"])
        self.assertEqual(diff["binary_old_sha256"], "bin_old")
        self.assertEqual(diff["binary_new_sha256"], "bin_new")

    def test_binary_added_is_change(self):
        old = self._inv([("a.c", "abc")])
        new = self._inv([("a.c", "abc")], binary_sha="bin_new")
        diff = compare_inventories(old, new)
        self.assertIsNotNone(diff)
        self.assertTrue(diff["binary_changed"])

    def test_binary_removed_is_change(self):
        old = self._inv([("a.c", "abc")], binary_sha="bin_old")
        new = self._inv([("a.c", "abc")])
        diff = compare_inventories(old, new)
        self.assertIsNotNone(diff)
        self.assertTrue(diff["binary_changed"])

    def test_both_binary_none_is_no_change(self):
        old = self._inv([("a.c", "abc")])
        new = self._inv([("a.c", "abc")])
        self.assertIsNone(compare_inventories(old, new))

    def test_old_inventory_without_sha256_returns_none(self):
        old = {"files": [{"path": "a.c"}]}
        new = self._inv([("a.c", "abc")])
        self.assertIsNone(compare_inventories(old, new))

    def test_multiple_changes_combined(self):
        old = self._inv([
            ("a.c", "aaa"),
            ("b.c", "bbb"),
            ("c.c", "ccc"),
        ])
        new = self._inv([
            ("a.c", "aaa"),
            ("b.c", "modified"),
            ("d.c", "ddd"),
        ])
        diff = compare_inventories(old, new)
        self.assertIsNotNone(diff)
        self.assertIn("d.c", diff["added"])
        self.assertIn("c.c", diff["removed"])
        self.assertIn("b.c", diff["modified"])

    def test_no_source_change_only_binary(self):
        old = self._inv([("a.c", "abc")], binary_sha="old")
        new = self._inv([("a.c", "abc")], binary_sha="new")
        diff = compare_inventories(old, new)
        self.assertFalse(diff["source_changed"])
        self.assertTrue(diff["binary_changed"])


if __name__ == "__main__":
    unittest.main()
