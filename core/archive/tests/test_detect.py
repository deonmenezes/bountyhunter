"""Tests for core/archive/detect.py — magic-byte archive detection."""

from __future__ import annotations

import unittest

from core.archive.detect import detect_format, is_archive


class TestDetectFormat(unittest.TestCase):

    def test_zip_pk0304(self, tmp_path_factory=None):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"PK\x03\x04" + b"\x00" * 100)
            f.flush()
            self.assertEqual(detect_format(f.name), "zip")

    def test_zip_pk0506_empty_archive(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"PK\x05\x06" + b"\x00" * 100)
            f.flush()
            self.assertEqual(detect_format(f.name), "zip")

    def test_zip_pk0708_spanned(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"PK\x07\x08" + b"\x00" * 100)
            f.flush()
            self.assertEqual(detect_format(f.name), "zip")

    def test_gzip(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x1f\x8b" + b"\x00" * 100)
            f.flush()
            self.assertEqual(detect_format(f.name), "gz")

    def test_bz2(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"BZh" + b"\x00" * 100)
            f.flush()
            self.assertEqual(detect_format(f.name), "bz2")

    def test_xz(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\xfd7zXZ\x00" + b"\x00" * 100)
            f.flush()
            self.assertEqual(detect_format(f.name), "xz")

    def test_zstd(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x28\xb5\x2f\xfd" + b"\x00" * 100)
            f.flush()
            self.assertEqual(detect_format(f.name), "zst")

    def test_tar_ustar(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            header = b"\x00" * 257 + b"ustar\x0000" + b"\x00" * 200
            f.write(header)
            f.flush()
            self.assertEqual(detect_format(f.name), "tar")

    def test_tar_ustar_space_variant(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            header = b"\x00" * 257 + b"ustar  \x00" + b"\x00" * 200
            f.write(header)
            f.flush()
            self.assertEqual(detect_format(f.name), "tar")

    def test_unknown_format_returns_none(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"not an archive at all, just random text content")
            f.flush()
            self.assertIsNone(detect_format(f.name))

    def test_empty_file_returns_none(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.flush()
            self.assertIsNone(detect_format(f.name))

    def test_nonexistent_file_returns_none(self):
        self.assertIsNone(detect_format("/nonexistent/path/to/file"))

    def test_short_file_no_tar_false_positive(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 10)
            f.flush()
            self.assertIsNone(detect_format(f.name))


class TestIsArchive(unittest.TestCase):

    def test_true_for_zip(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"PK\x03\x04" + b"\x00" * 100)
            f.flush()
            self.assertTrue(is_archive(f.name))

    def test_false_for_text_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello world")
            f.flush()
            self.assertFalse(is_archive(f.name))

    def test_false_for_nonexistent(self):
        self.assertFalse(is_archive("/does/not/exist"))


if __name__ == "__main__":
    unittest.main()
