"""Tests for core/archive/compression.py — single-file decompression."""

from __future__ import annotations

import bz2
import gzip
import lzma
import unittest

from core.archive.compression import (
    decompress_single,
    looks_like_tar,
)
from core.archive.errors import (
    ArchiveError,
    DecompressionLimitExceeded,
    UnsupportedArchive,
)


class TestDecompressSingle(unittest.TestCase):

    def test_gz_decompress(self, tmp_path_factory=None):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as f:
            compressed = gzip.compress(b"hello world")
            f.write(compressed)
            f.flush()
            result = decompress_single(f.name, "gz")
            self.assertEqual(result, b"hello world")

    def test_bz2_decompress(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bz2", delete=False) as f:
            compressed = bz2.compress(b"bz2 content here")
            f.write(compressed)
            f.flush()
            result = decompress_single(f.name, "bz2")
            self.assertEqual(result, b"bz2 content here")

    def test_xz_decompress(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".xz", delete=False) as f:
            compressed = lzma.compress(b"xz payload")
            f.write(compressed)
            f.flush()
            result = decompress_single(f.name, "xz")
            self.assertEqual(result, b"xz payload")

    def test_unsupported_format_raises(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".rar", delete=False) as f:
            f.write(b"dummy")
            f.flush()
            with self.assertRaises(UnsupportedArchive):
                decompress_single(f.name, "rar")

    def test_bomb_defense_raises_on_oversize(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as f:
            # Compress 200 bytes but set cap to 50
            compressed = gzip.compress(b"A" * 200)
            f.write(compressed)
            f.flush()
            with self.assertRaises(DecompressionLimitExceeded):
                decompress_single(f.name, "gz", max_bytes=50)

    def test_corrupt_stream_raises_archive_error(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as f:
            # Write partial gz header followed by garbage
            f.write(b"\x1f\x8b\x08" + b"\xff" * 50)
            f.flush()
            with self.assertRaises(ArchiveError):
                decompress_single(f.name, "gz")


class TestLooksLikeTar(unittest.TestCase):

    def test_posix_tar_header(self):
        data = b"\x00" * 257 + b"ustar\x0000" + b"\x00" * 200
        self.assertTrue(looks_like_tar(data))

    def test_gnu_tar_header(self):
        data = b"\x00" * 257 + b"ustar  \x00" + b"\x00" * 200
        self.assertTrue(looks_like_tar(data))

    def test_short_ustar_magic(self):
        data = b"\x00" * 257 + b"ustar" + b"\x00" * 200
        self.assertTrue(looks_like_tar(data))

    def test_not_tar(self):
        data = b"\x00" * 257 + b"notatar!" + b"\x00" * 200
        self.assertFalse(looks_like_tar(data))

    def test_too_short_data(self):
        data = b"\x00" * 100
        self.assertFalse(looks_like_tar(data))

    def test_empty_data(self):
        self.assertFalse(looks_like_tar(b""))


if __name__ == "__main__":
    unittest.main()
