"""Tests for core/startup/banner.py — startup banner formatting."""

from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest.mock import patch

from core.startup.banner import format_banner, read_logo, read_random_quote


class TestReadLogo(unittest.TestCase):

    def test_returns_empty_string_when_asset_missing(self):
        with patch("core.startup.banner._ASSETS", pathlib.Path("/nonexistent")):
            self.assertEqual(read_logo(), "")

    def test_returns_content_when_asset_exists(self):
        with tempfile.TemporaryDirectory() as td:
            assets = pathlib.Path(td)
            (assets / "mantishack-offset").write_text("LOGO ART\n\n")
            with patch("core.startup.banner._ASSETS", assets):
                result = read_logo()
                self.assertEqual(result, "LOGO ART")


class TestReadRandomQuote(unittest.TestCase):

    def test_returns_fallback_when_asset_missing(self):
        with patch("core.startup.banner._ASSETS", pathlib.Path("/nonexistent")):
            self.assertEqual(read_random_quote(), '"Hack the planet!"')

    def test_returns_fallback_for_empty_file(self):
        with tempfile.TemporaryDirectory() as td:
            assets = pathlib.Path(td)
            (assets / "hackers-8ball").write_text("")
            with patch("core.startup.banner._ASSETS", assets):
                self.assertEqual(read_random_quote(), '"Hack the planet!"')

    def test_returns_a_line_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            assets = pathlib.Path(td)
            (assets / "hackers-8ball").write_text("only one quote\n")
            with patch("core.startup.banner._ASSETS", assets):
                self.assertEqual(read_random_quote(), "only one quote")


class TestFormatBanner(unittest.TestCase):

    def test_minimal_banner_with_no_optional_sections(self):
        result = format_banner(
            logo="",
            quote="test quote",
            tool_results=[("semgrep", True), ("codeql", False)],
            tool_warnings=[],
            llm_lines=[],
            llm_warnings=[],
            env_parts=["sandbox ✓"],
            env_warnings=[],
        )
        self.assertIn("semgrep ✓", result)
        self.assertIn("codeql ✗", result)
        self.assertIn("sandbox ✓", result)
        self.assertIn("test quote", result)
        self.assertIn("defensive security research", result)

    def test_logo_appears_at_top(self):
        result = format_banner(
            logo="ASCII LOGO",
            quote="q",
            tool_results=[],
            tool_warnings=[],
            llm_lines=[],
            llm_warnings=[],
            env_parts=[],
            env_warnings=[],
        )
        self.assertTrue(result.startswith("ASCII LOGO"))

    def test_warnings_ordered_unavailable_first(self):
        result = format_banner(
            logo="",
            quote="q",
            tool_results=[],
            tool_warnings=["limited: only basic rules"],
            llm_lines=[],
            llm_warnings=["unavailable: no key set"],
            env_parts=[],
            env_warnings=[],
        )
        lines = result.split("\n")
        warn_lines = [line for line in lines if "warn:" in line or line.strip().startswith("unavailable") or line.strip().startswith("limited")]
        first_warn_content = warn_lines[0] if warn_lines else ""
        self.assertIn("unavailable", first_warn_content)

    def test_project_line_included(self):
        result = format_banner(
            logo="",
            quote="q",
            tool_results=[],
            tool_warnings=[],
            llm_lines=[],
            llm_warnings=[],
            env_parts=[],
            env_warnings=[],
            project_line="project: myapp (3 runs)",
        )
        self.assertIn("project: myapp (3 runs)", result)

    def test_lang_line_included(self):
        result = format_banner(
            logo="",
            quote="q",
            tool_results=[],
            tool_warnings=[],
            llm_lines=[],
            llm_warnings=[],
            env_parts=[],
            env_warnings=[],
            lang_line="  lang: Python 3.12 + C",
        )
        self.assertIn("lang: Python 3.12 + C", result)

    def test_llm_lines_appear_in_output(self):
        result = format_banner(
            logo="",
            quote="q",
            tool_results=[],
            tool_warnings=[],
            llm_lines=["   llm: claude-4 (anthropic)"],
            llm_warnings=[],
            env_parts=[],
            env_warnings=[],
        )
        self.assertIn("llm: claude-4 (anthropic)", result)

    def test_multiple_warnings_indented(self):
        result = format_banner(
            logo="",
            quote="q",
            tool_results=[],
            tool_warnings=["unavailable: A", "other warn"],
            llm_lines=[],
            llm_warnings=[],
            env_parts=[],
            env_warnings=[],
        )
        lines = result.split("\n")
        warn_lines = [line for line in lines if "warn:" in line]
        self.assertTrue(len(warn_lines) >= 1)


if __name__ == "__main__":
    unittest.main()
