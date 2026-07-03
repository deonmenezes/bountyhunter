#!/usr/bin/env python3
"""Tests for reporting formatting utilities."""

import unittest
from core.reporting.formatting import (
    get_display_status, title_case_type, truncate_path, format_elapsed,
)


class TestGetDisplayStatus(unittest.TestCase):

    def test_validate_ruling_exploitable(self):
        self.assertEqual(get_display_status({"ruling": {"status": "exploitable"}}), "Exploitable")

    def test_validate_ruling_confirmed(self):
        self.assertEqual(get_display_status({"ruling": {"status": "confirmed"}}), "Confirmed")

    def test_validate_ruling_ruled_out(self):
        self.assertEqual(get_display_status({"ruling": {"status": "ruled_out"}}), "Ruled Out")

    def test_validate_ruling_constrained(self):
        self.assertEqual(get_display_status({"ruling": {"status": "confirmed_constrained"}}), "Confirmed (Constrained)")

    def test_agentic_exploitable(self):
        self.assertEqual(get_display_status({"is_true_positive": True, "is_exploitable": True}), "Exploitable")

    def test_agentic_false_positive(self):
        self.assertEqual(get_display_status({"is_true_positive": False}), "False Positive")

    def test_agentic_confirmed(self):
        self.assertEqual(get_display_status({"is_true_positive": True, "is_exploitable": False}), "Confirmed")

    def test_agentic_error(self):
        self.assertEqual(get_display_status({"error": "timeout", "error_type": "timeout"}), "Error (timeout)")

    def test_flat_status(self):
        self.assertEqual(get_display_status({"status": "exploitable"}), "Exploitable")

    def test_final_status(self):
        self.assertEqual(get_display_status({"final_status": "confirmed_blocked"}), "Confirmed (Blocked)")

    def test_empty(self):
        self.assertEqual(get_display_status({}), "Unknown")

    def test_validated_ruling(self):
        self.assertEqual(get_display_status({"ruling": {"status": "validated"}}), "Confirmed")

    def test_final_status_overrides_ruling(self):
        """final_status (post-feasibility) takes priority over ruling.status (Stage D)."""
        self.assertEqual(get_display_status({
            "ruling": {"status": "exploitable"},
            "final_status": "confirmed_constrained",
        }), "Confirmed (Constrained)")

    def test_final_status_overrides_ruling_blocked(self):
        self.assertEqual(get_display_status({
            "ruling": {"status": "confirmed"},
            "final_status": "confirmed_blocked",
        }), "Confirmed (Blocked)")

    def test_boolean_overrides_ruling_string(self):
        # Agentic: is_exploitable=True should win over ruling=test_code
        self.assertEqual(get_display_status(
            {"is_true_positive": True, "is_exploitable": True, "ruling": "test_code"}
        ), "Exploitable")

    def test_boolean_false_positive_overrides_ruling(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": False, "ruling": "validated"}
        ), "False Positive")

    def test_boolean_confirmed_when_not_exploitable(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": True, "is_exploitable": False, "ruling": "test_code"}
        ), "Confirmed")

    def test_string_true_coerced_to_exploitable(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": "true", "is_exploitable": "true"}
        ), "Exploitable")

    def test_string_false_coerced_to_false_positive(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": "false"}
        ), "False Positive")

    def test_string_yes_coerced_to_true(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": "yes", "is_exploitable": "no"}
        ), "Confirmed")

    def test_string_zero_coerced_to_false(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": "0"}
        ), "False Positive")

    def test_string_one_coerced_to_true(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": "1", "is_exploitable": "1"}
        ), "Exploitable")

    def test_unknown_string_value_falls_through(self):
        result = get_display_status(
            {"is_true_positive": "maybe", "is_exploitable": "maybe"}
        )
        self.assertNotEqual(result, "Exploitable")

    def test_ruling_as_string_not_dict(self):
        self.assertEqual(get_display_status({"ruling": "exploitable"}), "Exploitable")

    def test_ruling_as_empty_string(self):
        self.assertEqual(get_display_status({"ruling": ""}), "Unknown")

    def test_error_without_error_type(self):
        self.assertEqual(get_display_status({"error": "something"}), "Error (unknown)")

    def test_poc_success_status(self):
        self.assertEqual(get_display_status({"status": "poc_success"}), "Exploitable")

    def test_not_disproven_status(self):
        self.assertEqual(get_display_status({"status": "not_disproven"}), "Unconfirmed")

    def test_disproven_status(self):
        self.assertEqual(get_display_status({"status": "disproven"}), "Ruled Out")

    def test_test_code_status(self):
        self.assertEqual(get_display_status({"status": "test_code"}), "Ruled Out")

    def test_dead_code_status(self):
        self.assertEqual(get_display_status({"status": "dead_code"}), "Ruled Out")

    def test_mitigated_status(self):
        self.assertEqual(get_display_status({"status": "mitigated"}), "Ruled Out")

    def test_unreachable_status(self):
        self.assertEqual(get_display_status({"status": "unreachable"}), "Ruled Out")

    def test_unknown_status_title_cased(self):
        self.assertEqual(get_display_status({"status": "needs_review"}), "Needs Review")


class TestTitleCaseType(unittest.TestCase):

    def test_buffer_overflow(self):
        self.assertEqual(title_case_type("buffer_overflow"), "Buffer Overflow")

    def test_command_injection(self):
        self.assertEqual(title_case_type("command_injection"), "Command Injection")

    def test_empty(self):
        self.assertEqual(title_case_type(""), "—")

    def test_none(self):
        self.assertEqual(title_case_type(None), "—")

    def test_display_name_lookup(self):
        self.assertEqual(title_case_type("null_deref"), "Null Pointer Dereference")
        self.assertEqual(title_case_type("xss"), "Cross-Site Scripting")
        self.assertEqual(title_case_type("sql_injection"), "SQL Injection")

    def test_fallback_for_unlisted(self):
        self.assertEqual(title_case_type("race_condition"), "Race Condition")


class TestTruncatePath(unittest.TestCase):

    def test_short_path(self):
        self.assertEqual(truncate_path("src/foo.py"), "src/foo.py")

    def test_long_path(self):
        result = truncate_path("/very/long/path/to/some/deeply/nested/file.py")
        self.assertTrue(result.startswith("..."))
        self.assertEqual(len(result), 40)

    def test_exact_max_len_not_truncated(self):
        path = "a" * 40
        self.assertEqual(truncate_path(path, max_len=40), path)

    def test_custom_max_len(self):
        result = truncate_path("/a/very/long/path/here.py", max_len=20)
        self.assertTrue(result.startswith("..."))
        self.assertEqual(len(result), 20)

    def test_non_ascii_path_short_enough(self):
        path = "/src/\u4e2d\u6587.py"
        result = truncate_path(path, max_len=40)
        self.assertEqual(result, path)

    def test_non_ascii_path_truncated(self):
        path = "/long/path/" + "\u4e2d" * 30 + "/file.py"
        result = truncate_path(path, max_len=20)
        self.assertTrue(result.startswith("..."))


class TestFormatElapsed(unittest.TestCase):

    def test_seconds(self):
        self.assertEqual(format_elapsed(45), "45s")

    def test_minutes(self):
        self.assertEqual(format_elapsed(125), "2m 5s")

    def test_hours(self):
        self.assertEqual(format_elapsed(3725), "1h 2m")

    def test_zero_seconds(self):
        self.assertEqual(format_elapsed(0), "0s")

    def test_exactly_60_seconds(self):
        self.assertEqual(format_elapsed(60), "1m 0s")

    def test_exactly_3600_seconds(self):
        self.assertEqual(format_elapsed(3600), "1h 0m")


if __name__ == "__main__":
    unittest.main()
