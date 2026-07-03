"""Tests for core/verified_outcome/types.py — VerifiedOutcome dataclass."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from core.verified_outcome.types import (
    Oracle,
    OutcomeStatus,
    VerifiedOutcome,
)


class TestOracle(unittest.TestCase):

    def test_values(self):
        self.assertEqual(Oracle.SANDBOX.value, "sandbox")
        self.assertEqual(Oracle.FUZZER.value, "fuzzer")
        self.assertEqual(Oracle.CODEQL.value, "codeql")
        self.assertEqual(Oracle.WEB.value, "web")
        self.assertEqual(Oracle.MANUAL.value, "manual")

    def test_str_serialisation(self):
        # ``str`` subclass: the member IS its value, so it serialises
        # as a plain string in JSON without a custom encoder. Assert
        # the version-stable contract rather than ``str(...)`` repr,
        # which changed for str-Enums in Python 3.12.
        self.assertIsInstance(Oracle.SANDBOX, str)
        self.assertEqual(Oracle.SANDBOX, "sandbox")
        self.assertEqual(json.dumps(Oracle.SANDBOX), '"sandbox"')

    def test_from_value(self):
        self.assertEqual(Oracle("sandbox"), Oracle.SANDBOX)
        self.assertEqual(Oracle("manual"), Oracle.MANUAL)


class TestOutcomeStatus(unittest.TestCase):

    def test_values(self):
        self.assertEqual(OutcomeStatus.VERIFIED.value, "verified")
        self.assertEqual(OutcomeStatus.REFUTED.value, "refuted")
        self.assertEqual(OutcomeStatus.INCONCLUSIVE.value, "inconclusive")


class TestVerifiedOutcome(unittest.TestCase):

    def _make_outcome(self, **kwargs):
        defaults = {
            "finding_id": "F-001",
            "oracle": Oracle.SANDBOX,
            "status": OutcomeStatus.VERIFIED,
            "reproducible": True,
        }
        defaults.update(kwargs)
        return VerifiedOutcome(**defaults)

    def test_basic_construction(self):
        vo = self._make_outcome()
        self.assertEqual(vo.finding_id, "F-001")
        self.assertEqual(vo.oracle, Oracle.SANDBOX)
        self.assertEqual(vo.status, OutcomeStatus.VERIFIED)
        self.assertTrue(vo.reproducible)

    def test_default_evidence_is_empty_dict(self):
        vo = self._make_outcome()
        self.assertEqual(vo.evidence, {})

    def test_optional_fields_default_to_none(self):
        vo = self._make_outcome()
        self.assertIsNone(vo.cwe_id)
        self.assertIsNone(vo.file)
        self.assertIsNone(vo.produced_by)
        self.assertIsNone(vo.authorization)

    def test_timestamp_auto_set(self):
        vo = self._make_outcome()
        self.assertIsInstance(vo.timestamp, datetime)
        self.assertIsNotNone(vo.timestamp.tzinfo)

    def test_to_dict(self):
        ts = datetime(2026, 6, 30, 12, 0, 0, tzinfo=timezone.utc)
        vo = self._make_outcome(
            cwe_id="CWE-89",
            file="src/auth.py",
            evidence={"trigger": "payload"},
            timestamp=ts,
        )
        d = vo.to_dict()
        self.assertEqual(d["finding_id"], "F-001")
        self.assertEqual(d["oracle"], "sandbox")
        self.assertEqual(d["status"], "verified")
        self.assertTrue(d["reproducible"])
        self.assertEqual(d["cwe_id"], "CWE-89")
        self.assertEqual(d["file"], "src/auth.py")
        self.assertEqual(d["evidence"], {"trigger": "payload"})
        self.assertEqual(d["timestamp"], "2026-06-30T12:00:00+00:00")

    def test_from_dict_roundtrip(self):
        original = self._make_outcome(
            cwe_id="CWE-79",
            file="app.js",
            produced_by="agent-1",
            authorization="pentest-contract-42",
            evidence={"url": "/login"},
        )
        d = original.to_dict()
        restored = VerifiedOutcome.from_dict(d)
        self.assertEqual(restored.finding_id, original.finding_id)
        self.assertEqual(restored.oracle, original.oracle)
        self.assertEqual(restored.status, original.status)
        self.assertEqual(restored.reproducible, original.reproducible)
        self.assertEqual(restored.cwe_id, original.cwe_id)
        self.assertEqual(restored.file, original.file)
        self.assertEqual(restored.produced_by, original.produced_by)
        self.assertEqual(restored.authorization, original.authorization)
        self.assertEqual(restored.evidence, original.evidence)

    def test_from_dict_missing_timestamp_uses_now(self):
        d = {
            "finding_id": "F-002",
            "oracle": "fuzzer",
            "status": "refuted",
            "reproducible": False,
        }
        vo = VerifiedOutcome.from_dict(d)
        self.assertEqual(vo.oracle, Oracle.FUZZER)
        self.assertEqual(vo.status, OutcomeStatus.REFUTED)
        self.assertIsInstance(vo.timestamp, datetime)

    def test_from_dict_datetime_timestamp_passthrough(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        d = {
            "finding_id": "F-003",
            "oracle": "codeql",
            "status": "inconclusive",
            "timestamp": ts,
        }
        vo = VerifiedOutcome.from_dict(d)
        self.assertEqual(vo.timestamp, ts)

    def test_from_dict_extra_keys_tolerated(self):
        d = {
            "finding_id": "F-004",
            "oracle": "manual",
            "status": "verified",
            "reproducible": True,
            "extra_field": "ignored",
            "another": 42,
        }
        vo = VerifiedOutcome.from_dict(d)
        self.assertEqual(vo.finding_id, "F-004")

    def test_from_dict_missing_evidence_defaults_to_empty(self):
        d = {
            "finding_id": "F-005",
            "oracle": "web",
            "status": "verified",
        }
        vo = VerifiedOutcome.from_dict(d)
        self.assertEqual(vo.evidence, {})


if __name__ == "__main__":
    unittest.main()
