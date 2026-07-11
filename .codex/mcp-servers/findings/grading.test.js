"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { gradeToDisposition } = require("./grading.js");

const HIGH_GRADE = {
  impact: 30,
  proof: 25,
  severity_accuracy: 15,
  chain: 15,
  report_quality: 15,
}; // total 100

test("gradeToDisposition returns null when no grade is given", () => {
  assert.equal(gradeToDisposition(null, "critical"), null);
});

test("SUBMIT requires total>=40 AND a medium+ severity", () => {
  assert.equal(
    gradeToDisposition(HIGH_GRADE, "critical").disposition,
    "SUBMIT",
  );
  assert.equal(gradeToDisposition(HIGH_GRADE, "high").disposition, "SUBMIT");
  assert.equal(gradeToDisposition(HIGH_GRADE, "medium").disposition, "SUBMIT");
});

test("a high-scoring but low/unrated-severity finding is downgraded to HOLD, not SUBMIT", () => {
  assert.equal(gradeToDisposition(HIGH_GRADE, "low").disposition, "HOLD");
  assert.equal(gradeToDisposition(HIGH_GRADE, "info").disposition, "HOLD");
  assert.equal(gradeToDisposition(HIGH_GRADE, null).disposition, "HOLD");
  assert.equal(gradeToDisposition(HIGH_GRADE, undefined).disposition, "HOLD");
});

test("a low total is HOLD in the 20-39 band regardless of severity", () => {
  const grade = {
    impact: 10,
    proof: 10,
    severity_accuracy: 0,
    chain: 0,
    report_quality: 5,
  }; // total 25
  assert.equal(gradeToDisposition(grade, "critical").disposition, "HOLD");
});

test("a very low total is SKIP regardless of severity", () => {
  const grade = {
    impact: 2,
    proof: 0,
    severity_accuracy: 0,
    chain: 0,
    report_quality: 0,
  }; // total 2
  assert.equal(gradeToDisposition(grade, "critical").disposition, "SKIP");
});

test("total is computed the same regardless of disposition", () => {
  assert.equal(gradeToDisposition(HIGH_GRADE, "low").total, 100);
});
