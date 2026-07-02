//! Precision/recall/F1 + per-FP-category breakdown for a `run_corpus` CSV.

const VERDICT_TRUE_POSITIVE: &str = "true_positive";
const VERDICT_FALSE_POSITIVE: &str = "false_positive";
const FP_MISSING_SANITIZER_MODEL: &str = "missing_sanitizer_model";

/// Minimum FP share `missing_sanitizer_model` must reach (`PIVOT_GATE_THRESHOLD`).
pub const PIVOT_GATE_THRESHOLD: f64 = 0.10;

/// One corpus CSV row's relevant fields.
#[derive(Clone, Debug)]
pub struct Row {
    pub label_verdict: String,
    pub validator_label: String,
    pub fp_category: String,
}

impl Row {
    pub fn new(label_verdict: &str, validator_label: &str, fp_category: &str) -> Self {
        Row {
            label_verdict: label_verdict.to_string(),
            validator_label: validator_label.to_string(),
            fp_category: fp_category.to_string(),
        }
    }
}

/// Aggregated confusion-matrix counts (`Metrics`); `exploitable` is the positive
/// class. `fp_categories` keeps insertion order (like `collections.Counter`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Metrics {
    pub total: usize,
    pub tp: usize,
    pub fp: usize,
    pub tn: usize,
    pub fn_: usize,
    pub uncertain: usize,
    pub fp_categories: Vec<(String, usize)>,
}

impl Metrics {
    fn bump_category(&mut self, cat: &str) {
        if let Some(entry) = self.fp_categories.iter_mut().find(|(k, _)| k == cat) {
            entry.1 += 1;
        } else {
            self.fp_categories.push((cat.to_string(), 1));
        }
    }

    fn category_count(&self, cat: &str) -> usize {
        self.fp_categories.iter().find(|(k, _)| k == cat).map(|(_, c)| *c).unwrap_or(0)
    }

    fn total_fps(&self) -> usize {
        self.fp_categories.iter().map(|(_, c)| *c).sum()
    }

    /// `tp / (tp + fp)`, or `None` when there are no positive predictions.
    pub fn precision(&self) -> Option<f64> {
        let denom = self.tp + self.fp;
        (denom != 0).then(|| self.tp as f64 / denom as f64)
    }

    /// `tp / (tp + fn)`, or `None` when there are no positive labels.
    pub fn recall(&self) -> Option<f64> {
        let denom = self.tp + self.fn_;
        (denom != 0).then(|| self.tp as f64 / denom as f64)
    }

    /// Harmonic mean of precision and recall, or `None` when undefined.
    pub fn f1(&self) -> Option<f64> {
        let (p, r) = (self.precision()?, self.recall()?);
        if p + r == 0.0 {
            return None;
        }
        Some(2.0 * p * r / (p + r))
    }

    /// `most_common()` order: count descending, ties in insertion order.
    fn most_common(&self) -> Vec<(String, usize)> {
        let mut v = self.fp_categories.clone();
        v.sort_by(|a, b| b.1.cmp(&a.1)); // stable -> ties keep insertion order
        v
    }
}

/// Accumulate confusion-matrix metrics from corpus rows (`compute`). The CSV
/// read stays Python; this consumes the already-parsed rows.
pub fn compute(rows: &[Row]) -> Metrics {
    let mut m = Metrics::default();
    for row in rows {
        m.total += 1;
        let label = row.label_verdict.as_str();
        let v = row.validator_label.as_str();
        if label == VERDICT_FALSE_POSITIVE && !row.fp_category.is_empty() {
            m.bump_category(&row.fp_category);
        }
        if v == "uncertain" {
            m.uncertain += 1;
            continue;
        }
        if v == VERDICT_TRUE_POSITIVE {
            if label == VERDICT_TRUE_POSITIVE {
                m.tp += 1;
            } else {
                m.fp += 1;
            }
        } else if v == VERDICT_FALSE_POSITIVE {
            if label == VERDICT_TRUE_POSITIVE {
                m.fn_ += 1;
            } else {
                m.tn += 1;
            }
        }
    }
    m
}

/// Python `format(share * 100, ".1f") + "%"` (i.e. `{share:.1%}`).
fn pct1(share: f64) -> String {
    format!("{:.1}%", share * 100.0)
}

/// Python `format(share * 100, ".0f") + "%"` (i.e. `{share:.0%}`).
fn pct0(share: f64) -> String {
    format!("{:.0}%", share * 100.0)
}

/// Human-readable metrics report (`render`).
pub fn render(m: &Metrics) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("Total findings: {}", m.total));
    let tp_total = m.tp + m.fn_;
    let fp_total = m.fp + m.tn;
    lines.push(format!("  True positives:  {tp_total}  (validator-confirmed: {}, missed: {})", m.tp, m.fn_));
    lines.push(format!("  False positives: {fp_total}  (suppressed: {}, leaked: {})", m.tn, m.fp));
    lines.push(format!("  Uncertain:       {}", m.uncertain));
    lines.push(String::new());
    lines.push("Validator metrics:".to_string());
    lines.push(match m.precision() {
        Some(p) => format!("  Precision: {p:.3}"),
        None => "  Precision: undefined (no exploitable predictions)".to_string(),
    });
    lines.push(match m.recall() {
        Some(r) => format!("  Recall:    {r:.3}"),
        None => "  Recall:    undefined (no positives in labels)".to_string(),
    });
    lines.push(match m.f1() {
        Some(f) => format!("  F1:        {f:.3}"),
        None => "  F1:        undefined".to_string(),
    });
    lines.push(String::new());
    lines.push("FP category distribution:".to_string());
    if m.fp_categories.is_empty() {
        lines.push("  (no labelled FPs in corpus)".to_string());
    } else {
        let total_fps = m.total_fps() as f64;
        for (cat, count) in m.most_common() {
            let pct = count as f64 / total_fps * 100.0;
            lines.push(format!("  {cat}: {count} ({pct:.1}%)"));
        }
    }
    lines.join("\n")
}

/// Enforce the design pivot gate (`check_pivot_gate`): returns `(ok, message)`.
pub fn check_pivot_gate(m: &Metrics) -> (bool, String) {
    let total_fps = m.total_fps();
    if total_fps == 0 {
        return (false, "no FPs in corpus; pivot gate undefined".to_string());
    }
    let share = m.category_count(FP_MISSING_SANITIZER_MODEL) as f64 / total_fps as f64;
    if share >= PIVOT_GATE_THRESHOLD {
        (true, format!("missing_sanitizer_model = {} of FPs (threshold {})", pct1(share), pct0(PIVOT_GATE_THRESHOLD)))
    } else {
        (false, format!("missing_sanitizer_model = {} of FPs (BELOW threshold {})", pct1(share), pct0(PIVOT_GATE_THRESHOLD)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Row> {
        vec![
            Row::new("true_positive", "true_positive", ""),
            Row::new("true_positive", "false_positive", ""),
            Row::new("false_positive", "true_positive", "missing_sanitizer_model"),
            Row::new("false_positive", "false_positive", "other"),
            Row::new("false_positive", "uncertain", "other"),
        ]
    }

    #[test]
    fn confusion_and_metrics() {
        let m = compute(&sample());
        assert_eq!((m.total, m.tp, m.fp, m.tn, m.fn_, m.uncertain), (5, 1, 1, 1, 1, 1));
        assert_eq!(m.precision(), Some(0.5));
        assert_eq!(m.recall(), Some(0.5));
        assert_eq!(m.f1(), Some(0.5));
        // fp_categories counted even for the uncertain row (before the skip).
        assert_eq!(m.category_count("other"), 2);
        assert_eq!(m.category_count("missing_sanitizer_model"), 1);
        // most_common: count desc.
        assert_eq!(m.most_common(), vec![("other".into(), 2), ("missing_sanitizer_model".into(), 1)]);
    }

    #[test]
    fn undefined_metrics() {
        let m = compute(&[]);
        assert_eq!(m.precision(), None);
        assert_eq!(m.recall(), None);
        assert_eq!(m.f1(), None);
    }

    #[test]
    fn pivot_gate() {
        let m = compute(&sample());
        assert_eq!(check_pivot_gate(&m), (true, "missing_sanitizer_model = 33.3% of FPs (threshold 10%)".to_string()));
        // No FPs -> undefined.
        let empty = compute(&[Row::new("true_positive", "true_positive", "")]);
        assert_eq!(check_pivot_gate(&empty), (false, "no FPs in corpus; pivot gate undefined".to_string()));
    }

    #[test]
    fn render_report() {
        let expected = "\
Total findings: 5
  True positives:  2  (validator-confirmed: 1, missed: 1)
  False positives: 2  (suppressed: 1, leaked: 1)
  Uncertain:       1

Validator metrics:
  Precision: 0.500
  Recall:    0.500
  F1:        0.500

FP category distribution:
  other: 2 (66.7%)
  missing_sanitizer_model: 1 (33.3%)";
        assert_eq!(render(&compute(&sample())), expected);
    }
}
