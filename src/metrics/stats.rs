//! Descriptive statistics over sample sets (F-14).
//!
//! Implemented natively (the old `bench_log` crate is not part of the current
//! SCG workspace). Everything here is pure, deterministic, and unit-tested so a
//! distribution of latencies or per-run throughputs can be summarised the same
//! way every time:
//!   * central tendency / spread: mean, median, sample standard deviation,
//!   * tail percentiles: p50/p90/p95/p99/p99.9 (linear interpolation, numpy
//!     "type 7"), min, max,
//!   * confidence: 95 % confidence-interval half-width using Student's *t* (so
//!     small N-run aggregates aren't over-confident),
//!   * stability: coefficient of variation (stddev / mean),
//!   * robustness: Tukey IQR outlier removal (`1.5 × IQR` fences).
//!
//! Inputs are plain `f64` slices; the caller chooses the unit (we use
//! microseconds for latency and Gbit/s for throughput).
#![allow(dead_code)]

use serde::Serialize;

/// A full descriptive summary of a sample set.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Summary {
    pub n: usize,
    pub mean: f64,
    pub median: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub p999: f64,
    /// 95 % CI half-width about the mean (Student's *t*).
    pub ci95: f64,
    /// Coefficient of variation = stddev / mean.
    pub cov: f64,
}

impl Summary {
    /// An all-zero summary for an empty sample set.
    pub fn empty() -> Self {
        Summary {
            n: 0,
            mean: 0.0,
            median: 0.0,
            stddev: 0.0,
            min: 0.0,
            max: 0.0,
            p50: 0.0,
            p90: 0.0,
            p95: 0.0,
            p99: 0.0,
            p999: 0.0,
            ci95: 0.0,
            cov: 0.0,
        }
    }
}

/// Arithmetic mean. Returns 0.0 for an empty slice.
pub fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Sample standard deviation (Bessel-corrected, divides by N-1).
///
/// Returns 0.0 for fewer than two samples.
pub fn stddev(xs: &[f64]) -> f64 {
    let n = xs.len();
    if n < 2 {
        return 0.0;
    }
    let m = mean(xs);
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (n as f64 - 1.0);
    var.sqrt()
}

/// Percentile `p` (0..=100) over `sorted` (ascending) using linear
/// interpolation between closest ranks (numpy "type 7" / R-7).
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    match sorted.len() {
        0 => return f64::NAN,
        1 => return sorted[0],
        _ => {}
    }
    let p = p.clamp(0.0, 100.0);
    let rank = (p / 100.0) * (sorted.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return sorted[lo];
    }
    let frac = rank - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

/// Two-sided 95 % critical value of Student's *t* for `df` degrees of freedom.
///
/// Small-df values are tabulated; for `df >= 120` we use the normal limit
/// (1.96). This keeps confidence intervals honest when aggregating a handful of
/// runs (e.g. N=5 → t=2.776, vs 1.96 for the normal approximation).
pub fn t_value_95(df: usize) -> f64 {
    const TABLE: &[(usize, f64)] = &[
        (1, 12.706),
        (2, 4.303),
        (3, 3.182),
        (4, 2.776),
        (5, 2.571),
        (6, 2.447),
        (7, 2.365),
        (8, 2.306),
        (9, 2.262),
        (10, 2.228),
        (12, 2.179),
        (15, 2.131),
        (20, 2.086),
        (24, 2.064),
        (30, 2.042),
        (40, 2.021),
        (60, 2.000),
        (120, 1.980),
    ];
    if df == 0 {
        return 0.0;
    }
    if df >= 120 {
        return 1.960;
    }
    // Nearest tabulated df at or above the request (conservative: wider CI).
    for &(d, t) in TABLE {
        if df <= d {
            return t;
        }
    }
    1.960
}

/// 95 % confidence-interval half-width for the mean of `xs`.
///
/// `half_width = t(N-1) * stddev / sqrt(N)`. The interval is `mean ± half_width`.
pub fn ci95_halfwidth(xs: &[f64]) -> f64 {
    let n = xs.len();
    if n < 2 {
        return 0.0;
    }
    let sd = stddev(xs);
    t_value_95(n - 1) * sd / (n as f64).sqrt()
}

/// Coefficient of variation (stddev / mean). 0.0 when the mean is ~0.
pub fn coefficient_of_variation(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m.abs() < f64::EPSILON {
        return 0.0;
    }
    stddev(xs) / m
}

/// Remove outliers using Tukey's `1.5 × IQR` fences.
///
/// Returns the kept samples (original order) and the number removed. Sets with
/// fewer than four samples are returned unchanged (IQR is not meaningful).
pub fn remove_outliers_iqr(xs: &[f64]) -> (Vec<f64>, usize) {
    if xs.len() < 4 {
        return (xs.to_vec(), 0);
    }
    let mut sorted = xs.to_vec();
    sorted.sort_by(f64::total_cmp);
    let q1 = percentile(&sorted, 25.0);
    let q3 = percentile(&sorted, 75.0);
    let iqr = q3 - q1;
    let lo = q1 - 1.5 * iqr;
    let hi = q3 + 1.5 * iqr;
    let kept: Vec<f64> = xs.iter().copied().filter(|&x| x >= lo && x <= hi).collect();
    let removed = xs.len() - kept.len();
    (kept, removed)
}

/// Compute a full [`Summary`] of `xs`. Does not mutate the input.
pub fn summarize(xs: &[f64]) -> Summary {
    if xs.is_empty() {
        return Summary::empty();
    }
    let mut sorted = xs.to_vec();
    sorted.sort_by(f64::total_cmp);
    let m = mean(xs);
    Summary {
        n: xs.len(),
        mean: m,
        median: percentile(&sorted, 50.0),
        stddev: stddev(xs),
        min: sorted[0],
        max: sorted[sorted.len() - 1],
        p50: percentile(&sorted, 50.0),
        p90: percentile(&sorted, 90.0),
        p95: percentile(&sorted, 95.0),
        p99: percentile(&sorted, 99.0),
        p999: percentile(&sorted, 99.9),
        ci95: ci95_halfwidth(xs),
        cov: coefficient_of_variation(xs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() <= eps
    }

    #[test]
    fn mean_and_stddev_known() {
        let xs = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        assert!(approx(mean(&xs), 5.0, 1e-9));
        // sample stddev of this classic set is ~2.138 (population is 2.0).
        assert!(approx(stddev(&xs), 2.1380899, 1e-6));
    }

    #[test]
    fn percentiles_on_1_to_100() {
        let xs: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        assert!(approx(percentile(&xs, 0.0), 1.0, 1e-9));
        assert!(approx(percentile(&xs, 100.0), 100.0, 1e-9));
        // type-7: p50 of 1..100 is 50.5
        assert!(approx(percentile(&xs, 50.0), 50.5, 1e-9));
        assert!(approx(percentile(&xs, 99.0), 99.01, 1e-9));
    }

    #[test]
    fn percentile_single_and_empty() {
        assert!(percentile(&[], 50.0).is_nan());
        assert_eq!(percentile(&[42.0], 99.9), 42.0);
    }

    #[test]
    fn iqr_removes_obvious_outlier() {
        let xs = [10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0, 1000.0];
        let (kept, removed) = remove_outliers_iqr(&xs);
        assert_eq!(removed, 1);
        assert!(!kept.contains(&1000.0));
    }

    #[test]
    fn iqr_keeps_small_sets() {
        let xs = [1.0, 2.0, 100.0];
        let (kept, removed) = remove_outliers_iqr(&xs);
        assert_eq!(removed, 0);
        assert_eq!(kept.len(), 3);
    }

    #[test]
    fn ci_uses_t_for_small_n() {
        // N=5, stddev=1 → half = t(4)/sqrt(5) = 2.776/2.2360 ≈ 1.2415
        let xs = [4.0, 5.0, 5.0, 5.0, 6.0]; // mean 5, stddev 0.7071
        let half = ci95_halfwidth(&xs);
        let expected = 2.776 * stddev(&xs) / (5.0f64).sqrt();
        assert!(approx(half, expected, 1e-6));
    }

    #[test]
    fn cov_zero_mean_is_zero() {
        assert_eq!(coefficient_of_variation(&[0.0, 0.0, 0.0]), 0.0);
    }

    #[test]
    fn summarize_basic() {
        let xs: Vec<f64> = (1..=10).map(|i| i as f64).collect();
        let s = summarize(&xs);
        assert_eq!(s.n, 10);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.max, 10.0);
        assert!(approx(s.mean, 5.5, 1e-9));
        assert!(approx(s.median, 5.5, 1e-9));
    }

    #[test]
    fn summarize_empty_is_zero() {
        let s = summarize(&[]);
        assert_eq!(s.n, 0);
        assert_eq!(s.mean, 0.0);
    }
}
