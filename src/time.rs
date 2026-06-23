//! Monotonic + wall clocks for timestamping (F-12, F-13).
//!
//! Latency is measured from a send timestamp embedded in each message. We use
//! `CLOCK_MONOTONIC` (never steps backwards, unaffected by NTP/settimeofday) for
//! all latency math on a single host. Wall-clock `CLOCK_REALTIME` is only used
//! for human-facing run timestamps / result-directory names.
//!
//! Consumed by the workload/metrics engine in later phases.
#![allow(dead_code)]

/// Read `CLOCK_MONOTONIC` as nanoseconds.
///
/// Monotonic time has an arbitrary origin, so only *differences* are meaningful
/// — which is exactly what latency is. Comparable within one host only.
#[inline]
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, fully-initialised timespec we own; clock_gettime
    // only writes into it and the clock id is a documented constant.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Read `CLOCK_REALTIME` as nanoseconds since the Unix epoch.
///
/// Used only for naming/reporting, never for latency.
#[inline]
pub fn realtime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: see `monotonic_ns`.
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Busy/sleep hybrid wait until the monotonic clock reaches `deadline_ns`.
///
/// Pacing accuracy matters for the workload generator (NFR-PERF): a plain
/// `thread::sleep` can overshoot by hundreds of microseconds. We sleep for the
/// bulk of the interval, then spin for the final ~50 µs so send times land
/// close to schedule without burning a whole core for the entire wait.
#[inline]
pub fn sleep_until_ns(deadline_ns: u64) {
    const SPIN_THRESHOLD_NS: u64 = 50_000;
    loop {
        let now = monotonic_ns();
        if now >= deadline_ns {
            return;
        }
        let remaining = deadline_ns - now;
        if remaining > SPIN_THRESHOLD_NS {
            std::thread::sleep(std::time::Duration::from_nanos(
                remaining - SPIN_THRESHOLD_NS,
            ));
        } else {
            std::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_is_nondecreasing() {
        let a = monotonic_ns();
        let b = monotonic_ns();
        assert!(b >= a, "monotonic clock went backwards: {a} -> {b}");
    }

    #[test]
    fn realtime_is_after_2020() {
        // 2020-01-01 in ns since epoch; sanity that the clock is plausibly set.
        const Y2020_NS: u64 = 1_577_836_800 * 1_000_000_000;
        assert!(realtime_ns() > Y2020_NS);
    }
}
