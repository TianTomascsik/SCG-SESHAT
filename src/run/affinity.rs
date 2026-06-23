//! CPU affinity pinning (F-15, NFR-PERF).
//!
//! Pinning the sender and receiver threads to cores *separate* from the SCG
//! keeps the harness off the gateway's cores and avoids cache-line bouncing, so
//! the measurement reflects the SCG's limit rather than scheduler noise. This is
//! a best-effort hint: if a core id is out of range or the syscall is denied
//! (containers), we report failure and the caller carries on unpinned.
#![allow(dead_code)]

/// Pin the **calling** thread to the given set of logical CPUs.
///
/// Returns `true` on success. An empty `cores` list is a no-op that returns
/// `false` (nothing was pinned).
pub fn pin_current_thread(cores: &[usize]) -> bool {
    if cores.is_empty() {
        return false;
    }
    // SAFETY: we zero-initialise a `cpu_set_t`, set only in-range bits, and pass
    // its real size to `sched_setaffinity` for the current thread (pid 0).
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        let mut any = false;
        for &c in cores {
            if c < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(c, &mut set);
                any = true;
            }
        }
        if !any {
            return false;
        }
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        ret == 0
    }
}

/// Pin an arbitrary process (by `pid`) to the given set of logical CPUs.
///
/// Best-effort sibling of [`pin_current_thread`] that targets another process —
/// used to keep the spawned gateway on cores *separate* from the harness so the
/// two never contend (NFR-PERF). Returns `true` on success; an empty `cores`
/// list is a no-op returning `false`. Failure (e.g. denied in a container) is
/// reported, not fatal.
pub fn pin_pid(pid: i32, cores: &[usize]) -> bool {
    if cores.is_empty() {
        return false;
    }
    // SAFETY: zero-initialised `cpu_set_t`, only in-range bits set, real size
    // passed to `sched_setaffinity` for the target `pid`.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        let mut any = false;
        for &c in cores {
            if c < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(c, &mut set);
                any = true;
            }
        }
        if !any {
            return false;
        }
        libc::sched_setaffinity(pid, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

/// Read the calling thread's current CPU affinity as a list of logical CPUs.
///
/// Used by tests / diagnostics to confirm pinning took effect.
pub fn current_affinity() -> Vec<usize> {
    let mut cores = Vec::new();
    // SAFETY: zero-initialised set written by `sched_getaffinity` with its size.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) == 0 {
            for c in 0..libc::CPU_SETSIZE as usize {
                if libc::CPU_ISSET(c, &set) {
                    cores.push(c);
                }
            }
        }
    }
    cores
}

/// Split `total_cores` logical CPUs into `weights.len()` **disjoint**, contiguous
/// core sets sized proportionally to `weights` (each group gets at least one
/// core). Core 0 is reserved for the OS/IRQs when there are at least 4 cores.
///
/// Returns one set per weight. If there are too few cores to give every group a
/// distinct core, every set is empty so callers fall back to running unpinned.
/// This is how the harness auto-derives separate sender / receiver / gateway
/// core pools when the config leaves affinity unset.
pub fn partition_cores(total_cores: usize, weights: &[usize]) -> Vec<Vec<usize>> {
    let groups = weights.len();
    if groups == 0 {
        return Vec::new();
    }
    let reserve = usize::from(total_cores >= 4);
    let usable = total_cores.saturating_sub(reserve);
    if usable < groups {
        // Not enough cores to isolate the groups — signal "don't pin".
        return vec![Vec::new(); groups];
    }
    let weight_sum: usize = weights.iter().map(|w| (*w).max(1)).sum();
    let mut counts: Vec<usize> = weights
        .iter()
        .map(|w| (usable * (*w).max(1) / weight_sum).max(1))
        .collect();
    // Reconcile rounding so the counts sum to exactly `usable`.
    let mut assigned: usize = counts.iter().sum();
    while assigned > usable {
        let Some(idx) = counts
            .iter()
            .enumerate()
            .filter(|(_, &c)| c > 1)
            .max_by_key(|(_, &c)| c)
            .map(|(i, _)| i)
        else {
            break;
        };
        counts[idx] -= 1;
        assigned -= 1;
    }
    while assigned < usable {
        let idx = weights
            .iter()
            .enumerate()
            .max_by_key(|(_, &w)| w)
            .map(|(i, _)| i)
            .unwrap_or(0);
        counts[idx] += 1;
        assigned += 1;
    }
    let mut next = reserve;
    let mut result = Vec::with_capacity(groups);
    for count in counts {
        let mut set = Vec::with_capacity(count);
        for _ in 0..count {
            set.push(next);
            next += 1;
        }
        result.push(set);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_to_cpu0_is_observable() {
        // CPU 0 exists on every host; pinning to it should be reflected back.
        if pin_current_thread(&[0]) {
            assert_eq!(current_affinity(), vec![0]);
        }
    }

    #[test]
    fn empty_list_is_noop() {
        assert!(!pin_current_thread(&[]));
        assert!(!pin_pid(std::process::id() as i32, &[]));
    }

    #[test]
    fn partition_is_disjoint_and_reserves_core0() {
        let groups = partition_cores(20, &[1, 1, 1]);
        assert_eq!(groups.len(), 3);
        // Reserves core 0 on a large host.
        assert!(!groups.iter().flatten().any(|&c| c == 0));
        // Disjoint: total count equals the unique count.
        let all: Vec<usize> = groups.iter().flatten().copied().collect();
        let total = all.len();
        let mut uniq = all;
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), total, "core sets must be disjoint");
        // Each group has at least one core.
        assert!(groups.iter().all(|g| !g.is_empty()));
    }

    #[test]
    fn partition_weighted_split() {
        // 19 usable cores (core 0 reserved) split 2:1:1 → larger first group.
        let groups = partition_cores(20, &[2, 1, 1]);
        assert!(groups[0].len() >= groups[1].len());
        assert!(groups[0].len() >= groups[2].len());
    }

    #[test]
    fn partition_too_few_cores_is_unpinned() {
        // 2 cores cannot isolate 3 groups → all empty (run unpinned).
        let groups = partition_cores(2, &[1, 1, 1]);
        assert_eq!(groups.len(), 3);
        assert!(groups.iter().all(|g| g.is_empty()));
    }
}
