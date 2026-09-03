//! Pool counters.
//!
//! Deliberately plain atomics for now; M7 exports these through Prometheus. The four
//! that matter are queue wait, service time, queue depth, and rejections -- queue wait
//! against service time is the graph that makes the whole pool design legible.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default, Debug)]
pub struct PoolMetrics {
    pub jobs_submitted: AtomicU64,
    pub jobs_completed: AtomicU64,
    pub jobs_failed: AtomicU64,
    pub jobs_rejected_queue_full: AtomicU64,
    pub jobs_timed_out: AtomicU64,
    pub queue_wait_nanos_total: AtomicU64,
    pub service_nanos_total: AtomicU64,
    pub session_resets: AtomicU64,
    pub handle_cache_hits: AtomicU64,
    pub handle_cache_misses: AtomicU64,
}

impl PoolMetrics {
    pub fn incr(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, Ordering::Relaxed);
    }

    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Mean queue wait in microseconds, or 0 before any job completes.
    pub fn mean_queue_wait_micros(&self) -> u64 {
        let completed = Self::get(&self.jobs_completed);
        if completed == 0 {
            return 0;
        }
        Self::get(&self.queue_wait_nanos_total) / completed / 1_000
    }

    /// Mean HSM service time in microseconds, or 0 before any job completes.
    pub fn mean_service_micros(&self) -> u64 {
        let completed = Self::get(&self.jobs_completed);
        if completed == 0 {
            return 0;
        }
        Self::get(&self.service_nanos_total) / completed / 1_000
    }
}
