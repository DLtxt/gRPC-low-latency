//! Rolling windows: the per-minute rate and hourly auto-sign budget of transfer keys,
//! and the hourly signature cap of release keys.
//!
//! Bucketed rather than a log of every transfer. A log grows with throughput, and a
//! transfer key that is being drained is exactly the case where throughput is highest.
//! Sixty fixed buckets per window keep memory constant whatever the rate, at the cost of
//! resolution: the hour is measured in one-minute steps and the minute in one-second
//! steps, so a limit can come into force up to one step early or late. That is precise
//! enough for a limit whose job is to bound a loss rather than to bill it.

use std::time::{Duration, Instant};

const SLOTS: usize = 60;

/// A sum over the last `span`, kept in `SLOTS` buckets of `span / SLOTS` each.
#[derive(Debug)]
pub struct Window {
    origin: Instant,
    width: Duration,
    totals: [u128; SLOTS],
    /// Which step each bucket currently holds. A bucket whose step has fallen out of
    /// the window is stale and is reset the next time its slot comes round.
    steps: [u64; SLOTS],
}

/// Where an `add` landed, so it can be taken back if the signature it was reserved for
/// never happened.
#[derive(Debug, Clone, Copy)]
pub struct Mark {
    step: u64,
    value: u128,
}

impl Window {
    pub fn new(span: Duration, origin: Instant) -> Self {
        Self {
            origin,
            width: span / SLOTS as u32,
            totals: [0; SLOTS],
            steps: [0; SLOTS],
        }
    }

    pub fn per_minute(origin: Instant) -> Self {
        Self::new(Duration::from_secs(60), origin)
    }

    pub fn per_hour(origin: Instant) -> Self {
        Self::new(Duration::from_secs(3_600), origin)
    }

    fn step(&self, now: Instant) -> u64 {
        (now.saturating_duration_since(self.origin).as_nanos() / self.width.as_nanos()) as u64
    }

    fn live(&self, step: u64, now_step: u64) -> bool {
        step <= now_step && now_step - step < SLOTS as u64
    }

    /// Everything added within the window ending at `now`.
    pub fn total(&self, now: Instant) -> u128 {
        let now_step = self.step(now);
        (0..SLOTS)
            .filter(|&slot| self.live(self.steps[slot], now_step))
            .fold(0u128, |sum, slot| sum.saturating_add(self.totals[slot]))
    }

    pub fn add(&mut self, now: Instant, value: u128) -> Mark {
        let step = self.step(now);
        let slot = (step % SLOTS as u64) as usize;
        if self.steps[slot] != step {
            self.steps[slot] = step;
            self.totals[slot] = 0;
        }
        self.totals[slot] = self.totals[slot].saturating_add(value);
        Mark { step, value }
    }

    /// Undo an `add`. A no-op once its bucket has been recycled, because by then the
    /// value has aged out of the window anyway.
    pub fn remove(&mut self, mark: Mark) {
        let slot = (mark.step % SLOTS as u64) as usize;
        if self.steps[slot] == mark.step {
            self.totals[slot] = self.totals[slot].saturating_sub(mark.value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(origin: Instant, secs: u64) -> Instant {
        origin + Duration::from_secs(secs)
    }

    #[test]
    fn sums_within_the_window() {
        let origin = Instant::now();
        let mut window = Window::per_hour(origin);
        window.add(at(origin, 0), 5);
        window.add(at(origin, 1_800), 7);
        assert_eq!(window.total(at(origin, 1_800)), 12);
    }

    #[test]
    fn values_age_out_after_the_span() {
        let origin = Instant::now();
        let mut window = Window::per_minute(origin);
        window.add(at(origin, 0), 5);
        window.add(at(origin, 30), 7);
        assert_eq!(window.total(at(origin, 59)), 12);
        assert_eq!(window.total(at(origin, 60)), 7);
        assert_eq!(window.total(at(origin, 90)), 0);
    }

    /// A recycled slot must not carry its previous lap's total into the new one.
    #[test]
    fn recycled_buckets_start_empty() {
        let origin = Instant::now();
        let mut window = Window::per_minute(origin);
        window.add(at(origin, 5), 100);
        window.add(at(origin, 65), 1);
        assert_eq!(window.total(at(origin, 65)), 1);
    }

    #[test]
    fn remove_takes_back_an_add() {
        let origin = Instant::now();
        let mut window = Window::per_hour(origin);
        window.add(at(origin, 0), 5);
        let mark = window.add(at(origin, 10), 7);
        window.remove(mark);
        assert_eq!(window.total(at(origin, 10)), 5);
    }

    #[test]
    fn remove_after_recycling_is_harmless() {
        let origin = Instant::now();
        let mut window = Window::per_minute(origin);
        let mark = window.add(at(origin, 0), 5);
        window.add(at(origin, 60), 3);
        window.remove(mark);
        assert_eq!(window.total(at(origin, 60)), 3);
    }

    /// Memory is fixed by design, so a burst far beyond any limit costs nothing extra.
    #[test]
    fn a_burst_lands_in_one_bucket() {
        let origin = Instant::now();
        let mut window = Window::per_minute(origin);
        for _ in 0..100_000 {
            window.add(at(origin, 3), 1);
        }
        assert_eq!(window.total(at(origin, 3)), 100_000);
    }
}
