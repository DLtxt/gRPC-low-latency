//! A circuit breaker over a rolling window of request outcomes.
//!
//! Hand-rolled rather than pulled from a crate: `tower-circuit-breaker` is unmaintained,
//! and the state machine is small enough that owning it is cheaper than carrying a
//! dependency for it (plan.md 4.6).
//!
//! The point is not to make failures succeed. It is to stop paying for them. When the
//! token is broken, every request still costs a worker slot, a queue slot, and the
//! caller's deadline before failing. Opening the circuit converts a slow failure into a
//! fast one, which is what keeps the tail latency of *healthy* traffic intact.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Circuit state. Stored as a `u8` so the hot path reads it with a single atomic load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Normal operation; requests pass through.
    Closed,
    /// Failing; requests are rejected immediately without touching the HSM.
    Open,
    /// Probing; a limited number of requests are allowed through to test recovery.
    HalfOpen,
}

impl State {
    fn as_u8(self) -> u8 {
        match self {
            State::Closed => 0,
            State::Open => 1,
            State::HalfOpen => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => State::Open,
            2 => State::HalfOpen,
            _ => State::Closed,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            State::Closed => "closed",
            State::Open => "open",
            State::HalfOpen => "half_open",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BreakerConfig {
    /// Fraction of failures in the window that trips the breaker, in `0.0..=1.0`.
    pub failure_ratio: f64,
    /// Minimum requests in the window before the ratio is trusted. Without this, the
    /// first failed request is a 100% failure rate and would trip the circuit on noise.
    pub minimum_requests: u64,
    /// Width of the rolling window.
    pub window: Duration,
    /// How long to stay open before probing.
    pub cooldown: Duration,
    /// Consecutive successes in half-open needed to close again.
    pub probe_successes: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_ratio: 0.5,
            minimum_requests: 20,
            window: Duration::from_secs(10),
            cooldown: Duration::from_secs(5),
            probe_successes: 3,
        }
    }
}

impl BreakerConfig {
    pub fn from_env() -> Self {
        let d = Self::default();
        // Each field parses to its own type, so this cannot be one generic closure.
        fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
            std::env::var(key).ok()?.parse().ok()
        }
        Self {
            failure_ratio: env_parse("BREAKER_FAILURE_RATIO").unwrap_or(d.failure_ratio),
            minimum_requests: env_parse("BREAKER_MIN_REQUESTS").unwrap_or(d.minimum_requests),
            window: env_parse::<u64>("BREAKER_WINDOW_SECS")
                .map(Duration::from_secs)
                .unwrap_or(d.window),
            cooldown: env_parse::<u64>("BREAKER_COOLDOWN_SECS")
                .map(Duration::from_secs)
                .unwrap_or(d.cooldown),
            probe_successes: env_parse("BREAKER_PROBE_SUCCESSES").unwrap_or(d.probe_successes),
        }
    }
}

/// Counts inside the current window, plus when the window started.
#[derive(Debug)]
struct Window {
    started: Instant,
    successes: u64,
    failures: u64,
    /// When the breaker last opened, used to time the cooldown.
    opened_at: Option<Instant>,
    /// Consecutive successes observed while half-open.
    probe_successes: u32,
}

pub struct CircuitBreaker {
    config: BreakerConfig,
    /// Read on every request, so it is kept separate from the mutex-guarded window.
    state: AtomicU8,
    window: Mutex<Window>,
    pub trips: AtomicU64,
    pub rejected: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            state: AtomicU8::new(State::Closed.as_u8()),
            window: Mutex::new(Window {
                started: Instant::now(),
                successes: 0,
                failures: 0,
                opened_at: None,
                probe_successes: 0,
            }),
            trips: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> State {
        State::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// May a request proceed?
    ///
    /// The common case -- closed circuit -- is a single relaxed atomic load and no lock,
    /// because this runs on every request inside a 2 ms budget.
    pub fn allow(&self) -> bool {
        match self.state() {
            State::Closed => true,
            State::HalfOpen => true,
            State::Open => {
                // Cooldown elapsed? Move to half-open and let this request probe.
                let mut window = match self.window.lock() {
                    Ok(w) => w,
                    Err(poisoned) => poisoned.into_inner(),
                };

                let elapsed = window.opened_at.map(|t| t.elapsed());
                if elapsed.is_some_and(|e| e >= self.config.cooldown) {
                    window.probe_successes = 0;
                    self.state.store(State::HalfOpen.as_u8(), Ordering::Relaxed);
                    tracing::info!("circuit breaker half-open, probing");
                    true
                } else {
                    self.rejected.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }
    }

    pub fn record_success(&self) {
        let mut window = match self.window.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };

        match self.state() {
            State::HalfOpen => {
                window.probe_successes += 1;
                if window.probe_successes >= self.config.probe_successes {
                    self.reset_window(&mut window);
                    self.state.store(State::Closed.as_u8(), Ordering::Relaxed);
                    tracing::info!("circuit breaker closed; service recovered");
                }
            }
            _ => {
                self.roll_if_stale(&mut window);
                window.successes += 1;
            }
        }
    }

    /// Record a failure. Only failures that indicate the *dependency* is unhealthy should
    /// reach here -- a client sending a bad key label is not an HSM fault, and counting it
    /// would let one misbehaving caller trip the circuit for everyone.
    pub fn record_failure(&self) {
        let mut window = match self.window.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };

        if self.state() == State::HalfOpen {
            // A probe failed: back to open, restart the cooldown.
            window.opened_at = Some(Instant::now());
            window.probe_successes = 0;
            self.state.store(State::Open.as_u8(), Ordering::Relaxed);
            tracing::warn!("circuit breaker re-opened; probe failed");
            return;
        }

        self.roll_if_stale(&mut window);
        window.failures += 1;

        let total = window.successes + window.failures;
        if total >= self.config.minimum_requests {
            let ratio = window.failures as f64 / total as f64;
            if ratio >= self.config.failure_ratio {
                window.opened_at = Some(Instant::now());
                self.state.store(State::Open.as_u8(), Ordering::Relaxed);
                self.trips.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    failures = window.failures,
                    total,
                    ratio = format!("{ratio:.2}"),
                    "circuit breaker opened"
                );
            }
        }
    }

    fn roll_if_stale(&self, window: &mut Window) {
        if window.started.elapsed() >= self.config.window {
            self.reset_window(window);
        }
    }

    fn reset_window(&self, window: &mut Window) {
        window.started = Instant::now();
        window.successes = 0;
        window.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            failure_ratio: 0.5,
            minimum_requests: 4,
            window: Duration::from_secs(60),
            cooldown: Duration::from_millis(50),
            probe_successes: 2,
        })
    }

    #[test]
    fn starts_closed_and_allows() {
        let b = breaker();
        assert_eq!(b.state(), State::Closed);
        assert!(b.allow());
    }

    /// Below the minimum request count the ratio is not trusted, so a single failure --
    /// a 100% failure rate on one sample -- must not trip the breaker.
    #[test]
    fn does_not_trip_below_minimum_requests() {
        let b = breaker();
        b.record_failure();
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn trips_once_ratio_and_minimum_are_met() {
        let b = breaker();
        for _ in 0..2 {
            b.record_success();
        }
        for _ in 0..2 {
            b.record_failure();
        }
        assert_eq!(b.state(), State::Open);
        assert!(!b.allow(), "open circuit must reject");
    }

    #[test]
    fn recovers_through_half_open() {
        let b = breaker();
        for _ in 0..2 {
            b.record_success();
        }
        for _ in 0..2 {
            b.record_failure();
        }
        assert_eq!(b.state(), State::Open);

        std::thread::sleep(Duration::from_millis(60));

        assert!(b.allow(), "cooldown elapsed, should probe");
        assert_eq!(b.state(), State::HalfOpen);

        b.record_success();
        b.record_success();
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn failed_probe_reopens() {
        let b = breaker();
        for _ in 0..2 {
            b.record_success();
        }
        for _ in 0..2 {
            b.record_failure();
        }
        std::thread::sleep(Duration::from_millis(60));
        assert!(b.allow());
        assert_eq!(b.state(), State::HalfOpen);

        b.record_failure();
        assert_eq!(b.state(), State::Open);
    }

    /// A healthy service must never trip, however many requests it serves.
    #[test]
    fn sustained_success_never_trips() {
        let b = breaker();
        for _ in 0..1000 {
            b.record_success();
        }
        assert_eq!(b.state(), State::Closed);
    }
}
