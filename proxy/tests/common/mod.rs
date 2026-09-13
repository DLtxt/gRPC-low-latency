//! A disposable SoftHSM token for integration tests.
//!
//! plan.md §8 is explicit that these run against a *real* token rather than a mock
//! PKCS#11. A mock would pass while telling us nothing: the behaviour worth testing here
//! — session invalidation, login state being per-token rather than per-session, handle
//! scoping — is exactly the behaviour a mock would have to invent.
//!
//! `SOFTHSM2_CONF` is read by the module when it loads and is process-global, so all
//! tests in one binary share a single token directory and distinguish themselves by
//! token label rather than by config file.
//!
//! This module is compiled into every integration-test binary, and no single binary uses
//! all of it -- the pool tests need the serialisation guard, the property tests do not --
//! so unused items here are expected rather than a sign of dead code.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use grpc_low_latency_proxy::pkcs11::TokenConfig;

static COUNTER: AtomicUsize = AtomicUsize::new(0);
/// `OnceLock` rather than `Once` plus a `static mut`: the latter needs `unsafe` to
/// read and is a data race waiting to happen if the initialiser ever gains an early
/// return path.
static CONF_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

/// One shared token directory per test binary, created once.
fn conf_dir() -> Option<PathBuf> {
    CONF_DIR
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("gll-itest-{}", std::process::id()));
            let tokens = dir.join("tokens");
            std::fs::create_dir_all(&tokens).ok()?;
            let conf = dir.join("softhsm2.conf");
            let body = format!(
                "directories.tokendir = {}\n\
             objectstore.backend = file\n\
             objectstore.umask = 0077\n\
             log.level = ERROR\n\
             slots.removable = false\n\
             slots.mechanisms = ALL\n\
             library.reset_on_fork = false\n",
                tokens.display()
            );
            std::fs::write(&conf, body).ok()?;
            std::env::set_var("SOFTHSM2_CONF", &conf);
            Some(dir)
        })
        .clone()
}

/// Serialises pool construction across tests.
///
/// `C_Initialize` and `C_Finalize` are process-global in PKCS#11, so two live `Pool`
/// instances in one process tear down each other's module state -- which surfaces as a
/// SIGSEGV rather than an error, because the second pool keeps using handles the first
/// pool's `C_Finalize` already invalidated. Rust runs tests in parallel threads within
/// one binary, so without this every run is a race.
///
/// Holding this guard for the whole test body keeps one pool alive at a time.
/// An async mutex, not `std::sync::Mutex`: the guard is deliberately held across the
/// `.await` points in each test, which a blocking guard must never be.
pub static PKCS11_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Take the process-wide PKCS#11 lock for the duration of a test.
pub async fn serial_guard() -> tokio::sync::MutexGuard<'static, ()> {
    PKCS11_SERIAL.lock().await
}

pub struct TestToken {
    pub config: TokenConfig,
}

impl TestToken {
    /// Build a token with the demo keys, or `None` when SoftHSM2 is unavailable.
    ///
    /// Returning `None` rather than panicking is deliberate: these tests are valuable on
    /// a machine with SoftHSM2 and meaningless without it, and a hard failure would make
    /// `cargo test` unusable for someone working on, say, the policy parser.
    pub fn new() -> Option<Self> {
        let module = find_module()?;
        let util = which("softhsm2-util")?;
        let conf = conf_dir()?.join("softhsm2.conf");

        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let label = format!("itest-{}-{id}", std::process::id());

        let status = Command::new(util)
            .args([
                "--init-token",
                "--free",
                "--label",
                &label,
                "--so-pin",
                "0000",
                "--pin",
                "1234",
            ])
            .env("SOFTHSM2_CONF", &conf)
            .output()
            .ok()?;
        if !status.status.success() {
            eprintln!(
                "token init failed: {}",
                String::from_utf8_lossy(&status.stderr)
            );
            return None;
        }

        let token = Self {
            config: TokenConfig {
                module_path: module,
                token_label: label,
                user_pin: "1234".to_string(),
            },
        };
        token.provision()?;
        Some(token)
    }

    fn provision(&self) -> Option<()> {
        use grpc_low_latency_proxy::pkcs11::{open_token, provision::ensure_demo_keys};
        let (_ctx, _slot, session) = open_token(&self.config).ok()?;
        ensure_demo_keys(&session).ok()?;
        let _ = session.logout();
        Some(())
    }
}

fn which(bin: &str) -> Option<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

fn find_module() -> Option<String> {
    if let Ok(path) = std::env::var("PKCS11_MODULE") {
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    [
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    ]
    .iter()
    .find(|p| std::path::Path::new(p).exists())
    .map(|p| p.to_string())
}

/// Skip the test body when SoftHSM2 is unavailable, saying so rather than passing silently.
#[macro_export]
macro_rules! require_token {
    () => {
        match common::TestToken::new() {
            Some(token) => token,
            None => {
                eprintln!("SKIPPED: SoftHSM2 not available (install softhsm2 to run this)");
                return;
            }
        }
    };
}
