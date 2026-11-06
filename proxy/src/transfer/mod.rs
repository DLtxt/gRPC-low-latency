//! Transfer keys: signing requests the proxy has read, instead of whatever it is sent.
//!
//! `Sign` signs any bytes an authorized caller sends. Authorization decides who may use
//! which key, but nothing decides *what* gets signed, so a compromised caller can get
//! anything signed. For keys whose signatures carry meaning -- moving value, releasing
//! software, issuing certificates -- that makes the proxy a signing oracle.
//!
//! The fix has the same shape for each of them: the caller describes the request in
//! fields, and the signer checks the fields against policy, builds the exact bytes
//! itself, and holds the risky requests for people to approve. This module builds it for
//! one kind of request, a transfer of value. Transfers came first because of the October
//! 2026 Binance incident, where by the public accounts no key was stolen: the signer
//! signed what an attacker sent it.
//!
//! None of this makes the proxy a wallet. It holds no balances and talks to no chain; it
//! signs, and whatever moves the value sits in front of it.
//!
//! * `canonical` -- the caller describes a transfer, and the proxy builds the exact bytes
//!   it signs. There is no hash to smuggle in, and a transfer is the only thing such a
//!   key can sign.
//! * `policy` -- per key and asset: a destination allowlist, a per-transfer cap, a
//!   per-minute rate, an hourly auto-sign budget, and who may approve what is held.
//! * `velocity` -- the rolling windows behind the rate and the budget.
//! * `guard` -- applies all of it: sign now, hold for approval, or refuse.
//!
//! The key itself is marked transfer-only on the token (`pkcs11::TRANSFER_ONLY_ID`), and
//! the pool's workers refuse to blind-sign with a marked key. So the generic `Sign` RPC
//! cannot reach it through any handler, proxy mode, or policy file.
//!
//! See docs/m10-transfer-keys.md for the pattern, the design, and what this does not
//! cover.

pub mod canonical;
pub mod guard;
pub mod policy;
pub mod velocity;

pub use canonical::Transfer;
pub use guard::{
    ApproverKeys, HoldKind, HoldStatus, Outcome, Outflow, Refusal, Reservation, TransferGuard,
    TransferRequest,
};
pub use policy::TransferPolicy;

/// Why the generic `Sign` RPC refuses a transfer key. Shared by both backends so the
/// refusal reads the same whichever one served it.
pub fn raw_sign_refusal(key_label: &str) -> String {
    format!(
        "'{key_label}' is a transfer key: it signs only transfers the proxy has built and \
         checked itself, through SignTransfer"
    )
}
