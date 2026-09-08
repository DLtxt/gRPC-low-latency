//! Opening, authenticating to, and searching a PKCS#11 token.

use anyhow::{anyhow, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// Everything needed to reach a token, read from the environment.
///
/// The PIN is deliberately not logged or included in `Debug`; `plan.md` 9 lists
/// leaked PINs as a headline risk for a project that is ostensibly about security.
#[derive(Clone)]
pub struct TokenConfig {
    pub module_path: String,
    pub token_label: String,
    pub user_pin: String,
}

impl std::fmt::Debug for TokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenConfig")
            .field("module_path", &self.module_path)
            .field("token_label", &self.token_label)
            .field("user_pin", &"<redacted>")
            .finish()
    }
}

impl TokenConfig {
    /// Read configuration from the environment.
    ///
    /// `USER_PIN` has no default on purpose: a silent fallback PIN is how a demo
    /// credential ends up in production.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            module_path: std::env::var("PKCS11_MODULE")
                .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string()),
            token_label: std::env::var("TOKEN_LABEL")
                .unwrap_or_else(|_| "grpc-low-latency".to_string()),
            user_pin: std::env::var("USER_PIN")
                .context("USER_PIN is not set; refusing to guess a PIN")?,
        })
    }
}

/// Load the module, initialize it, and locate the slot holding `token_label`.
///
/// `CKF_OS_LOCKING_OK` is required because the M3 worker pool calls into this module
/// from several threads at once.
pub fn load_module(config: &TokenConfig) -> Result<(Pkcs11, Slot)> {
    let pkcs11 = Pkcs11::new(&config.module_path)
        .with_context(|| format!("failed to load PKCS#11 module {}", config.module_path))?;

    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("C_Initialize(CKF_OS_LOCKING_OK) failed")?;

    let slot = pkcs11
        .get_slots_with_token()
        .context("C_GetSlotList failed")?
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .map(|info| info.label().trim() == config.token_label)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            anyhow!(
                "no slot holds a token labelled '{}'; has softhsm-init run?",
                config.token_label
            )
        })?;

    Ok((pkcs11, slot))
}

/// Open a read/write session on `slot` and log in as the user.
///
/// PKCS#11 login state is per-token for the whole application rather than per-session,
/// so later sessions on the same token inherit it. That is asserted by an integration
/// test rather than assumed -- `plan.md` 4.3 flags it as a spec reading worth checking.
pub fn login_session(pkcs11: &Pkcs11, slot: Slot, config: &TokenConfig) -> Result<Session> {
    let session = pkcs11
        .open_rw_session(slot)
        .context("C_OpenSession(CKF_RW_SESSION) failed")?;

    session
        .login(
            UserType::User,
            Some(&AuthPin::new(config.user_pin.clone().into())),
        )
        .context("C_Login(CKU_USER) failed -- wrong USER_PIN?")?;

    Ok(session)
}

/// Convenience: load the module and return one logged-in read/write session.
pub fn open_token(config: &TokenConfig) -> Result<(Pkcs11, Slot, Session)> {
    let (pkcs11, slot) = load_module(config)?;
    let session = login_session(&pkcs11, slot, config)?;
    Ok((pkcs11, slot, session))
}

/// Find a single object of `class` carrying `label`.
///
/// Object handles are scoped to the session that found them and must never be shared
/// across sessions (`plan.md` 4.3).
pub fn find_object(
    session: &Session,
    class: ObjectClass,
    label: &str,
) -> Result<Option<ObjectHandle>> {
    let template = [
        Attribute::Class(class),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    Ok(session
        .find_objects(&template)
        .context("C_FindObjects failed")?
        .into_iter()
        .next())
}

/// Find the (private, public) pair sharing `label`.
pub fn find_object_pair(
    session: &Session,
    label: &str,
) -> Result<Option<(ObjectHandle, ObjectHandle)>> {
    match (
        find_object(session, ObjectClass::PRIVATE_KEY, label)?,
        find_object(session, ObjectClass::PUBLIC_KEY, label)?,
    ) {
        (Some(private), Some(public)) => Ok(Some((private, public))),
        _ => Ok(None),
    }
}
