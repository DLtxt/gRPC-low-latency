#!/bin/sh
# Initialize the SoftHSM2 token and provision the demo keys.
#
# Idempotent by design (plan.md M1 exit criterion): every step checks for its own
# result first, so re-running this container is a no-op. That matters because the
# proxy has depends_on: service_completed_successfully, so this runs on every up.
#
# This is the ONLY process that writes the token directory. SoftHSM2 uses file
# locking, but concurrent writers across containers corrupt tokens, so the proxy
# mounts the same volume and only reads/uses it (plan.md 4.1).
set -eu

MODULE="${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"
TOKEN_LABEL="${TOKEN_LABEL:?TOKEN_LABEL must be set}"
SO_PIN="${SO_PIN:?SO_PIN must be set}"
USER_PIN="${USER_PIN:?USER_PIN must be set}"
TOKEN_DIR="${TOKEN_DIR:-/var/lib/softhsm/tokens}"

mkdir -p "${TOKEN_DIR}"

log() { printf '[softhsm-init] %s\n' "$*"; }

# --- 1. The token itself -------------------------------------------------------
# SoftHSM pads token labels to 32 characters, so the label line carries trailing
# spaces. Strip them before comparing: an anchored match against the raw line never
# fires, and because `--init-token --free` always claims a *fresh* slot, a failed
# existence check silently creates a duplicate token on every run instead of being
# a no-op. Compare with grep -Fxq so labels containing regex metacharacters are safe.
token_labels() {
    softhsm2-util --show-slots 2>/dev/null \
        | sed -n 's/^[[:space:]]*Label:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p'
}

existing=$(token_labels | grep -Fxc "${TOKEN_LABEL}" || true)

if [ "${existing}" -gt 1 ]; then
    log "ERROR: ${existing} tokens are labelled '${TOKEN_LABEL}'."
    log "       Slot selection by label is ambiguous and the proxy may bind to the"
    log "       wrong one. Destroy the volume and start over: make clean && make up"
    exit 1
elif [ "${existing}" -eq 1 ]; then
    log "token '${TOKEN_LABEL}' already initialized"
else
    log "initializing token '${TOKEN_LABEL}'"
    softhsm2-util --init-token --free \
        --label "${TOKEN_LABEL}" \
        --so-pin "${SO_PIN}" \
        --pin "${USER_PIN}"
fi

p11() {
    pkcs11-tool --module "${MODULE}" --token-label "${TOKEN_LABEL}" "$@"
}

# --- 2. Demo keys --------------------------------------------------------------
# `pkcs11-tool --list-objects` prints "  label:      <name>" for each object.
object_exists() {
    p11 --login --pin "${USER_PIN}" --list-objects 2>/dev/null \
        | grep -q "label:[[:space:]]*$1\$"
}

ensure_keypair() {
    label="$1"; key_type="$2"
    if object_exists "${label}"; then
        log "key '${label}' already present"
        return 0
    fi
    log "generating ${key_type} key pair '${label}'"
    p11 --login --pin "${USER_PIN}" \
        --keypairgen --key-type "${key_type}" \
        --label "${label}" \
        --usage-sign
}

ensure_secret_key() {
    label="$1"; key_type="$2"
    if object_exists "${label}"; then
        log "key '${label}' already present"
        return 0
    fi
    log "generating ${key_type} secret key '${label}'"
    p11 --login --pin "${USER_PIN}" \
        --keygen --key-type "${key_type}" \
        --label "${label}" \
        --usage-decrypt
}

ensure_keypair    "demo-ec-p256"  "EC:prime256v1"
ensure_keypair    "demo-rsa-2048" "rsa:2048"
ensure_secret_key "demo-aes-256"  "aes:32"

# --- 3. Report -----------------------------------------------------------------
log "token contents:"
p11 --login --pin "${USER_PIN}" --list-objects 2>/dev/null \
    | sed 's/^/[softhsm-init]   /'

log "provisioning complete"
