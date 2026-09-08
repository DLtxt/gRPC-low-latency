#!/usr/bin/env bash
# Take a fresh Linux host from nothing to "make bench works".
#
# Targets Ubuntu 24.04 and Amazon Linux 2023 on both arm64 and x86_64, which covers the
# reference instances in results/REFERENCE.md. Idempotent: safe to re-run.
set -euo pipefail

GHZ_VERSION="${GHZ_VERSION:-0.121.0}"
GRPCURL_VERSION="${GRPCURL_VERSION:-1.9.3}"
REPO_DIR="${REPO_DIR:-$HOME/gRPC-low-latency}"
TOKEN_LABEL="${TOKEN_LABEL:-grpc-low-latency}"

log() { printf '\n[bootstrap] %s\n' "$*"; }

# Root in a container has no sudo; a normal EC2 login has sudo but is not root.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    echo "need either root or sudo to install packages" >&2
    exit 1
fi

# --- package manager ----------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    log "installing packages (apt)"
    ${SUDO} apt-get update -qq
    ${SUDO} apt-get install -y -qq build-essential pkg-config libssl-dev softhsm2 git curl ca-certificates
    SOFTHSM_CONF=/etc/softhsm/softhsm2.conf
elif command -v dnf >/dev/null 2>&1; then
    log "installing packages (dnf)"
    ${SUDO} dnf install -y -q gcc gcc-c++ make openssl-devel softhsm git curl tar
    SOFTHSM_CONF=/etc/softhsm2.conf
else
    echo "unsupported distro: need apt-get or dnf" >&2
    exit 1
fi

# --- rust ---------------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
    log "installing rust"
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
fi
export PATH="$HOME/.cargo/bin:$PATH"

# --- ghz ----------------------------------------------------------------------
if ! command -v ghz >/dev/null 2>&1; then
    log "installing ghz ${GHZ_VERSION}"
    case "$(uname -m)" in
        x86_64)  GHZ_ARCH=x86_64 ;;
        aarch64) GHZ_ARCH=arm64 ;;
        *) echo "unsupported architecture $(uname -m) for ghz" >&2; exit 1 ;;
    esac
    TMP="$(mktemp -d)"
    curl -sSfL -o "${TMP}/ghz.tar.gz" \
        "https://github.com/bojand/ghz/releases/download/v${GHZ_VERSION}/ghz-linux-${GHZ_ARCH}.tar.gz"
    tar -xzf "${TMP}/ghz.tar.gz" -C "${TMP}"
    ${SUDO} install -m 0755 "${TMP}/ghz" /usr/local/bin/ghz
    rm -rf "${TMP}"
fi

# --- grpcurl ------------------------------------------------------------------
# The reference suite needs it to mint a signature for the cached-verify sweep:
# ghz reports statuses but not response bodies, so it cannot produce one itself.
if ! command -v grpcurl >/dev/null 2>&1; then
    log "installing grpcurl ${GRPCURL_VERSION}"
    case "$(uname -m)" in
        x86_64)  GRPCURL_ARCH=x86_64 ;;
        aarch64) GRPCURL_ARCH=arm64 ;;
        *) echo "unsupported architecture $(uname -m) for grpcurl" >&2; exit 1 ;;
    esac
    TMP="$(mktemp -d)"
    curl -sSfL -o "${TMP}/grpcurl.tar.gz" \
        "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_${GRPCURL_ARCH}.tar.gz"
    tar -xzf "${TMP}/grpcurl.tar.gz" -C "${TMP}" grpcurl
    ${SUDO} install -m 0755 "${TMP}/grpcurl" /usr/local/bin/grpcurl
    rm -rf "${TMP}"
fi

# --- repo ---------------------------------------------------------------------
# The repository is private, so a bare clone from a fresh host has no credentials.
# Three ways in, in order of preference:
#
#   1. The source is already at REPO_DIR (rsync'd or scp'd from a machine that has
#      it). This is the documented path and needs no tokens on the host.
#   2. GITHUB_TOKEN is set in the environment, so we can clone over HTTPS.
#   3. Nothing works -- fail loudly rather than half-configuring the host.
if [ -f "${REPO_DIR}/proxy/Cargo.toml" ]; then
    log "using existing source at ${REPO_DIR}"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
    log "cloning repository into ${REPO_DIR}"
    git clone --quiet \
        "https://x-access-token:${GITHUB_TOKEN}@github.com/DLtxt/gRPC-low-latency.git" \
        "${REPO_DIR}"
else
    cat >&2 <<'MISSING'
[bootstrap] ERROR: no source found and no GITHUB_TOKEN set.

The repository is private. Either copy it to this host first:

    rsync -az --exclude target --exclude .local --exclude .env \
        ./ USER@HOST:~/gRPC-low-latency/

or export GITHUB_TOKEN with repo read access before running this script.
MISSING
    exit 1
fi
cd "${REPO_DIR}"

if [ ! -f proxy/Cargo.toml ] || [ ! -f proto/hsm/v1/hsm.proto ]; then
    echo "[bootstrap] ERROR: ${REPO_DIR} does not look like this repository" >&2
    exit 1
fi

# --- token --------------------------------------------------------------------
# Kept inside the repo, exactly as on a development machine, so the benchmark path
# is identical everywhere and nothing is written outside the working tree.
log "preparing SoftHSM token"
mkdir -p "${REPO_DIR}/.local/softhsm/tokens"
cat > "${REPO_DIR}/.local/softhsm/softhsm2.conf" <<CONF
directories.tokendir = ${REPO_DIR}/.local/softhsm/tokens
objectstore.backend = file
objectstore.umask = 0077
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
CONF
export SOFTHSM2_CONF="${REPO_DIR}/.local/softhsm/softhsm2.conf"

./scripts/gen-env.sh >/dev/null
# shellcheck disable=SC1091
set -a; . ./.env; set +a

if ! softhsm2-util --show-slots 2>/dev/null \
    | sed -n 's/^[[:space:]]*Label:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p' \
    | grep -Fxq "${TOKEN_LABEL}"; then
    softhsm2-util --init-token --free --label "${TOKEN_LABEL}" \
        --so-pin "${SO_PIN}" --pin "${USER_PIN}"
fi

log "building (release)"
cd proxy && cargo build --release --locked --quiet && cd ..

log "provisioning demo keys"
TOKEN_LABEL="${TOKEN_LABEL}" USER_PIN="${USER_PIN}" ./proxy/target/release/provision

cat <<DONE

[bootstrap] ready. To run the reference benchmarks:

  cd ${REPO_DIR}
  export SOFTHSM2_CONF=${REPO_DIR}/.local/softhsm/softhsm2.conf
  set -a; . ./.env; set +a
  ./scripts/bench-reference.sh

Results land in results/reference/ and are stamped with this host's identity.
DONE
