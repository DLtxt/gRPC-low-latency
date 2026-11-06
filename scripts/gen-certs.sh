#!/usr/bin/env bash
# Generate a local CA, a server certificate, one certificate per demo workload, and a
# signing key per approver (M10, M11).
#
# plan.md 4.5 specifies mkcert; this uses OpenSSL instead so the project depends on
# nothing beyond what is already installed. The output is equivalent: a private CA that
# signs a server cert and client certs carrying SPIFFE-style URI SANs.
#
# NOTHING here is committed. certs/ is gitignored and this script is the only way to
# produce it -- committing a private key to a repository about key protection would be
# the single most embarrassing possible defect (plan.md 9).
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CERT_DIR="${CERT_DIR:-certs}"
DAYS="${DAYS:-365}"
TRUST_DOMAIN="${TRUST_DOMAIN:-spiffe://local/ns/default/sa}"

# Workload identities. The third is deliberately under-privileged: policy/authz.toml
# denies it demo-rsa-2048 so the demo can show a real authorization failure rather than
# describing one (plan.md M4 exit criterion). treasury relays transfer approvals (M10);
# ci requests release signatures and release-review relays their approvals (M11).
WORKLOADS="${WORKLOADS:-payments reporting batch treasury ci release-review}"

# Approvers, as named in policy/transfers.toml and policy/releases.toml. Their private
# keys go to APPROVER_KEY_DIR, deliberately not CERT_DIR: certs/ is mounted into the
# proxy container, and an approval key the proxy can read is not an independent
# approval. Only the public halves go to CERT_DIR/approvers, which is where the proxy
# looks.
APPROVERS="${APPROVERS:-alice bob carol}"
APPROVER_KEY_DIR="${APPROVER_KEY_DIR:-.local/approvers}"

FORCE="${FORCE:-0}"

mkdir -p "${CERT_DIR}/approvers" "${APPROVER_KEY_DIR}"
chmod 700 "${CERT_DIR}" "${APPROVER_KEY_DIR}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/gll-certs.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

log() { printf '[gen-certs] %s\n' "$*"; }

# Each piece is generated only when it is missing, so adding a workload or an approver
# does not reissue everything else. FORCE=1 regenerates all of it, and a new CA always
# reissues every certificate, since the old ones would no longer chain to anything.
NEW_CA=0
missing() { [ "${FORCE}" = "1" ] || [ "${NEW_CA}" = "1" ] || [ ! -f "$1" ]; }

# --- Certificate authority ----------------------------------------------------
if missing "${CERT_DIR}/ca.crt" || [ ! -f "${CERT_DIR}/ca.key" ]; then
    log "generating CA"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
        -days "${DAYS}" \
        -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
        -subj "/CN=gRPC-low-latency local CA/O=gRPC-low-latency" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    NEW_CA=1
else
    log "keeping the existing CA (FORCE=1 regenerates everything)"
fi

# --- Server -------------------------------------------------------------------
# rustls validates against SANs and ignores CN entirely, so the SAN list is what
# actually decides whether a client can connect. "proxy" and "grpc-low-latency" cover
# the compose service names; localhost and 127.0.0.1 cover local runs.
if missing "${CERT_DIR}/server.crt"; then
    log "generating server certificate"
    cat > "${TMP}/server.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:grpc-low-latency,DNS:proxy,IP:127.0.0.1
EXT

    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
        -keyout "${CERT_DIR}/server.key" -out "${TMP}/server.csr" \
        -subj "/CN=grpc-low-latency/O=gRPC-low-latency" 2>/dev/null

    openssl x509 -req -in "${TMP}/server.csr" \
        -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
        -days "${DAYS}" -extfile "${TMP}/server.ext" \
        -out "${CERT_DIR}/server.crt" 2>/dev/null
fi

# --- Clients ------------------------------------------------------------------
for WORKLOAD in ${WORKLOADS}; do
    missing "${CERT_DIR}/${WORKLOAD}.crt" || continue

    log "generating client certificate for '${WORKLOAD}'"
    cat > "${TMP}/${WORKLOAD}.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:${TRUST_DOMAIN}/${WORKLOAD}
EXT

    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
        -keyout "${CERT_DIR}/${WORKLOAD}.key" -out "${TMP}/${WORKLOAD}.csr" \
        -subj "/CN=${WORKLOAD}/O=gRPC-low-latency" 2>/dev/null

    openssl x509 -req -in "${TMP}/${WORKLOAD}.csr" \
        -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
        -days "${DAYS}" -extfile "${TMP}/${WORKLOAD}.ext" \
        -out "${CERT_DIR}/${WORKLOAD}.crt" 2>/dev/null
done

# --- Approvers (M10, M11) -----------------------------------------------------
# A plain P-256 key pair each, not a certificate: the proxy pins each approver's public
# key by name in its own configuration rather than trusting whatever the CA signs, so
# a CA compromise does not mint approvers. In this demo the private keys sit on the same
# machine as everything else; for real, each would live on the approver's own device.
for APPROVER in ${APPROVERS}; do
    if missing "${APPROVER_KEY_DIR}/${APPROVER}.key"; then
        log "generating approver key for '${APPROVER}'"
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
            -out "${APPROVER_KEY_DIR}/${APPROVER}.key" 2>/dev/null
    fi
    # Always re-derived, so the public half can never drift from the private one.
    openssl pkey -in "${APPROVER_KEY_DIR}/${APPROVER}.key" -pubout \
        -out "${CERT_DIR}/approvers/${APPROVER}.pub" 2>/dev/null
done

chmod 600 "${CERT_DIR}"/*.key "${APPROVER_KEY_DIR}"/*.key
chmod 644 "${CERT_DIR}"/*.crt "${CERT_DIR}"/approvers/*.pub

log "wrote to ${CERT_DIR}/:"
ls -1 "${CERT_DIR}" | sed 's/^/  /'
log "identities:"
for WORKLOAD in ${WORKLOADS}; do
    printf '  %-12s %s/%s\n' "${WORKLOAD}" "${TRUST_DOMAIN}" "${WORKLOAD}"
done
log "approvers (private keys in ${APPROVER_KEY_DIR}/, public keys in ${CERT_DIR}/approvers/):"
for APPROVER in ${APPROVERS}; do
    printf '  %s\n' "${APPROVER}"
done
