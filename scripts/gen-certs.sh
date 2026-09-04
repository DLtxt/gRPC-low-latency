#!/usr/bin/env bash
# Generate a local CA, a server certificate, and one certificate per demo workload.
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
# describing one (plan.md M4 exit criterion).
WORKLOADS="${WORKLOADS:-payments reporting batch}"

if [ -f "${CERT_DIR}/ca.crt" ] && [ "${FORCE:-0}" != "1" ]; then
    echo "${CERT_DIR}/ca.crt already exists; set FORCE=1 to regenerate"
    exit 0
fi

mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/gll-certs.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

log() { printf '[gen-certs] %s\n' "$*"; }

# --- Certificate authority ----------------------------------------------------
log "generating CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
    -days "${DAYS}" \
    -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
    -subj "/CN=gRPC-low-latency local CA/O=gRPC-low-latency" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# --- Server -------------------------------------------------------------------
# rustls validates against SANs and ignores CN entirely, so the SAN list is what
# actually decides whether a client can connect. "proxy" and "grpc-low-latency" cover
# the compose service names; localhost and 127.0.0.1 cover local runs.
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

# --- Clients ------------------------------------------------------------------
for WORKLOAD in ${WORKLOADS}; do
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

chmod 600 "${CERT_DIR}"/*.key
chmod 644 "${CERT_DIR}"/*.crt

log "wrote to ${CERT_DIR}/:"
ls -1 "${CERT_DIR}" | sed 's/^/  /'
log "identities:"
for WORKLOAD in ${WORKLOADS}; do
    printf '  %-12s %s/%s\n' "${WORKLOAD}" "${TRUST_DOMAIN}" "${WORKLOAD}"
done
