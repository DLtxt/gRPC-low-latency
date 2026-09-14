#!/usr/bin/env bash
# Sustained load at a fixed rate, sampling the proxy's own metrics throughout.
#
# The question a soak answers is not throughput -- the sweeps already answer that -- but
# whether anything *drifts*. Three specific failure modes, none of which a short run can
# see:
#
#   * memory growth: a leak in the cache, the handle maps, or per-request allocation
#   * latency drift: p99 climbing over time while throughput holds steady
#   * session churn: workers quietly resetting sessions and recovering
#
# Run from the load-generator host against a proxy on another machine. Sampling the
# proxy's RSS requires SSH access to it, which is why SERVER_SSH is separate from TARGET.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET="${TARGET:?TARGET must be set, e.g. TARGET=10.0.1.5:50051}"
RATE="${RATE:-16000}"
DURATION_MIN="${DURATION_MIN:-60}"
SAMPLE_SECS="${SAMPLE_SECS:-30}"
KEY="${KEY:-demo-ec-p256}"
MECHANISM="${MECHANISM:-SIGNATURE_MECHANISM_ECDSA_SHA256}"
CONCURRENCY="${CONCURRENCY:-200}"
CONNECTIONS="${CONNECTIONS:-16}"
METRICS_URL="${METRICS_URL:-}"   # e.g. http://10.0.1.5:9090/metrics
LABEL="${LABEL:-soak}"
# Set TLS=on to soak the mTLS path. Worth measuring separately: TLS adds per-record
# encryption and framing to every request, and a leak in certificate or session handling
# would only appear here.
TLS="${TLS:-off}"
CLIENT_IDENTITY="${CLIENT_IDENTITY:-payments}"
SERVER_NAME="${SERVER_NAME:-localhost}"

HOST_KIND="$(./scripts/host-info.sh | awk -F'"' '/host_kind/{print $4}')"
OUT_DIR="results/${HOST_KIND}"
mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAMPLES="${OUT_DIR}/${STAMP}-${LABEL}-samples.csv"
RESULT="${OUT_DIR}/${STAMP}-${LABEL}.json"

PAYLOAD="$(printf 'soak probe' | base64)"
DATA="{\"key_label\":\"${KEY}\",\"mechanism\":\"${MECHANISM}\",\"input\":{\"message\":\"${PAYLOAD}\"}}"
TOTAL=$(( RATE * DURATION_MIN * 60 ))

echo "soak: ${RATE} req/s for ${DURATION_MIN} min against ${TARGET} (tls=${TLS})"
echo "      ${TOTAL} requests total, sampling every ${SAMPLE_SECS}s"
echo

# --- metric sampler ------------------------------------------------------------
# Runs alongside the load. Scraping the proxy's own /metrics is what makes drift
# visible: ghz reports one aggregate at the end, which cannot distinguish "steady
# 1 ms" from "0.5 ms rising to 2 ms".
echo "elapsed_s,rss_bytes,p99_seconds,queue_depth,cache_entries,session_resets,requests_total" > "${SAMPLES}"

sample() {
    local started=$SECONDS
    while true; do
        local elapsed=$(( SECONDS - started ))
        local rss="" p99="" qdepth="" centries="" resets="" total=""

        if [ -n "${METRICS_URL}" ]; then
            local body
            body="$(curl -sf --max-time 5 "${METRICS_URL}" 2>/dev/null || true)"
            if [ -n "${body}" ]; then
                qdepth="$(printf '%s' "${body}" | awk '/^hsm_queue_depth /{print $2; exit}')"
                centries="$(printf '%s' "${body}" | awk '/^hsm_cache_entries /{print $2; exit}')"
                resets="$(printf '%s' "${body}" | awk '/^hsm_session_resets_total /{print $2; exit}')"
                total="$(printf '%s' "${body}" \
                    | awk '/^hsm_requests_total/{s+=$2} END{printf "%.0f", s}')"
            fi
        fi

        if [ -n "${SERVER_SSH:-}" ]; then
            rss="$(ssh ${SSH_OPTS:-} "${SERVER_SSH}" \
                "ps -o rss= -C proxy 2>/dev/null | awk '{s+=\$1} END{print s*1024}'" 2>/dev/null || true)"
        fi

        echo "${elapsed},${rss},${p99},${qdepth},${centries},${resets},${total}" >> "${SAMPLES}"
        sleep "${SAMPLE_SECS}"
    done
}

sample &
SAMPLER_PID=$!
trap 'kill "${SAMPLER_PID}" 2>/dev/null || true' EXIT

if [ "${TLS}" = "on" ]; then
    GHZ_TRANSPORT=(--cacert certs/ca.crt
                   --cert "certs/${CLIENT_IDENTITY}.crt"
                   --key "certs/${CLIENT_IDENTITY}.key"
                   --cname "${SERVER_NAME}")
else
    GHZ_TRANSPORT=(--insecure)
fi

START_EPOCH=$(date -u +%s)
ghz "${GHZ_TRANSPORT[@]}" \
    --proto proto/hsm/v1/hsm.proto --import-paths proto \
    --call hsm.v1.HsmService/Sign -d "${DATA}" \
    --rps "${RATE}" -c "${CONCURRENCY}" -n "${TOTAL}" \
    --connections "${CONNECTIONS}" \
    -O json "${TARGET}" > "/tmp/soak-ghz.json" 2>/dev/null || true
END_EPOCH=$(date -u +%s)

kill "${SAMPLER_PID}" 2>/dev/null || true

python3 - "${SAMPLES}" "/tmp/soak-ghz.json" "${RESULT}" "${RATE}" "$(( END_EPOCH - START_EPOCH ))" <<'PY'
import csv, json, sys, os

samples_path, ghz_path, out_path, rate, elapsed = sys.argv[1:6]

rows = []
with open(samples_path) as f:
    for r in csv.DictReader(f):
        rows.append(r)

def series(col):
    out = []
    for r in rows:
        v = r.get(col, "")
        if v not in ("", None):
            try:
                out.append(float(v))
            except ValueError:
                pass
    return out

rss = series("rss_bytes")
resets = series("session_resets")

# Split the run in half and compare, which is what makes drift visible: a leak shows as
# a rising floor, and latency drift as a second half slower than the first.
try:
    d = json.load(open(ghz_path))
    details = d.get("details", [])
except Exception:
    details = []

ok = [x for x in details if x.get("status") == "OK"]
errors = len(details) - len(ok)

def pct(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    return vals[min(int(len(vals) * p / 100), len(vals) - 1)] / 1e6

half = len(ok) // 2
first, second = [x["latency"] for x in ok[:half]], [x["latency"] for x in ok[half:]]

summary = {
    "offered_rate": int(rate),
    "elapsed_seconds": int(elapsed),
    "requests_ok": len(ok),
    "requests_error": errors,
    # NOT derived from len(details): ghz caps the per-request detail array (it recorded
    # 1,000,000 entries for a 57,600,000-request run), so dividing it by elapsed time
    # understates the real rate by the truncation factor -- it reported 278 req/s for a
    # run the server's own counter measured at 15,861 req/s. The detail array is still a
    # valid latency *sample*; it is just not a count. True throughput has to come from
    # the server's hsm_requests_total, which the sampler records.
    "latency_sample_size": len(details),
    "achieved_rps_note": "derive from hsm_requests_total in the samples CSV, not from the detail count",
    "latency": {
        "p50_ms": pct([x["latency"] for x in ok], 50),
        "p99_ms": pct([x["latency"] for x in ok], 99),
        "first_half_p99_ms": pct(first, 99),
        "second_half_p99_ms": pct(second, 99),
    },
    "memory": {
        "samples": len(rss),
        "first_rss_bytes": rss[0] if rss else None,
        "last_rss_bytes": rss[-1] if rss else None,
        "max_rss_bytes": max(rss) if rss else None,
        "growth_bytes": (rss[-1] - rss[0]) if len(rss) >= 2 else None,
        "growth_pct": (100 * (rss[-1] / rss[0] - 1)) if len(rss) >= 2 and rss[0] else None,
    },
    "session_resets": resets[-1] if resets else None,
    "samples_csv": os.path.basename(samples_path),
}

host = json.loads(os.popen("./scripts/host-info.sh").read())
json.dump({"client_host": host, "soak": summary}, open(out_path, "w"), indent=2)

print("\n-- soak summary --")
print(f"  requests ok / error : {summary['requests_ok']:,} / {summary['requests_error']:,}")
print(f"  latency sample      : {summary['latency_sample_size']:,} requests "
      f"(ghz truncates; not a total)")
lat = summary["latency"]
for k in ("p50_ms", "p99_ms", "first_half_p99_ms", "second_half_p99_ms"):
    v = lat[k]
    print(f"  {k:<20}: {v:.3f} ms" if v is not None else f"  {k:<20}: -")
mem = summary["memory"]
if mem["first_rss_bytes"]:
    print(f"  RSS first -> last   : {mem['first_rss_bytes']/1e6:.1f} MB -> "
          f"{mem['last_rss_bytes']/1e6:.1f} MB ({mem['growth_pct']:+.1f}%)")
else:
    print("  RSS                 : not sampled (set SERVER_SSH)")
print(f"  session resets      : {summary['session_resets']}")
print(f"\nsaved: {out_path}")
PY
