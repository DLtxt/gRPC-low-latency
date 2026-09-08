#!/usr/bin/env bash
# Open-loop overload sweep: hold a fixed offered rate and report accepted and shed
# requests as separate populations.
#
# Two departures from bench-sweep.sh, both required to answer the M6 question:
#
# 1. **Open loop.** ghz's default closed-loop mode keeps a fixed number of requests in
#    flight, so a fast rejection immediately frees a slot and the client sends more.
#    Under load shedding that inflates offered load without bound and makes "capacity"
#    an artifact of how quickly the server says no. `--rps` fixes the offered rate, which
#    is what "3x capacity" has to mean.
#
# 2. **Accepted and shed reported separately.** A shed request is answered in
#    microseconds, so mixing the two populations drags the reported p99 *down* as the
#    server gets worse. The claim under test is about accepted requests alone.
#
# TARGET must point at a proxy on a *different host*. M6 established that running the
# load generator beside the proxy measures the two competing for CPU: changing only
# client concurrency swung accepted p99 between 0.65 ms and 105 ms, and mean HSM service
# time rose 259 -> 500 us purely from starvation. Overload numbers from a shared host
# are not evidence.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET="${TARGET:?TARGET must be set, e.g. TARGET=10.0.1.5:50051}"
KEY="${KEY:-demo-ec-p256}"
MECHANISM="${MECHANISM:-SIGNATURE_MECHANISM_ECDSA_SHA256}"
RATES="${RATES:-2000 4000 8000 12000 16000 24000 32000 48000}"
DURATION="${DURATION:-8}"
CONCURRENCY="${CONCURRENCY:-200}"
CONNECTIONS="${CONNECTIONS:-16}"
BUDGET_MS="${BUDGET_MS:-2.0}"
LABEL="${LABEL:-overload}"

command -v ghz >/dev/null || { echo "ghz not found" >&2; exit 1; }

HOST_JSON="$(./scripts/host-info.sh)"
HOST_KIND="$(printf '%s' "${HOST_JSON}" | awk -F'"' '/host_kind/{print $4}')"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="results/${HOST_KIND}"
mkdir -p "${RESULT_DIR}"
RESULT_FILE="${RESULT_DIR}/${STAMP}-${LABEL}-${KEY}.json"

PAYLOAD="$(printf 'overload probe' | base64)"
DATA="{\"key_label\":\"${KEY}\",\"mechanism\":\"${MECHANISM}\",\"input\":{\"message\":\"${PAYLOAD}\"}}"

echo "target:  ${TARGET}  (load generator is on this host, proxy is not)"
echo "budget:  p99 < ${BUDGET_MS} ms for accepted requests"
echo
printf '%-9s %-10s %-9s %-8s %-11s %-11s %-11s\n' \
    offered achieved accepted shed% 'acc p50' 'acc p99' 'shed p99'
printf '%.0s-' {1..74}; echo

ROWS=""
TMP="$(mktemp -d "${TMPDIR:-/tmp}/gll-overload.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

for RPS in ${RATES}; do
    TOTAL=$(( RPS * DURATION ))
    ghz --insecure \
        --proto proto/hsm/v1/hsm.proto --import-paths proto \
        --call hsm.v1.HsmService/Sign -d "${DATA}" \
        --rps "${RPS}" -c "${CONCURRENCY}" -n "${TOTAL}" \
        --connections "${CONNECTIONS}" \
        -O json "${TARGET}" > "${TMP}/r-${RPS}.json" 2>/dev/null || true

    python3 - "${TMP}/r-${RPS}.json" "${RPS}" "${BUDGET_MS}" <<'PY'
import json, sys

path, rps, budget = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
try:
    d = json.load(open(path))
except Exception:
    print(f'{rps:<9} FAILED')
    raise SystemExit

details = d.get("details", [])
ok = [x["latency"] for x in details if x["status"] == "OK"]
shed = [x["latency"] for x in details if x["status"] != "OK"]

def pct(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    return vals[min(int(len(vals) * p / 100), len(vals) - 1)] / 1e6

total = len(ok) + len(shed)
if total == 0:
    print(f'{rps:<9} no responses')
    raise SystemExit

achieved = d.get("rps", 0)
shed_pct = 100 * len(shed) / total
p50, p99 = pct(ok, 50), pct(ok, 99)
shed_p99 = pct(shed, 99)

print(f'{rps:<9} {achieved:<10.0f} {len(ok):<9} {shed_pct:>3.0f}%    '
      f'{(f"{p50:.2f}" if p50 else "-"):<11} '
      f'{(f"{p99:.2f}" if p99 else "-"):<11} '
      f'{(f"{shed_p99:.2f}" if shed_p99 else "-"):<11}')

# Emitted for the JSON record assembled by the caller.
with open(path + ".row", "w") as f:
    json.dump({
        "offered_rps": rps,
        "achieved_rps": round(achieved),
        "accepted": len(ok),
        "shed": len(shed),
        "shed_pct": round(shed_pct, 1),
        "accepted_p50_ms": p50,
        "accepted_p99_ms": p99,
        "shed_p99_ms": shed_p99,
        "accepted_within_budget": bool(p99 is not None and p99 < budget),
    }, f)
PY
done

# Assemble the result file from the per-rate rows.
python3 - "${TMP}" "${RESULT_FILE}" "${TARGET}" "${KEY}" "${MECHANISM}" "${BUDGET_MS}" <<'PY'
import json, glob, sys, os

tmp, out, target, key, mech, budget = sys.argv[1:7]
rows = []
for path in sorted(glob.glob(os.path.join(tmp, "*.row")),
                   key=lambda p: int(os.path.basename(p).split("-")[1].split(".")[0])):
    rows.append(json.load(open(path)))

host = json.loads(os.popen("./scripts/host-info.sh").read())

# Capacity is the highest offered rate still served with essentially no shedding.
capacity = max((r["offered_rps"] for r in rows if r["shed_pct"] < 1.0), default=0)

json.dump({
    "host_note": "load generator host; the proxy runs on a separate machine",
    "client_host": host,
    "run": {
        "target": target,
        "key_label": key,
        "mechanism": mech,
        "budget_p99_ms": float(budget),
        "mode": "open-loop (fixed offered rate)",
    },
    "rows": rows,
    "analysis": {
        "capacity_rps": capacity,
        "accepted_p99_at_1x_ms": next((r["accepted_p99_ms"] for r in rows
                                       if r["offered_rps"] == capacity), None),
        "accepted_p99_at_2x_ms": next((r["accepted_p99_ms"] for r in rows
                                       if r["offered_rps"] >= 2 * capacity), None),
        "accepted_p99_at_3x_ms": next((r["accepted_p99_ms"] for r in rows
                                       if r["offered_rps"] >= 3 * capacity), None),
    },
}, open(out, "w"), indent=2)
print(f"\nsaved:  {out}")
print(f"capacity (highest rate with <1% shed): {capacity} QPS")
PY
