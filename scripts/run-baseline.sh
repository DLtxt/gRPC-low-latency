#!/usr/bin/env bash
# Run the Go baseline in all three modes and write the results as JSON.
#
# The three modes exist to make one point that no single number can: adding threads to a
# single PKCS#11 session buys nothing. `naive-concurrent` is the mistake stated plainly,
# and it should come out no faster than `serial` while its tail latency collapses.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. ./scripts/lib-common.sh

export PKCS11_MODULE="${PKCS11_MODULE:-$(find_pkcs11_module)}"
DURATION="${DURATION:-5s}"
WORKERS="${WORKERS:-8}"
MECHANISM="${MECHANISM:-ecdsa}"
KEY="${KEY:-demo-ec-p256}"

HOST_KIND="$(./scripts/host-info.sh | awk -F'"' '/host_kind/{print $4}')"
OUT="results/${HOST_KIND}"
mkdir -p "${OUT}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

[ -x ./bin/baseline ] || (cd baseline && go build -o ../bin/baseline ./...)

printf '%-20s %-8s %-13s %-11s %-11s\n' mode workers ops/sec p50 p99
printf '%.0s-' {1..66}; echo

for MODE in serial naive-concurrent pooled; do
    JSON="${OUT}/${STAMP}-baseline-${MODE}-${MECHANISM}.json"
    ./bin/baseline -mode "${MODE}" -workers "${WORKERS}" -duration "${DURATION}" \
        -mechanism "${MECHANISM}" -key "${KEY}" -json "${JSON}" > /tmp/baseline-out 2>&1 || {
        echo "FAILED: ${MODE}"; cat /tmp/baseline-out; exit 1; }

    python3 - "${JSON}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"{d['mode']:<20} {d['workers']:<8} {d['ops_per_sec']:<13.0f} "
      f"{d['p50_micros']:<11.0f} {d['p99_micros']:<11.0f}")
PY
done

echo
echo "results in ${OUT}/"
