#!/usr/bin/env bash
# Emit the host's identity as JSON, so every benchmark result carries the machine
# that produced it.
#
# A throughput number without its hardware is not a result, it is an anecdote: this
# workload is CPU-bound end to end, so the figures track microarchitecture and kernel
# almost entirely. On EC2 the instance type is queried from IMDS, which is what lets a
# result prove it came from a pinned reference host rather than someone's laptop.
set -euo pipefail

json_escape() { printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
field() { printf '  "%s": "%s",\n' "$1" "$(json_escape "${2:-unknown}")"; }

OS="$(uname -s)"
ARCH="$(uname -m)"
KERNEL="$(uname -r)"

case "${OS}" in
    Darwin)
        CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
        CPU_CORES="$(sysctl -n hw.physicalcpu 2>/dev/null || echo 0)"
        CPU_THREADS="$(sysctl -n hw.ncpu 2>/dev/null || echo 0)"
        MEM_BYTES="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
        OS_VERSION="macOS $(sw_vers -productVersion 2>/dev/null || echo unknown)"
        ;;
    Linux)
        # /proc/cpuinfo carries "model name" only on x86. ARM exposes numeric
        # implementer/part registers instead, so Graviton would record nothing at all --
        # which defeats the purpose of stamping the host. lscpu synthesizes a real name
        # on both, so prefer it and keep /proc/cpuinfo as the fallback.
        CPU_MODEL="$(lscpu 2>/dev/null | awk -F': +' '/^Model name/{print $2; exit}')"
        if [ -z "${CPU_MODEL}" ]; then
            CPU_MODEL="$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
        fi
        if [ -z "${CPU_MODEL}" ]; then
            IMPL="$(awk -F': ' '/CPU implementer/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
            PART="$(awk -F': ' '/CPU part/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
            [ -n "${IMPL}" ] && CPU_MODEL="ARM implementer ${IMPL} part ${PART}"
        fi
        CPU_MODEL="${CPU_MODEL:-unknown}"
        CPU_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)"
        CPU_THREADS="${CPU_CORES}"
        MEM_BYTES="$(( $(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0) * 1024 ))"
        OS_VERSION="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME}" || echo Linux)"
        ;;
    *)
        CPU_MODEL=unknown; CPU_CORES=0; CPU_THREADS=0; MEM_BYTES=0; OS_VERSION="${OS}"
        ;;
esac

# --- EC2 instance identity (IMDSv2), if we are on EC2 -------------------------
INSTANCE_TYPE=""
INSTANCE_REGION=""
IMDS_TOKEN="$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" --max-time 1 2>/dev/null || true)"
if [ -n "${IMDS_TOKEN}" ]; then
    INSTANCE_TYPE="$(curl -sf -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" --max-time 1 \
        http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || true)"
    INSTANCE_REGION="$(curl -sf -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" --max-time 1 \
        http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)"
fi

# The pinned reference hosts from plan.md 7. Only results from these are eligible to
# become published README figures; everything else is labelled local.
REFERENCE_TYPES="c7g.2xlarge c7i.2xlarge"
IS_REFERENCE=false
for T in ${REFERENCE_TYPES}; do
    [ "${INSTANCE_TYPE}" = "${T}" ] && IS_REFERENCE=true
done

version_of() { command -v "$1" >/dev/null 2>&1 && ( "$@" 2>&1 | head -1 ) || echo "absent"; }

printf '{\n'
field host_kind "$([ "${IS_REFERENCE}" = true ] && echo reference || echo local)"
field instance_type "${INSTANCE_TYPE:-none}"
field region "${INSTANCE_REGION:-none}"
field os "${OS_VERSION}"
field kernel "${KERNEL}"
field arch "${ARCH}"
field cpu_model "${CPU_MODEL}"
field cpu_cores "${CPU_CORES}"
field cpu_threads "${CPU_THREADS}"
field mem_bytes "${MEM_BYTES}"
field rustc "$(version_of rustc --version)"
field go "$(version_of go version)"
field ghz "$(version_of ghz --version)"
field softhsm "$(version_of softhsm2-util --version)"
field docker "$(version_of docker --version)"
field git_commit "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
# Distinguish "no git repository here" from "repository with uncommitted changes".
# Reporting a source export as dirty would wrongly discredit a valid reference run.
if git rev-parse --git-dir >/dev/null 2>&1; then
    field git_dirty "$(git diff --quiet 2>/dev/null && echo clean || echo dirty)"
else
    field git_dirty "no-git"
fi
printf '  "timestamp_utc": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '}\n'
