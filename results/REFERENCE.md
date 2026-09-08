# Reference hosts

Every published figure in the README comes from one of the two instance types below.
Nothing else is eligible, and the harness enforces it: `scripts/host-info.sh` queries
EC2 IMDS for the instance type, and results from anything else are written to
`results/local/` and labelled `local` in their own metadata.

## Why pin hardware at all

This workload is CPU-bound end to end. M0 measured RSA-2048 at ~836 µs and ECDSA P-256
at ~55 µs of pure computation, and the gRPC hop is loopback — there is no network
physics anywhere in the measurement. Results therefore track CPU microarchitecture,
clock, and kernel almost entirely, which is exactly what an instance type fixes.

The alternative that does *not* work is CPU-pinning containers on a laptop. Under Docker
Desktop on macOS the containers run inside a Linux VM, so `cpuset` pins the VM's vCPUs
rather than host cores. That is why plan.md §7 no longer asks for it.

Concretely, this laptop drifted by roughly 25% on an unchanged configuration inside a
single session — 9,952 QPS, then 12,332 QPS for the same 4-worker ECDSA sweep. That is
larger than most of the differences the benchmark is trying to detect.

## The hosts

| Role | Instance | CPU | vCPU | RAM | Why |
|---|---|---|---|---|---|
| ARM reference | `c7g.2xlarge` | Graviton3 | 8 | 16 GiB | Comparable in kind to the M2 dev machine, so local iteration tracks the reference |
| x86 reference | `c7i.2xlarge` | Sapphire Rapids | 8 | 16 GiB | Representative of where most readers would actually deploy this |

Two architectures on purpose. A worker-scaling curve with the same *shape* on both is
evidence about the design; the same curve on one machine is evidence about that machine.

Both are 8 vCPU to match the development machine's core count, so worker-count findings
carry across without re-deriving the knee.

## Reproducing a reference run

Step-by-step commands, including instance launch and teardown, are in
[`docs/running-reference-benchmarks.md`](../docs/running-reference-benchmarks.md).
The short version:

Launch either instance with Ubuntu 24.04. AMI IDs are region-specific and change, so
resolve the current one rather than hardcoding it:

```bash
# ARM (c7g.2xlarge)
AMI=$(aws ssm get-parameters --region us-east-1 \
  --names /aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id \
  --query 'Parameters[0].Value' --output text)

aws ec2 run-instances --region us-east-1 \
  --image-id "$AMI" --instance-type c7g.2xlarge \
  --key-name YOUR_KEY --security-group-ids YOUR_SG \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=gll-bench-arm}]'
```

For x86, swap `arm64` for `amd64` in the SSM parameter and use `c7i.2xlarge`.

Then copy the source across and bootstrap. The repository is **private**, so a fresh
host has no credentials to clone with — `rsync` from a machine that already has the
source is the path that needs no tokens on the benchmark host:

```bash
rsync -az --exclude target --exclude .local --exclude .env --exclude results/local \
    ./ ubuntu@HOST:~/gRPC-low-latency/

ssh ubuntu@HOST 'bash ~/gRPC-low-latency/scripts/bootstrap-linux.sh'
```

(If you would rather clone, export a `GITHUB_TOKEN` with repo read access on the host
and the bootstrap will use it. Do not pipe the script from `curl` — a 404 on a private
repo produces an empty body that `bash` runs happily and exits 0.)

The bootstrap installs build tools, Rust, SoftHSM2, and `ghz`, initializes a token
inside the working tree, builds release binaries, and provisions the demo keys. It is
idempotent and has been verified end to end on a clean Ubuntu 24.04 image.

Then run the suite:

```bash
ssh ubuntu@HOST
cd ~/gRPC-low-latency
export SOFTHSM2_CONF=$PWD/.local/softhsm/softhsm2.conf
set -a; . ./.env; set +a
./scripts/bench-reference.sh
```

Results are written to `results/reference/`, stamped with instance type, region, CPU
model, kernel, toolchain versions, git commit, and whether the tree was dirty. Copy them
back and commit them:

```bash
rsync -az ubuntu@HOST:~/gRPC-low-latency/results/reference/ ./results/reference/
```

**Terminate the instances afterwards.** A full pass is roughly 20–30 minutes per host,
so on-demand cost is well under $1 for both — but an instance left running is not.

## Protocol

Per plan.md §7: 30-second warm-up discarded, median of three runs per cell with min–max
spread reported, error counts printed beside every row. The error column is not
decoration — shed requests are answered fast, so a run that rejects most of its load
reports a *higher* QPS than one that serves it. A row with errors is not a result.

## Status

| Host | Status |
|---|---|
| `c7g.2xlarge` (Graviton3) | **run 2026-09-08** at commit `f9afbfd` — see [`docs/reference-run-c7g.md`](../docs/reference-run-c7g.md) |
| `c7i.2xlarge` (Intel) | not yet run |

Headline from the ARM run: **11,915 QPS ECDSA signing at p99 < 2 ms**, and **17,260 QPS**
for cached verification.

The run also showed that the M2 laptop figures used through M3-M5 were misleading rather
than merely imprecise: RSA throughput is *lower* on Graviton3 (slower per-operation) while
its worker scaling is *far better* (7.93x at 8 threads against 3.69x). The laptop's
asymmetric cores had been capping the scaling curve, and that cap was mistakenly read as a
property of SoftHSM2. Figures in `docs/m3-findings.md` through `docs/m5-findings.md`
remain valid as laptop measurements and should be labelled as such.
