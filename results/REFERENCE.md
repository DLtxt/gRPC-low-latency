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

Then, on the instance:

```bash
curl -sSfL https://raw.githubusercontent.com/DLtxt/gRPC-low-latency/main/scripts/bootstrap-linux.sh | bash
cd ~/gRPC-low-latency
export SOFTHSM2_CONF=$PWD/.local/softhsm/softhsm2.conf
set -a; . ./.env; set +a
./scripts/bench-reference.sh
```

Results are written to `results/reference/`, stamped with instance type, region, CPU
model, kernel, toolchain versions, git commit, and whether the tree was dirty. Copy them
back and commit them:

```bash
scp -r ubuntu@HOST:~/gRPC-low-latency/results/reference/ ./results/
```

**Terminate the instances afterwards.** A full pass is roughly 20–30 minutes per host,
so on-demand cost is well under $1 for both — but an instance left running is not.

## Protocol

Per plan.md §7: 30-second warm-up discarded, median of three runs per cell with min–max
spread reported, error counts printed beside every row. The error column is not
decoration — shed requests are answered fast, so a run that rejects most of its load
reports a *higher* QPS than one that serves it. A row with errors is not a result.

## Status

No reference runs have been recorded yet. Every number quoted in `docs/` so far is from
the local M2 laptop and is provisional.
