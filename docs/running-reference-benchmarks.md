# Running the reference benchmarks

Step-by-step commands for producing the published figures on the pinned hosts. For
*why* these two instance types, and what makes a result eligible for the README, see
[`results/REFERENCE.md`](../results/REFERENCE.md).

Everything here runs from your machine against EC2. The benchmark host needs no AWS
credentials and no GitHub access — the source is copied to it with `rsync`.

Budget roughly 40 minutes per host: ~5 minutes to build, ~20–30 minutes for the suite.

---

## 1. Launch the instances

Requires an existing key pair and a security group that allows SSH from your address.
AMI IDs are region-specific and change over time, so resolve the current one from SSM
rather than hardcoding it.

```bash
REGION=us-east-1
KEY=YOUR_KEY_NAME
SG=YOUR_SECURITY_GROUP_ID

# ARM reference -- c7g.2xlarge (Graviton3)
AMI_ARM=$(aws ssm get-parameters --region $REGION \
  --names /aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id \
  --query 'Parameters[0].Value' --output text)

aws ec2 run-instances --region $REGION --image-id "$AMI_ARM" \
  --instance-type c7g.2xlarge --key-name "$KEY" --security-group-ids "$SG" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=gll-bench-arm}]'

# x86 reference -- c7i.2xlarge (Sapphire Rapids)
AMI_X86=$(aws ssm get-parameters --region $REGION \
  --names /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query 'Parameters[0].Value' --output text)

aws ec2 run-instances --region $REGION --image-id "$AMI_X86" \
  --instance-type c7i.2xlarge --key-name "$KEY" --security-group-ids "$SG" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=gll-bench-x86}]'
```

Collect the public DNS names once they are running:

```bash
aws ec2 describe-instances --region $REGION \
  --filters 'Name=tag:Name,Values=gll-bench-*' 'Name=instance-state-name,Values=running' \
  --query 'Reservations[].Instances[].[Tags[?Key==`Name`].Value|[0],InstanceId,PublicDnsName]' \
  --output table
```

---

## 2. Copy the source and bootstrap

Run from the repository root on your machine, once per host.

```bash
HOST=ubuntu@ec2-XX-XX-XX-XX.compute-1.amazonaws.com

rsync -az --exclude target --exclude .local --exclude .env --exclude 'results/local' \
    ./ $HOST:~/gRPC-low-latency/

ssh $HOST 'bash ~/gRPC-low-latency/scripts/bootstrap-linux.sh'
```

The excludes matter. `target` is a macOS build tree and would be useless (and large) on
Linux; `.local` holds a token bound to local paths; `.env` holds this machine's PINs, and
the bootstrap generates fresh ones on the host.

Bootstrap installs build tools, Rust, SoftHSM2, and `ghz`, initializes a token inside the
working tree, builds release binaries, and provisions the demo keys. It is idempotent, so
re-running after a failure is safe. Verified end to end on a clean Ubuntu 24.04 image.

---

## 3. Run the suite

```bash
ssh $HOST 'cd ~/gRPC-low-latency && \
  export SOFTHSM2_CONF=$PWD/.local/softhsm/softhsm2.conf && \
  set -a && . ./.env && set +a && \
  export PATH=$HOME/.cargo/bin:$PATH && \
  ./scripts/bench-reference.sh' 2>&1 | tee bench-$(date +%s).log
```

This runs, in order: ECDSA single-session baseline, ECDSA worker pool, RSA-2048
single-session baseline, RSA-2048 worker pool, and the token ceiling probe (raw PKCS#11,
no gRPC in the path). Tables stream as they complete, so you can sanity-check the numbers
before it finishes.

Every row shows an **errors** column. Treat any row with a non-zero count as void: shed
requests are answered fast, so a run that rejects most of its load reports a *higher* QPS
than one that serves it.

---

## 4. Collect the results

```bash
rsync -az $HOST:~/gRPC-low-latency/results/reference/ ./results/reference/
```

Safe to run for both hosts into the same directory — filenames carry a UTC timestamp and
the run configuration, and each file records its own instance type, so ARM and x86 results
cannot be confused or overwritten.

---

## 5. Terminate

The only step that costs real money if skipped.

```bash
aws ec2 terminate-instances --region $REGION --instance-ids i-XXXXXXXX i-YYYYYYYY

# confirm nothing is left running
aws ec2 describe-instances --region $REGION \
  --filters 'Name=tag:Name,Values=gll-bench-*' 'Name=instance-state-name,Values=running' \
  --query 'Reservations[].Instances[].InstanceId' --output text
```

An empty result means everything is shut down.

---

## Troubleshooting

**`something is already listening on port 50051`** — the guard is working. A proxy from
an interrupted run is still up. `pkill -f target/release/proxy` on the host, then re-run.

**`could not locate libsofthsm2.so`** — the bootstrap did not finish. Re-run it; it is
idempotent and will report which step failed.

**Results land in `results/local/` instead of `results/reference/`** — IMDS did not
return a recognised instance type, so the host was not identified as a reference machine.
Check the instance really is `c7g.2xlarge` or `c7i.2xlarge`, and that IMDS is reachable
(`curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'`
should return a token). This is deliberate: the harness will not let an unpinned host
produce a published figure.
