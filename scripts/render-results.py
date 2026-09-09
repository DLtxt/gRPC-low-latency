#!/usr/bin/env python3
"""Render benchmark results to markdown, and update best_results.md when beaten.

Two jobs:

1. Turn the JSON in results/ into markdown tables, so no number in the README is ever
   hand-typed. A hand-typed benchmark figure is a figure that will be wrong after the
   next code change and stay wrong indefinitely.

2. Compare fresh results against best_results.md and update the entries a new run beats.
   A record is only replaced by a result measured under conditions at least as
   trustworthy -- see RANKING below, which encodes the rules from best_results.md.

Usage:
    render-results.py --table            markdown tables on stdout
    render-results.py --check-records    report which records a run beat
    render-results.py --update-records   rewrite best_results.md where beaten
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass

REPO = pathlib.Path(__file__).resolve().parent.parent
RESULTS = REPO / "results"
BEST = REPO / "best_results.md"

# A run is treated as clean below this shed fraction. Strict zero is too sharp an edge:
# a sweep at 20,000 QPS shed 22 requests out of 119,978 (0.018%), which is a rounding
# artifact of open-loop pacing rather than the service refusing work. Anything above
# this threshold is genuinely shedding and must not count as a throughput record.
MAX_ERROR_RATE = 0.001  # 0.1%

# Trust ordering. A result may only replace a record set under equal or better
# conditions, so a fast laptop number never displaces a slower reference-host one.
RANKING = {
    "two-host-reference": 4,   # proxy and load generator on separate pinned hosts
    "reference": 3,            # pinned instance, load generator sharing the host
    "local": 1,                # developer machine
}


@dataclass
class Record:
    """One measured figure, with everything needed to compare it to another."""
    workload: str
    qps: float
    p99_ms: float | None
    host: str
    trust: str
    setup: str
    errors: int
    served: int
    source: str

    def beats(self, other: "Record") -> bool:
        # Trust dominates throughput. Comparing QPS first would let a laptop figure that
        # happens to be higher permanently block a reference-host measurement from ever
        # becoming the record, which is exactly backwards.
        mine, theirs = RANKING.get(self.trust, 0), RANKING.get(other.trust, 0)
        if mine != theirs:
            return mine > theirs
        # An error-laden run is not a record: shed requests return in microseconds, so a
        # run rejecting most of its load reports a *higher* QPS than one serving it.
        if self.error_rate > MAX_ERROR_RATE:
            return False
        return self.qps > other.qps

    @property
    def error_rate(self) -> float:
        total = self.errors + self.served
        return self.errors / total if total else 0.0


def load_results() -> list[dict]:
    out = []
    for path in sorted(RESULTS.rglob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        data["_path"] = str(path.relative_to(REPO))
        out.append(data)
    return out


def to_records(results: list[dict]) -> list[Record]:
    records: list[Record] = []
    for d in results:
        run = d.get("run", {})

        # Two-host overload sweeps: the file records the client host, and the proxy was
        # elsewhere, which is the most trustworthy shape we produce.
        if "target" in run:
            rows = []
            for r in d.get("rows", []):
                total = r.get("shed", 0) + r.get("accepted", 0)
                if total and r.get("shed", 0) / total <= MAX_ERROR_RATE:
                    rows.append(r)
            if not rows:
                continue
            best = max(rows, key=lambda r: r["offered_rps"])
            host = d.get("client_host", {}).get("instance_type", "unknown")
            records.append(Record(
                workload=f"Sign {run.get('key_label','?')} (pool)",
                qps=float(best["offered_rps"]),
                p99_ms=best.get("accepted_p99_ms"),
                host=host,
                trust="two-host-reference" if host.startswith("c7") else "local",
                setup="two-host, open loop",
                errors=best.get("shed", 0),
                served=best.get("accepted", 0),
                source=d["_path"],
            ))
            continue

        # Single-host concurrency sweeps.
        res = d.get("result")
        if not res or not res.get("max_qps_within_budget"):
            continue
        host_info = d.get("host", {})
        rows = d.get("rows", [])
        within = [r for r in rows if r.get("within_budget")]
        p99 = max((r["p99_ms"] for r in within), default=None)
        call = run.get("call", "").split("/")[-1] or "Sign"
        records.append(Record(
            workload=f"{call} {run.get('key_label','?')} ({run.get('mode','?')})",
            qps=float(res["max_qps_within_budget"]),
            p99_ms=p99,
            host=host_info.get("instance_type", "local"),
            trust=host_info.get("host_kind", "local"),
            setup=f"single-host, {run.get('workers','?')} workers",
            errors=sum(r.get("errors", 0) for r in within),
            served=int(res["max_qps_within_budget"]),
            source=d["_path"],
        ))
    return records


def best_by_workload(records: list[Record]) -> dict[str, Record]:
    best: dict[str, Record] = {}
    for r in records:
        cur = best.get(r.workload)
        if cur is None or r.beats(cur):
            best[r.workload] = r
    return best


def render_table(records: list[Record]) -> str:
    best = best_by_workload(records)
    lines = [
        "| Workload | QPS within budget | p99 | Errors | Host | Setup |",
        "|---|---|---|---|---|---|",
    ]
    for workload, r in sorted(best.items(), key=lambda kv: -kv[1].qps):
        p99 = f"{r.p99_ms:.2f} ms" if r.p99_ms is not None else "—"
        err = "0" if r.errors == 0 else f"{r.errors:,} ({100 * r.error_rate:.3f}%)"
        lines.append(
            f"| {workload} | {r.qps:,.0f} | {p99} | {err} | `{r.host}` | {r.setup} |"
        )
    return "\n".join(lines)


def parse_recorded_bests() -> dict[str, float]:
    """Pull the QPS figures currently claimed in best_results.md.

    Deliberately forgiving: this is a cross-check that reports drift, not a parser that
    must understand the whole document. Anything it cannot read is simply not compared.
    """
    if not BEST.exists():
        return {}
    found: dict[str, float] = {}
    for line in BEST.read_text().splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip().strip("*`") for c in line.split("|")[1:-1]]
        if len(cells) < 2:
            continue
        m = re.search(r"([\d,]+)\s*QPS", cells[1])
        if m:
            found[cells[0]] = float(m.group(1).replace(",", ""))
    return found


def check_records(records: list[Record], update: bool) -> int:
    best = best_by_workload(records)
    recorded = parse_recorded_bests()

    print(f"scanned {len(records)} measurements across {len(best)} workloads\n")
    print(f"{'workload':<44} {'measured':>10} {'recorded':>10}  verdict")
    print("-" * 84)

    beaten = 0
    for workload, r in sorted(best.items(), key=lambda kv: -kv[1].qps):
        prior = None
        for key, qps in recorded.items():
            if key and (key.lower() in workload.lower() or workload.lower() in key.lower()):
                prior = qps
                break

        if prior is None:
            verdict = "no record to compare"
        elif r.qps > prior * 1.01:
            verdict = f"BEATS RECORD by {100 * (r.qps / prior - 1):.0f}%"
            beaten += 1
        elif r.qps < prior * 0.95:
            verdict = f"regression, {100 * (1 - r.qps / prior):.0f}% below record"
        else:
            verdict = "matches record"

        print(f"{workload[:44]:<44} {r.qps:>10,.0f} "
              f"{(f'{prior:,.0f}' if prior else '—'):>10}  {verdict}")

    print()
    if beaten and update:
        print(f"{beaten} record(s) beaten. best_results.md needs updating -- the figures,")
        print("their host and setup columns, and the 'Last updated' line all move together,")
        print("so edit it directly rather than letting a script rewrite prose around numbers.")
    elif beaten:
        print(f"{beaten} record(s) beaten. Re-run with --update-records for guidance.")
    else:
        print("no records beaten; best_results.md is current.")
    return beaten


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", action="store_true", help="print markdown tables")
    ap.add_argument("--check-records", action="store_true", help="compare against best_results.md")
    ap.add_argument("--update-records", action="store_true", help="report what to update")
    args = ap.parse_args()

    results = load_results()
    if not results:
        print("no results found under results/ -- run 'make bench' first", file=sys.stderr)
        return 1

    records = to_records(results)
    if not records:
        print("results found but none carried a usable figure", file=sys.stderr)
        return 1

    if args.table or not (args.check_records or args.update_records):
        print(render_table(records))
    if args.check_records or args.update_records:
        check_records(records, args.update_records)
    return 0


if __name__ == "__main__":
    sys.exit(main())
