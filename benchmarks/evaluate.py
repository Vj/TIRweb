"""
Evaluate TIRweb precision and recall against ground-truth vulnerable targets.

Usage:
    python benchmarks/evaluate.py --manifest benchmarks/ground_truth/targets.json --min-precision 0.90 --min-recall 0.90
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from tirweb.dispatcher import ToolDispatcher
from tirweb.models import AppProfile, AuthContext, TIRWebChecklist
from tirweb.probes import ScanContext


async def evaluate_target(
    checklist: TIRWebChecklist,
    target_spec: dict[str, object],
) -> tuple[int, int, int, list[str], list[str]]:
    url = str(target_spec["url"])
    profile = AppProfile(str(target_spec.get("profile", "core")))
    must_detect: list[str] = list(target_spec.get("must_detect_rule_prefixes", []))  # type: ignore[arg-type]
    must_not_detect: list[str] = list(target_spec.get("must_not_detect_rule_prefixes", []))  # type: ignore[arg-type]

    selected = checklist.filter_checks(profile=profile, include_core=True)
    dispatcher = ToolDispatcher(concurrency=4)
    await dispatcher.initialize_dynamic_bindings()
    ctx = ScanContext(primary_auth=AuthContext())

    results = await asyncio.gather(
        *[dispatcher.execute_check(url, mod, chk, ctx=ctx) for mod, chk in selected]
    )

    emitted_rule_ids = [
        finding.rule_id
        for res in results
        for finding in res.findings
    ]

    tp = 0
    fn_list: list[str] = []
    for expected_prefix in must_detect:
        if any(rid.startswith(expected_prefix) for rid in emitted_rule_ids):
            tp += 1
        else:
            fn_list.append(expected_prefix)

    fp_list: list[str] = []
    for forbidden_prefix in must_not_detect:
        for rid in emitted_rule_ids:
            if rid.startswith(forbidden_prefix):
                fp_list.append(rid)

    return tp, len(fp_list), len(fn_list), fp_list, fn_list


async def main() -> int:
    parser = argparse.ArgumentParser(description="Run TIRweb Precision/Recall Benchmark.")
    parser.add_argument("--manifest", type=Path, default=Path("benchmarks/ground_truth/targets.json"))
    parser.add_argument("--checklist", type=Path, default=Path("rules/tirweb_checklist_v1.yaml"))
    parser.add_argument("--target-filter", type=str, default="", help="Optional target name substring filter")
    parser.add_argument("--min-precision", type=float, default=0.90)
    parser.add_argument("--min-recall", type=float, default=0.90)
    args = parser.parse_args()

    checklist = TIRWebChecklist.from_yaml(args.checklist)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    targets = [
        t for t in manifest["targets"]
        if not args.target_filter or args.target_filter in t["name"]
    ]

    total_tp = 0
    total_fp = 0
    total_fn = 0

    for spec in targets:
        tp, fp, fn, fp_items, fn_items = await evaluate_target(checklist, spec)
        total_tp += tp
        total_fp += fp
        total_fn += fn
        print(f"[{spec['name']}] TP={tp}, FP={fp}, FN={fn}")
        if fn_items:
            print(f"  Missed expected rules: {fn_items}")
        if fp_items:
            print(f"  False positive rules:  {fp_items}")

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 1.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print(f"\nBenchmark Summary -> Precision: {precision:.3f} | Recall: {recall:.3f} | F1: {f1:.3f}")
    if precision < args.min_precision or recall < args.min_recall:
        print(
            f"ERROR: Benchmark threshold failed (required Precision >= {args.min_precision:.2f}, Recall >= {args.min_recall:.2f}).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))