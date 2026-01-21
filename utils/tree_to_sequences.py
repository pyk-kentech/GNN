#!/usr/bin/env python3
"""
Convert tree_edges.jsonl into per-process sequences for next-step prediction.

Input: tree_edges.jsonl (records with parent, child, child_type, last_ts, probability, weight)
Output:
  - sequences.jsonl: one line per parent process:
      {"parent":..., "tokens":[...], "ts":[...], "probs":[...], "weights":[...]}
  - nextstep.jsonl: training samples for next-token prediction:
      {"parent":..., "context":[...], "next":..., "t":..., "p":...}
"""

from __future__ import annotations
import argparse, json
from collections import defaultdict
from typing import Dict, List, Any, Tuple

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True, help="tree_edges.jsonl")
    ap.add_argument("--out-seq", required=True, help="sequences.jsonl")
    ap.add_argument("--out-next", required=True, help="nextstep.jsonl")
    ap.add_argument("--min-len", type=int, default=2, help="min tokens per parent to keep")
    ap.add_argument("--max-context", type=int, default=50, help="max context length for next-step samples")
    return ap.parse_args()

def main():
    args = parse_args()

    per_parent: Dict[str, List[Tuple[int, Dict[str, Any]]]] = defaultdict(list)

    with open(args.tree, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            p = r["parent"]
            t = int(r.get("last_ts", 0))
            per_parent[p].append((t, r))

    # write sequences
    kept = 0
    with open(args.out_seq, "w", encoding="utf-8") as out_seq, \
         open(args.out_next, "w", encoding="utf-8") as out_next:

        for parent, items in per_parent.items():
            items.sort(key=lambda x: x[0])  # by last_ts

            tokens = [it[1].get("child_type", "") or "" for it in items]
            ts     = [it[0] for it in items]
            probs  = [float(it[1].get("probability", 0.0)) for it in items]
            wts    = [float(it[1].get("weight", 0.0)) for it in items]

            # filter empties
            filt = [(tok, t, p, w) for tok, t, p, w in zip(tokens, ts, probs, wts) if tok]
            if len(filt) < args.min_len:
                continue

            tokens, ts, probs, wts = zip(*filt)
            tokens, ts, probs, wts = list(tokens), list(ts), list(probs), list(wts)

            out_seq.write(json.dumps({
                "parent": parent,
                "tokens": tokens,
                "ts": ts,
                "probs": probs,
                "weights": wts,
                "length": len(tokens),
            }) + "\n")
            kept += 1

            # next-step samples
            # for i: context=tokens[max(0,i-max_context):i] -> next=tokens[i]
            for i in range(1, len(tokens)):
                ctx = tokens[max(0, i - args.max_context): i]
                out_next.write(json.dumps({
                    "parent": parent,
                    "context": ctx,
                    "next": tokens[i],
                    "t": ts[i],
                    "p": probs[i],
                    "w": wts[i],
                }) + "\n")

    print(f"[DONE] parents kept: {kept}")
    print(f"[OUT] {args.out_seq}")
    print(f"[OUT] {args.out_next}")

if __name__ == "__main__":
    main()
