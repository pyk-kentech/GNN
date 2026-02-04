#!/usr/bin/env python3
"""
extract_path_features.py

Attack DAG(jsonl edges)에서 root->leaf path를 추출하고
각 path를 feature 벡터로 변환.

출력:
- CSV (path feature table)
"""

import argparse
import json
from collections import defaultdict
import pandas as pd

# -----------------------------
# Load DAG
# -----------------------------
def load_dag(edge_path):
    children = defaultdict(list)
    parents = defaultdict(list)
    edge_feat = {}

    with open(edge_path) as f:
        for line in f:
            r = json.loads(line)
            u = r["parent"]
            v = r["child"]
            children[u].append(v)
            parents[v].append(u)
            edge_feat[(u, v)] = r

    roots = [n for n in children if n not in parents]
    leaves = [n for n in parents if n not in children]

    return children, parents, edge_feat, roots, leaves


# -----------------------------
# Path enumeration (DFS)
# -----------------------------
def enumerate_paths(children, root, max_depth):
    paths = []

    def dfs(cur, path):
        if len(path) > max_depth or cur not in children:
            paths.append(path)
            return
        for nxt in children[cur]:
            if nxt in path:  # safety for cycles
                continue
            dfs(nxt, path + [nxt])

    dfs(root, [root])
    return paths


# -----------------------------
# Feature extraction
# -----------------------------
def path_features(path, edge_feat):
    rare_sum = 0.0
    rare_cnt = 0
    time_start = None
    time_end = None
    max_gap = 0

    prev_ts = None

    for u, v in zip(path[:-1], path[1:]):
        e = edge_feat[(u, v)]
        feats = e.get("features", {})
        rare = float(feats.get("rare_score", 0.0))
        rare_sum += rare
        if rare > 0:
            rare_cnt += 1

        ts_f = int(e["first_ts"])
        ts_l = int(e["last_ts"])

        if time_start is None:
            time_start = ts_f
        time_end = ts_l

        if prev_ts is not None:
            max_gap = max(max_gap, ts_f - prev_ts)
        prev_ts = ts_l

    length = len(path) - 1
    duration = (time_end - time_start) if time_start is not None else 0.0
    rare_density = rare_cnt / max(1, length)

    return {
        "path_length": length,
        "path_duration_ns": duration,
        "rare_sum": rare_sum,
        "rare_count": rare_cnt,
        "rare_density": rare_density,
        "max_time_gap_ns": max_gap,
    }


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--edges", required=True)
    ap.add_argument("--out-csv", default="path_features.csv")
    ap.add_argument("--max-depth", type=int, default=10)
    ap.add_argument("--top-k", type=int, default=50)
    args = ap.parse_args()

    children, parents, edge_feat, roots, leaves = load_dag(args.edges)

    print("[INFO] roots:", roots)
    print("[INFO] leaves:", len(leaves))

    all_rows = []

    for root in roots:
        paths = enumerate_paths(children, root, args.max_depth)
        for p in paths:
            feats = path_features(p, edge_feat)
            feats["root"] = root
            feats["leaf"] = p[-1]
            feats["path"] = "->".join(p)
            all_rows.append(feats)

    df = pd.DataFrame(all_rows)

    # ranking & top-K
    df = df.sort_values(
        by=["rare_sum", "path_length", "path_duration_ns"],
        ascending=False,
    ).head(args.top_k)

    df.to_csv(args.out_csv, index=False)
    print("[OK] wrote:", args.out_csv)
    print(df.head(10))


if __name__ == "__main__":
    main()
