 #!/usr/bin/env python3
"""
Build a root-centered arborescence (spanning tree-like) from MAGIC aggregated graph.

Input pickle format (as used in your project):
  obj["nodes"]: dict[nid -> dict(..., "type": str)]
  obj["edges"]: dict[(src, dst) -> attr]
    attr includes:
      - cnt_common: dict[event -> int]
      - rare_flags: dict[event -> bool]
      - first_ts, last_ts: int (ns)
      - weight: float (optional)

Core rules (aligned with our discussion):
  - Root: choose a SUBJECT_PROCESS node by strategy (out_degree / total_events / earliest_rare)
  - Expansion: ONLY expand SUBJECT_PROCESS nodes (process -> ...)
  - Parent conflict (child has 2+ parents): keep ONE by (last_ts desc, then weight desc)
  - Edge weight: a*log1p(total_events) + b*time_score + c*rare_score
  - Probability: per-parent softmax over child edge weights
Outputs:
  - edges.jsonl: one record per selected tree edge with weight/prob/ts/types
  - summary.json: basic stats
"""

from __future__ import annotations

import argparse
import json
import math
import pickle
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


SUBJECT_PROCESS = "SUBJECT_PROCESS"

IMPORTANT_RARE_EVENTS = {
    "EVENT_EXECUTE": 3.0,
    "EVENT_CONNECT": 3.0,
    "EVENT_ACCEPT": 2.5,
    "EVENT_LOADLIBRARY": 2.5,
    "EVENT_CHANGE_PRINCIPAL": 2.5,
    "EVENT_UNLINK": 2.0,
    "EVENT_CREATE_OBJECT": 2.0,
    "EVENT_RENAME": 2.0,
    "EVENT_TRUNCATE": 2.0,
    "EVENT_FORK": 2.0,
    "EVENT_CLONE": 2.0,
    "EVENT_MPROTECT": 1.5,
}


@dataclass
class EdgeInfo:
    parent: str
    child: str
    child_type: str
    first_ts: int
    last_ts: int
    weight: float


def load_graph(path: str) -> Tuple[Dict[str, Dict[str, Any]], Dict[Tuple[str, str], Dict[str, Any]]]:
    with open(path, "rb") as f:
        obj = pickle.load(f)
    return obj["nodes"], obj["edges"]


def is_subject(nid: str, nodes: Dict[str, Dict[str, Any]]) -> bool:
    return nodes.get(nid, {}).get("type") == SUBJECT_PROCESS


def build_out_index(
    edges: Dict[Tuple[str, str], Dict[str, Any]]
) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    out_adj: Dict[str, List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)
    for (u, v), attr in edges.items():
        out_adj[u].append((v, attr))
    return out_adj


def collect_root_stats(nodes, edges):
    out_degree = Counter()
    total_events = Counter()
    earliest_rare_ts: Dict[str, int] = {}

    for (src, _dst), attr in edges.items():
        if not is_subject(src, nodes):
            continue
        out_degree[src] += 1

        cc = attr.get("cnt_common", {}) or {}
        total_events[src] += sum(int(x) for x in cc.values() if x)

        rf = attr.get("rare_flags", {}) or {}
        if any(bool(v) for v in rf.values()):
            first_ts = int(attr.get("first_ts", 0))
            prev = earliest_rare_ts.get(src)
            if prev is None or first_ts < prev:
                earliest_rare_ts[src] = first_ts

    return out_degree, total_events, earliest_rare_ts


def select_root(nodes, edges, strategy: str) -> Optional[str]:
    subjects = [nid for nid, data in nodes.items() if data.get("type") == SUBJECT_PROCESS]
    if not subjects:
        return None

    out_degree, total_events, earliest_rare_ts = collect_root_stats(nodes, edges)

    if strategy == "out_degree":
        return max(subjects, key=lambda n: out_degree.get(n, 0))
    if strategy == "total_events":
        return max(subjects, key=lambda n: total_events.get(n, 0))
    if strategy == "earliest_rare":
        cand = [n for n in subjects if n in earliest_rare_ts]
        if not cand:
            return None
        return min(cand, key=lambda n: earliest_rare_ts[n])

    raise ValueError(f"Unknown root strategy: {strategy}")


def compute_time_window(edges, root: str) -> Tuple[int, int]:
    min_ts: Optional[int] = None
    max_ts: Optional[int] = None
    for (src, _dst), attr in edges.items():
        if src != root:
            continue
        f = int(attr.get("first_ts", 0))
        l = int(attr.get("last_ts", 0))
        min_ts = f if min_ts is None else min(min_ts, f)
        max_ts = l if max_ts is None else max(max_ts, l)
    return (min_ts or 0, max_ts or 0)


def edge_weight(attr: Dict[str, Any], min_ts: int, max_ts: int, a: float, b: float, c: float) -> float:
    cc = attr.get("cnt_common", {}) or {}
    total_cnt = sum(int(x) for x in cc.values() if x)
    w_count = math.log1p(total_cnt)

    last_ts = int(attr.get("last_ts", 0))
    time_score = (last_ts - min_ts) / (max_ts - min_ts) if max_ts > min_ts else 0.0

    rf = attr.get("rare_flags", {}) or {}
    rare_score = 0.0
    for ev, flag in rf.items():
        if not flag:
            continue
        rare_score += IMPORTANT_RARE_EVENTS.get(ev, 1.0)

    return a * w_count + b * time_score + c * rare_score


def choose_better(existing: Optional[EdgeInfo], cand: EdgeInfo) -> EdgeInfo:
    if existing is None:
        return cand
    # later event wins; if tie, heavier wins
    if cand.last_ts > existing.last_ts:
        return cand
    if cand.last_ts < existing.last_ts:
        return existing
    if cand.weight > existing.weight:
        return cand
    return existing


def build_tree(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[Tuple[str, str], Dict[str, Any]],
    root: str,
    max_depth: int,
    time_window_ns: Optional[int],
    a: float,
    b: float,
    c: float,
) -> Tuple[Dict[str, EdgeInfo], Dict[str, List[str]], Dict[str, int]]:
    out_adj = build_out_index(edges)

    min_ts, max_ts = compute_time_window(edges, root)
    if time_window_ns is not None and max_ts > min_ts:
        max_ts = min_ts + time_window_ns

    parent_by_child: Dict[str, EdgeInfo] = {}
    frontier = [root]
    depth = 0
    visited_subjects = {root}

    while frontier and depth < max_depth:
        next_frontier: List[str] = []
        candidate_subjects: List[str] = []

        for src in frontier:
            for dst, attr in out_adj.get(src, []):
                if time_window_ns is not None:
                    f = int(attr.get("first_ts", 0))
                    if f > max_ts:
                        continue

                w = edge_weight(attr, min_ts, max_ts, a, b, c)
                ei = EdgeInfo(
                    parent=src,
                    child=dst,
                    child_type=nodes.get(dst, {}).get("type", ""),
                    first_ts=int(attr.get("first_ts", 0)),
                    last_ts=int(attr.get("last_ts", 0)),
                    weight=w,
                )
                parent_by_child[dst] = choose_better(parent_by_child.get(dst), ei)

                # only processes can be expanded (depth growth)
                if is_subject(dst, nodes):
                    candidate_subjects.append(dst)

        for child in candidate_subjects:
            if child in visited_subjects or depth + 1 >= max_depth:
                continue
            chosen = parent_by_child.get(child)
            if chosen and chosen.parent in visited_subjects:
                visited_subjects.add(child)
                next_frontier.append(child)

        frontier = next_frontier
        depth += 1

    children_by_parent: Dict[str, List[str]] = defaultdict(list)
    for child, ei in parent_by_child.items():
        if child == root:
            continue
        children_by_parent[ei.parent].append(child)

    # helpful sanity counts
    sanity = {
        "num_edges_selected": len(parent_by_child),
        "num_subject_in_tree_excl_root": sum(1 for n in parent_by_child if is_subject(n, nodes)),
        "num_leaf_in_tree": sum(1 for n in parent_by_child if not is_subject(n, nodes)),
    }
    return parent_by_child, children_by_parent, sanity


def softmax_probs(children_by_parent: Dict[str, List[str]], parent_by_child: Dict[str, EdgeInfo]) -> Dict[Tuple[str, str], float]:
    probs: Dict[Tuple[str, str], float] = {}
    for p, childs in children_by_parent.items():
        ws = [parent_by_child[ch].weight for ch in childs]
        m = max(ws) if ws else 0.0
        exps = [math.exp(w - m) for w in ws]
        denom = sum(exps)
        for ch, s in zip(childs, exps):
            probs[(p, ch)] = (s / denom) if denom else 0.0
    return probs


def write_outputs(
    out_edges: str,
    out_summary: str,
    root: str,
    nodes: Dict[str, Dict[str, Any]],
    parent_by_child: Dict[str, EdgeInfo],
    children_by_parent: Dict[str, List[str]],
    probs: Dict[Tuple[str, str], float],
    params: Dict[str, Any],
    sanity: Dict[str, int],
) -> None:
    type_dist = Counter(nodes.get(ch, {}).get("type", "") for ch in parent_by_child)

    with open(out_edges, "w", encoding="utf-8") as f:
        for (p, ch), pr in probs.items():
            ei = parent_by_child[ch]
            f.write(json.dumps({
                "parent": p,
                "parent_type": nodes.get(p, {}).get("type", ""),
                "child": ch,
                "child_type": ei.child_type,
                "first_ts": ei.first_ts,
                "last_ts": ei.last_ts,
                "weight": ei.weight,
                "probability": pr,
            }) + "\n")

    with open(out_summary, "w", encoding="utf-8") as f:
        json.dump({
            "root": root,
            "root_type": nodes.get(root, {}).get("type", ""),
            "number_of_nodes_in_tree": len(parent_by_child) + 1,
            "type_distribution": dict(type_dist),
            "children_counts": {p: len(cs) for p, cs in children_by_parent.items()},
            "parameters": params,
            "sanity": sanity,
        }, f, indent=2)


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("pickle_path")
    ap.add_argument("--root-strategy", choices=["out_degree", "total_events", "earliest_rare"], default="out_degree")
    ap.add_argument("--max-depth", type=int, default=1)
    ap.add_argument("--time-window-ns", type=int, default=None)
    ap.add_argument("--weight-a", type=float, default=1.0)
    ap.add_argument("--weight-b", type=float, default=1.0)
    ap.add_argument("--weight-c", type=float, default=1.0)
    ap.add_argument("--out-edges", default="tree_edges.jsonl")
    ap.add_argument("--out-summary", default="tree_summary.json")
    return ap.parse_args()


def main():
    args = parse_args()
    nodes, edges = load_graph(args.pickle_path)

    root = select_root(nodes, edges, args.root_strategy)
    if root is None:
        raise SystemExit("No SUBJECT_PROCESS root found.")

    parent_by_child, children_by_parent, sanity = build_tree(
        nodes, edges, root,
        max_depth=args.max_depth,
        time_window_ns=args.time_window_ns,
        a=args.weight_a, b=args.weight_b, c=args.weight_c,
    )
    probs = softmax_probs(children_by_parent, parent_by_child)

    params = {
        "pickle_path": args.pickle_path,
        "root_strategy": args.root_strategy,
        "max_depth": args.max_depth,
        "time_window_ns": args.time_window_ns,
        "weight_a": args.weight_a,
        "weight_b": args.weight_b,
        "weight_c": args.weight_c,
    }
    write_outputs(args.out_edges, args.out_summary, root, nodes, parent_by_child, children_by_parent, probs, params, sanity)


if __name__ == "__main__":
    main()
