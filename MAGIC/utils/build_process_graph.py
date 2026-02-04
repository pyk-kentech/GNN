#!/usr/bin/env python3
"""
Build a derived PROCESS->PROCESS graph from an aggregated provenance graph
that mostly has PROCESS->OBJECT edges.

Input pickle format:
  obj["nodes"]: dict[nid -> {"type": ...}]
  obj["edges"]: dict[(src, dst) -> attr], attr contains:
      - cnt_common: dict[str,int]
      - rare_flags: dict[str,bool]
      - first_ts, last_ts: int
      - weight: float (optional)

Output pickle format (same style):
  out["nodes"]: only SUBJECT_PROCESS nodes (copied from input)
  out["edges"]: dict[(p1, p2) -> aggregated attr], where:
      - cnt_total: number of supporting object-links
      - last_ts: max supporting last_ts
      - first_ts: min supporting first_ts
      - support_objects: (optional) not stored by default to save memory
      - support_types: counts by object type
      - rare_support: counts of rare flags seen in supporting edges

Design:
  For each object O, collect incident processes with their timestamps.
  Then create directed edges between temporally ordered processes.

Important scaling notes:
  - We DO NOT store full process lists for all objects at once.
    We build object->list in streaming, but still requires memory.
  - Filter objects by type and/or maximum degree to prevent explosion.
"""

from __future__ import annotations

import argparse
import pickle
from collections import defaultdict, Counter
from typing import Any, Dict, Tuple, List, Optional


SUBJECT_PROCESS = "SUBJECT_PROCESS"

# object types worth using for mediation (tune as you like)
DEFAULT_OBJECT_ALLOW_PREFIXES = ("OBJECT_FILELIKE", "OBJECT_MIXED", "FILE_OBJECT_")

# events that we treat as "important"
IMPORTANT_RARE = {
    "EVENT_EXECUTE",
    "EVENT_FORK",
    "EVENT_CLONE",
    "EVENT_CONNECT",
    "EVENT_LOADLIBRARY",
    "EVENT_CHANGE_PRINCIPAL",
}


def load_graph(path: str):
    with open(path, "rb") as f:
        obj = pickle.load(f)
    return obj["nodes"], obj["edges"]


def is_process(nid: str, nodes: Dict[str, Dict[str, Any]]) -> bool:
    return nodes.get(nid, {}).get("type") == SUBJECT_PROCESS


def object_ok(obj_id: str, nodes: Dict[str, Dict[str, Any]], allow_prefixes: Tuple[str, ...]) -> bool:
    t = nodes.get(obj_id, {}).get("type", "")
    return any(t.startswith(p) for p in allow_prefixes)


def has_any_important_rare(attr: Dict[str, Any]) -> bool:
    rf = attr.get("rare_flags", {}) or {}
    for k in IMPORTANT_RARE:
        if rf.get(k):
            return True
    return False


def merge_pp_attr(dst: Dict[str, Any], src_attr: Dict[str, Any], obj_type: str):
    # dst: aggregated PROCESS->PROCESS edge attr
    # src_attr: original PROCESS->OBJECT edge attr that supports this link
    dst["cnt_total"] += 1

    f = int(src_attr.get("first_ts", 0))
    l = int(src_attr.get("last_ts", 0))
    dst["first_ts"] = f if dst["first_ts"] == 0 else min(dst["first_ts"], f)
    dst["last_ts"] = max(dst["last_ts"], l)

    # summarize supporting object types
    dst["support_types"][obj_type] += 1

    # propagate rare signals
    rf = src_attr.get("rare_flags", {}) or {}
    for ev, flag in rf.items():
        if flag:
            dst["rare_support"][ev] += 1

    # count common events too (optional)
    cc = src_attr.get("cnt_common", {}) or {}
    for ev, c in cc.items():
        if c:
            dst["cnt_common"][ev] += int(c)


def build_process_graph(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[Tuple[str, str], Dict[str, Any]],
    allow_prefixes: Tuple[str, ...],
    require_rare: bool,
    max_obj_degree: int,
    max_pairs_per_object: int,
):
    """
    Steps:
      1) Build object -> list of (process, last_ts, first_ts, attr)
         only for edges process->object and object passes filters.
      2) For each object, sort by time and create directed pairs.
    """

    # object -> list[(proc, last_ts, first_ts, attr)]
    obj_inc: Dict[str, List[Tuple[str, int, int, Dict[str, Any]]]] = defaultdict(list)

    scanned = 0
    kept_edges = 0

    for (u, v), attr in edges.items():
        scanned += 1
        if not is_process(u, nodes):
            continue
        if not object_ok(v, nodes, allow_prefixes):
            continue
        if require_rare and not has_any_important_rare(attr):
            continue

        f = int(attr.get("first_ts", 0))
        l = int(attr.get("last_ts", 0))
        obj_inc[v].append((u, l, f, attr))
        kept_edges += 1

    print(f"[STAGE1] scanned edges={scanned:,}, kept proc->obj edges={kept_edges:,}, objects={len(obj_inc):,}")

    # output graph: process nodes only
    out_nodes = {nid: nodes[nid] for nid in nodes if nodes[nid].get("type") == SUBJECT_PROCESS}

    pp_edges: Dict[Tuple[str, str], Dict[str, Any]] = {}

    skipped_hub_objects = 0
    total_pairs = 0

    for obj_id, lst in obj_inc.items():
        if len(lst) < 2:
            continue
        if max_obj_degree > 0 and len(lst) > max_obj_degree:
            skipped_hub_objects += 1
            continue

        obj_type = nodes.get(obj_id, {}).get("type", "")

        # sort by last_ts (time order)
        lst.sort(key=lambda x: x[1])

        # build pairs (i<j => pi -> pj)
        # to avoid O(k^2) blow-up, cap pairs per object
        pairs_here = 0
        k = len(lst)
        for i in range(k - 1):
            pi, li, fi, attr_i = lst[i]
            for j in range(i + 1, k):
                pj, lj, fj, attr_j = lst[j]
                if pi == pj:
                    continue

                key = (pi, pj)
                if key not in pp_edges:
                    pp_edges[key] = {
                        "cnt_total": 0,
                        "first_ts": 0,
                        "last_ts": 0,
                        "support_types": Counter(),
                        "rare_support": Counter(),
                        "cnt_common": Counter(),
                    }

                # support by the *later* interaction edge is often more meaningful,
                # but we can merge both sides; here we merge the later one (j)
                merge_pp_attr(pp_edges[key], attr_j, obj_type)

                pairs_here += 1
                total_pairs += 1
                if max_pairs_per_object > 0 and pairs_here >= max_pairs_per_object:
                    break
            if max_pairs_per_object > 0 and pairs_here >= max_pairs_per_object:
                break

    print(f"[STAGE2] pp_edges={len(pp_edges):,}, total_pairs_added={total_pairs:,}, skipped_hub_objects={skipped_hub_objects:,}")

    out = {
        "nodes": out_nodes,
        "edges": pp_edges,
        "meta": {
            "allow_prefixes": allow_prefixes,
            "require_rare": require_rare,
            "max_obj_degree": max_obj_degree,
            "max_pairs_per_object": max_pairs_per_object,
        }
    }
    return out


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", required=True, help="input aggregated graph pickle")
    ap.add_argument("--out", required=True, help="output process graph pickle")
    ap.add_argument("--allow-prefixes", default="OBJECT_FILELIKE,OBJECT_MIXED,FILE_OBJECT_",
                    help="comma-separated prefixes allowed for mediator objects")
    ap.add_argument("--require-rare", action="store_true", help="only use proc->obj edges that have important rare flags")
    ap.add_argument("--max-obj-degree", type=int, default=50, help="skip objects touched by > this many processes (0=disable)")
    ap.add_argument("--max-pairs-per-object", type=int, default=500, help="cap number of pp pairs generated per object (0=disable)")
    return ap.parse_args()


def main():
    args = parse_args()
    allow_prefixes = tuple([s.strip() for s in args.allow_prefixes.split(",") if s.strip()])

    nodes, edges = load_graph(args.inp)
    out = build_process_graph(
        nodes, edges,
        allow_prefixes=allow_prefixes,
        require_rare=args.require_rare,
        max_obj_degree=args.max_obj_degree,
        max_pairs_per_object=args.max_pairs_per_object,
    )
    with open(args.out, "wb") as f:
        pickle.dump(out, f, protocol=pickle.HIGHEST_PROTOCOL)

    print(f"[SAVE] {args.out}")
    print(f"[DONE] process nodes={len(out['nodes']):,}, process edges={len(out['edges']):,}")


if __name__ == "__main__":
    main()
