#!/usr/bin/env python3
"""
build_attack_subgraph.py

목표:
- aggregated PP 그래프에서 "의미 있는" attack-context subgraph(트리/약한 DAG)를 추출
- 단순 depth-BFS 대신:
  - node budget (예: 200노드)
  - best-first expansion (가중치 큰 간선부터)
  - beam-width (부모별 상위 B개 후보만)
  - keep-parents (child당 top-k 부모 허용; k=1이면 트리)

중요:
- 여기서의 weight/prob는 '공격 확률'이 아니라 '탐색 휴리스틱'입니다.
"""

from __future__ import annotations

import argparse
import json
import math
import heapq
import pickle
from dataclasses import dataclass
from collections import Counter, defaultdict
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
    parent_type: str
    child_type: str
    first_ts: int
    last_ts: int
    weight: float
    # 원자 feature들도 같이 남겨두면 "정보량"이 늘어납니다(나중에 학습으로 넘기기 쉬움)
    feat_total_events: float
    feat_time_score: float
    feat_rare_score: float


def load_graph(path: str) -> Tuple[Dict[str, Dict[str, Any]], Dict[Tuple[str, str], Dict[str, Any]]]:
    obj = pickle.load(open(path, "rb"))
    return obj["nodes"], obj["edges"]


def is_subject(nid: str, nodes: Dict[str, Dict[str, Any]]) -> bool:
    return nodes.get(nid, {}).get("type") == SUBJECT_PROCESS


def build_out_index(edges: Dict[Tuple[str, str], Dict[str, Any]]) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
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

        first_ts = int(attr.get("first_ts", 0))
        rf = attr.get("rare_flags", {}) or {}
        rs = attr.get("rare_support", {}) or {}
        is_rare = any(rf.values()) or (sum(rs.values()) > 0)
        if is_rare:
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
        return min(cand, key=lambda n: earliest_rare_ts[n]) if cand else None

    raise ValueError(strategy)


def compute_global_time_window(edges: Dict[Tuple[str, str], Dict[str, Any]]) -> Tuple[int, int]:
    min_ts = None
    max_ts = None
    for attr in edges.values():
        f = int(attr.get("first_ts", 0))
        l = int(attr.get("last_ts", 0))
        min_ts = f if min_ts is None else min(min_ts, f)
        max_ts = l if max_ts is None else max(max_ts, l)
    return (min_ts or 0, max_ts or 0)


def edge_features(attr: Dict[str, Any], min_ts: int, max_ts: int) -> Tuple[float, float, float]:
    # 1) total events
    cc = attr.get("cnt_common", {}) or {}
    total_cnt = sum(int(x) for x in cc.values() if x)
    f_total = math.log1p(total_cnt)

    # 2) time score (global window 기준)
    last_ts = int(attr.get("last_ts", 0))
    f_time = (last_ts - min_ts) / (max_ts - min_ts) if max_ts > min_ts else 0.0

    # 3) rare score
    rf = attr.get("rare_flags", {}) or {}
    rs = attr.get("rare_support", {}) or {}
    f_rare = 0.0
    if rf:
        for ev, is_rare in rf.items():
            if is_rare:
                f_rare += IMPORTANT_RARE_EVENTS.get(ev, 1.0)
    else:
        for ev, cnt in rs.items():
            f_rare += float(cnt) * IMPORTANT_RARE_EVENTS.get(ev, 1.0)

    return f_total, f_time, f_rare


def edge_weight_from_feats(f_total: float, f_time: float, f_rare: float, a: float, b: float, c: float) -> float:
    return a * f_total + b * f_time + c * f_rare


def keep_topk(existing: List[EdgeInfo], cand: EdgeInfo, k: int) -> List[EdgeInfo]:
    """
    child별로 parent 후보를 top-k 유지.
    우선순위: last_ts desc, weight desc
    """
    xs = existing + [cand]
    xs.sort(key=lambda e: (e.last_ts, e.weight), reverse=True)
    # 같은 parent 중복 제거(최고 하나만)
    seen = set()
    out = []
    for e in xs:
        if e.parent in seen:
            continue
        seen.add(e.parent)
        out.append(e)
        if len(out) >= k:
            break
    return out


def build_subgraph(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[Tuple[str, str], Dict[str, Any]],
    root: str,
    max_depth: int,
    node_budget: int,
    beam_width: int,
    keep_parents: int,
    time_window_ns: Optional[int],
    a: float,
    b: float,
    c: float,
):
    out_adj = build_out_index(edges)
    gmin, gmax = compute_global_time_window(edges)
    if time_window_ns is not None and gmax > gmin:
        gmax = min(gmax, gmin + time_window_ns)

    # child -> list[EdgeInfo] (top-k parents)
    parents_by_child: Dict[str, List[EdgeInfo]] = defaultdict(list)

    # depth tracking (최단 depth 기반)
    depth = {root: 0}

    # best-first 후보 간선 heap: (-weight, parent, child, EdgeInfo)
    heap: List[Tuple[float, str, str, EdgeInfo]] = []

    def push_candidates(u: str):
        """u의 outgoing 중 상위 beam_width개만 heap에 넣음"""
        if u not in out_adj:
            return
        cand_list = []
        for v, attr in out_adj[u]:
            f = int(attr.get("first_ts", 0))
            if time_window_ns is not None and f > gmax:
                continue
            # depth 제한: u의 자식은 depth[u]+1
            du = depth.get(u, 0)
            if du + 1 > max_depth:
                continue

            ft, ftime, fr = edge_features(attr, gmin, gmax)
            w = edge_weight_from_feats(ft, ftime, fr, a, b, c)
            ei = EdgeInfo(
                parent=u,
                child=v,
                parent_type=nodes.get(u, {}).get("type", ""),
                child_type=nodes.get(v, {}).get("type", ""),
                first_ts=int(attr.get("first_ts", 0)),
                last_ts=int(attr.get("last_ts", 0)),
                weight=w,
                feat_total_events=ft,
                feat_time_score=ftime,
                feat_rare_score=fr,
            )
            cand_list.append(ei)

        cand_list.sort(key=lambda e: e.weight, reverse=True)
        for ei in cand_list[:beam_width]:
            heapq.heappush(heap, (-ei.weight, ei.parent, ei.child, ei))

    # 시작: root의 후보를 넣고 시작
    push_candidates(root)

    selected_nodes = set([root])

    # budget 채울 때까지 best-first로 간선 선택
    while heap and len(selected_nodes) < node_budget:
        _nw, u, v, ei = heapq.heappop(heap)

        # depth 갱신
        du = depth.get(u, None)
        if du is None:
            continue
        dv = du + 1
        if dv > max_depth:
            continue

        # (1) 새로운 노드 추가가 우선: v가 아직 없으면 추가
        is_new = v not in selected_nodes
        if is_new:
            selected_nodes.add(v)
            depth[v] = min(depth.get(v, dv), dv)

        # (2) parent 후보 top-k 유지 (v가 이미 있어도 DAG용으로 넣을 수 있음)
        parents_by_child[v] = keep_topk(parents_by_child[v], ei, keep_parents)

        # (3) 새 subject 노드면 확장 후보 추가
        # PP 그래프면 보통 v도 SUBJECT_PROCESS지만, 안전하게 체크
        if is_new and is_subject(v, nodes):
            push_candidates(v)

    # 선택된 간선 집합 구성
    selected_edges: List[EdgeInfo] = []
    for ch, plist in parents_by_child.items():
        for e in plist:
            if e.parent in selected_nodes and e.child in selected_nodes and e.child != root:
                selected_edges.append(e)

    # parent -> children (선택된 간선 기준)
    children_by_parent: Dict[str, List[EdgeInfo]] = defaultdict(list)
    for e in selected_edges:
        children_by_parent[e.parent].append(e)

    # 확률(softmax)은 '해석용 확률'이 아니라 parent 내부 상대 선호도
    probs: Dict[Tuple[str, str], float] = {}
    for p, elist in children_by_parent.items():
        ws = [e.weight for e in elist]
        m = max(ws) if ws else 0.0
        exps = [math.exp(w - m) for w in ws]
        denom = sum(exps)
        for e, s in zip(elist, exps):
            probs[(e.parent, e.child)] = (s / denom) if denom else 0.0

    summary = {
        "root": root,
        "root_type": nodes.get(root, {}).get("type", ""),
        "num_nodes": len(selected_nodes),
        "num_edges": len(selected_edges),
        "max_depth_used": max(depth.values()) if depth else 0,
        "parameters": {
            "max_depth": max_depth,
            "node_budget": node_budget,
            "beam_width": beam_width,
            "keep_parents": keep_parents,
            "time_window_ns": time_window_ns,
            "weight_a": a, "weight_b": b, "weight_c": c,
        },
        "node_type_dist": dict(Counter(nodes.get(n, {}).get("type", "") for n in selected_nodes)),
    }
    return selected_nodes, selected_edges, probs, summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pickle_path")
    ap.add_argument("--root-strategy", choices=["out_degree", "total_events", "earliest_rare"], default="earliest_rare")
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--node-budget", type=int, default=200)
    ap.add_argument("--beam-width", type=int, default=20)
    ap.add_argument("--keep-parents", type=int, default=1)  # 1이면 트리, 2 이상이면 약한 DAG
    ap.add_argument("--time-window-ns", type=int, default=None)
    ap.add_argument("--weight-a", type=float, default=1.0)
    ap.add_argument("--weight-b", type=float, default=2.0)
    ap.add_argument("--weight-c", type=float, default=2.5)
    ap.add_argument("--out-edges", default="attack_subgraph_edges.jsonl")
    ap.add_argument("--out-summary", default="attack_subgraph_summary.json")
    args = ap.parse_args()

    nodes, edges = load_graph(args.pickle_path)
    root = select_root(nodes, edges, args.root_strategy)
    if root is None:
        raise SystemExit("No SUBJECT_PROCESS root found.")

    sel_nodes, sel_edges, probs, summary = build_subgraph(
        nodes, edges, root,
        max_depth=args.max_depth,
        node_budget=args.node_budget,
        beam_width=args.beam_width,
        keep_parents=max(1, args.keep_parents),
        time_window_ns=args.time_window_ns,
        a=args.weight_a, b=args.weight_b, c=args.weight_c,
    )

    with open(args.out_edges, "w", encoding="utf-8") as f:
        for e in sel_edges:
            f.write(json.dumps({
                "parent": e.parent,
                "parent_type": e.parent_type,
                "child": e.child,
                "child_type": e.child_type,
                "first_ts": e.first_ts,
                "last_ts": e.last_ts,
                "weight": e.weight,
                "probability": probs.get((e.parent, e.child), 0.0),
                "features": {
                    "log1p_total_events": e.feat_total_events,
                    "time_score": e.feat_time_score,
                    "rare_score": e.feat_rare_score,
                }
            }) + "\n")

    with open(args.out_summary, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("[OK] root:", root)
    print("[OK] nodes:", summary["num_nodes"], "edges:", summary["num_edges"], "max_depth_used:", summary["max_depth_used"])
    print("[OUT]", args.out_edges)
    print("[OUT]", args.out_summary)


if __name__ == "__main__":
    main()
