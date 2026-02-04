#!/usr/bin/env python3
"""
augment_pp_edges.py

PO(relation) 그래프를 이용해 PP(process-process) 그래프를 densify 합니다.

핵심: shared-object time-ordered P->P
- 같은 object O를 접근한 (P,t) 목록을 시간순 정렬
- 각 P_i에 대해 뒤쪽의 top-k (P_{i+1}..P_{i+k})에만 P_i -> P_j 간선 추가
- dt_ns(시간차) 제한으로 edge 폭발 방지

옵션: rare-anchored
- 기존 PP에서 rare_support가 있는 프로세스만 anchor로 보고
- anchor가 포함된 pair에서만 간선 추가 (품질 유지)

입력 pkl 포맷 가정:
- obj["nodes"]: dict[nid -> {"type": ...}]
- obj["edges"]: dict[(src, dst) -> {"first_ts","last_ts", ...}]
"""

from __future__ import annotations

import argparse
import pickle
from collections import Counter, defaultdict
from typing import Any, Dict, Tuple, List, Optional, Set

SUBJECT_PROCESS = "SUBJECT_PROCESS"


def load_pkl(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


def save_pkl(obj, path: str):
    with open(path, "wb") as f:
        pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)


def is_process(nid: str, nodes: Dict[str, Dict[str, Any]]) -> bool:
    return nodes.get(nid, {}).get("type") == SUBJECT_PROCESS


def get_node_type(nid: str, nodes: Dict[str, Dict[str, Any]]) -> str:
    return nodes.get(nid, {}).get("type", "")


def build_object_to_proc_events(
    po_nodes: Dict[str, Dict[str, Any]],
    po_edges: Dict[Tuple[str, str], Dict[str, Any]],
    max_events_per_object: Optional[int] = None,
    use_first_ts: bool = True,
):
    """
    object_id -> list[(ts, proc_id, object_type)]
    """
    obj2events: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)

    for (u, v), attr in po_edges.items():
        # process->object 또는 object->process 모두 처리
        if is_process(u, po_nodes) and (not is_process(v, po_nodes)):
            proc, obj = u, v
        elif is_process(v, po_nodes) and (not is_process(u, po_nodes)):
            proc, obj = v, u
        else:
            continue

        ts = int(attr.get("first_ts" if use_first_ts else "last_ts", 0))
        if ts <= 0:
            continue
        obj_type = get_node_type(obj, po_nodes)
        obj2events[obj].append((ts, proc, obj_type))

    # 정렬 + (옵션) object당 이벤트 수 제한
    for obj, evs in obj2events.items():
        evs.sort(key=lambda x: x[0])
        if max_events_per_object is not None and len(evs) > max_events_per_object:
            # 너무 핫한 object는 초반/후반만 일부 샘플링(폭발 방지)
            half = max_events_per_object // 2
            obj2events[obj] = evs[:half] + evs[-(max_events_per_object - half):]

    return obj2events


def collect_rare_processes(pp_edges: Dict[Tuple[str, str], Dict[str, Any]]) -> Set[str]:
    rare_procs = set()
    for (u, v), attr in pp_edges.items():
        rs = attr.get("rare_support", {}) or {}
        if sum(rs.values()) > 0:
            rare_procs.add(u)
            rare_procs.add(v)
    return rare_procs


def add_or_update_pp_edge(
    pp_edges: Dict[Tuple[str, str], Dict[str, Any]],
    u: str,
    v: str,
    ts_u: int,
    ts_v: int,
    obj_type: str,
):
    key = (u, v)
    first_ts = min(ts_u, ts_v)
    last_ts = max(ts_u, ts_v)

    if key not in pp_edges:
        pp_edges[key] = {
            "cnt_total": 1,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "support_types": Counter({obj_type: 1}),
            "rare_support": Counter(),
            "cnt_common": Counter(),  # 여기서는 object-bridge 생성이라 이벤트 카운트는 비움
            "bridge_rule": "shared_object_time_ordered",
        }
    else:
        e = pp_edges[key]
        e["cnt_total"] = int(e.get("cnt_total", 0)) + 1
        e["first_ts"] = min(int(e.get("first_ts", first_ts)), first_ts)
        e["last_ts"] = max(int(e.get("last_ts", last_ts)), last_ts)
        st = e.get("support_types")
        if not isinstance(st, Counter):
            st = Counter(st or {})
        st[obj_type] += 1
        e["support_types"] = st


def densify_pp(
    po_path: str,
    pp_path: str,
    out_path: str,
    top_k: int,
    dt_ns: int,
    rare_anchored: bool,
    max_events_per_object: Optional[int],
):
    po = load_pkl(po_path)
    pp = load_pkl(pp_path)

    po_nodes = po["nodes"]
    po_edges = po["edges"]

    pp_nodes = pp["nodes"]
    pp_edges = pp["edges"]

    # rare anchor set (옵션)
    rare_procs = collect_rare_processes(pp_edges) if rare_anchored else None

    obj2events = build_object_to_proc_events(
        po_nodes, po_edges,
        max_events_per_object=max_events_per_object,
        use_first_ts=True,
    )

    added = 0
    skipped = 0

    for obj, evs in obj2events.items():
        # evs: [(ts, proc, obj_type)] sorted
        L = len(evs)
        if L < 2:
            continue

        for i in range(L - 1):
            ts_i, p_i, obj_type = evs[i]
            # 동일 프로세스 반복 이벤트는 스킵(연쇄만들기에서 noise)
            if not is_process(p_i, pp_nodes):
                continue

            # i 다음 top-k
            for j in range(i + 1, min(L, i + 1 + top_k)):
                ts_j, p_j, _obj_type2 = evs[j]
                if p_i == p_j:
                    continue
                if not is_process(p_j, pp_nodes):
                    continue

                # 시간차 제한
                if dt_ns is not None and (ts_j - ts_i) > dt_ns:
                    break  # 더 뒤는 더 커지니 조기 종료

                # rare anchored면 anchor 포함 pair만 허용
                if rare_procs is not None:
                    if (p_i not in rare_procs) and (p_j not in rare_procs):
                        skipped += 1
                        continue

                add_or_update_pp_edge(pp_edges, p_i, p_j, ts_i, ts_j, obj_type)
                added += 1

    # pp 객체 갱신 저장
    out = {
        "nodes": pp_nodes,  # process-only 유지
        "edges": pp_edges,
        "meta": {
            "source_pp": pp_path,
            "source_po": po_path,
            "rule": "shared_object_time_ordered",
            "top_k": top_k,
            "dt_ns": dt_ns,
            "rare_anchored": rare_anchored,
            "max_events_per_object": max_events_per_object,
            "added_pairs": added,
            "skipped_pairs": skipped,
        }
    }
    save_pkl(out, out_path)

    print("[OK] wrote:", out_path)
    print("[STAT] original_pp_edges:", len(pp["edges"]))
    print("[STAT] new_pp_edges:", len(out["edges"]))
    print("[STAT] added_pairs (updates+new):", added, "skipped:", skipped)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--po", required=True, help="agg_relation_graph_*.pkl (process-object)")
    ap.add_argument("--pp", required=True, help="agg_process_graph_*.pkl (process-process)")
    ap.add_argument("--out", required=True, help="output augmented PP pickle path")
    ap.add_argument("--top-k", type=int, default=3, help="per event, connect to next k processes")
    ap.add_argument("--dt-ns", type=int, default=1_000_000_000, help="time window ns (default 1s)")
    ap.add_argument("--rare-anchored", action="store_true", help="only connect pairs where at least one proc is rare")
    ap.add_argument("--max-events-per-object", type=int, default=200, help="cap events per object to avoid blow-up")
    args = ap.parse_args()

    densify_pp(
        po_path=args.po,
        pp_path=args.pp,
        out_path=args.out,
        top_k=max(1, args.top_k),
        dt_ns=args.dt_ns,
        rare_anchored=args.rare_anchored,
        max_events_per_object=args.max_events_per_object,
    )


if __name__ == "__main__":
    main()
