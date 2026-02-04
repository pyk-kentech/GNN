#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import math
import pickle
from collections import defaultdict

# ===== 설정 =====
DATA_DIR = "../data/trace"
TXT_DIR  = os.path.join(DATA_DIR, "02_txt")
OUT_DIR  = os.path.join(DATA_DIR, "05_outputs")

BASE = "ta1-trace-e3-official-1.json"
PARTS = [0, 1, 2, 3, 4]   # ★ B안: 0~4 통합 ★

OUT_FILE = os.path.join(OUT_DIR, "agg_relation_graph_p0_4.pkl")

COMMON_EVENTS = {
    "EVENT_READ",
    "EVENT_WRITE",
    "EVENT_OPEN",
    "EVENT_CLOSE",
    "EVENT_RECVMSG",
    "EVENT_SENDMSG",
}

RARE_EVENTS = {
    "EVENT_EXECUTE",
    "EVENT_CONNECT",
    "EVENT_ACCEPT",
    "EVENT_FORK",
    "EVENT_CLONE",
    "EVENT_UNLINK",
    "EVENT_RENAME",
    "EVENT_CREATE_OBJECT",
    "EVENT_TRUNCATE",
    "EVENT_LOADLIBRARY",
    "EVENT_CHANGE_PRINCIPAL",
    "EVENT_MPROTECT",
}

# ===== txt line iterator =====
def iter_txt(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            sp = line.rstrip("\n").split("\t")
            if len(sp) < 6:
                continue
            u, utype, v, vtype, etype, ts = sp
            try:
                ts = int(ts)
            except:
                continue
            yield u, utype, v, vtype, etype, ts


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    txt_files = []
    for p in PARTS:
        if p == 0:
            fn = f"{BASE}.txt"
        else:
            fn = f"{BASE}.{p}.txt"
        path = os.path.join(TXT_DIR, fn)
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        txt_files.append(path)

    nodes = {}  # uuid -> {type}
    edges = {}  # (u,v) -> stats

    def get_edge(u, v):
        if (u, v) not in edges:
            edges[(u, v)] = {
                "cnt_total": 0,
                "cnt_common": {e: 0 for e in COMMON_EVENTS},
                "cnt_other": 0,
                "cnt_rare_total": 0,
                "rare_flags": {e: False for e in RARE_EVENTS},
                "first_ts": None,
                "last_ts": None,
            }
        return edges[(u, v)]

    total = 0
    for txt in txt_files:
        print(f"[READ] {txt}")
        for u, utype, v, vtype, etype, ts in iter_txt(txt):
            if u not in nodes:
                nodes[u] = {"type": utype}
            if v not in nodes:
                nodes[v] = {"type": vtype}

            st = get_edge(u, v)
            st["cnt_total"] += 1

            if etype in COMMON_EVENTS:
                st["cnt_common"][etype] += 1
            else:
                st["cnt_other"] += 1

            if etype in RARE_EVENTS:
                st["cnt_rare_total"] += 1
                st["rare_flags"][etype] = True

            st["first_ts"] = ts if st["first_ts"] is None else min(st["first_ts"], ts)
            st["last_ts"]  = ts if st["last_ts"]  is None else max(st["last_ts"], ts)

            total += 1
            if total % 1_000_000 == 0:
                print(f"  processed {total:,}")

    # ===== weight 계산 (spanning tree용) =====
    last_ts_all = [st["last_ts"] for st in edges.values()]
    t_min, t_max = min(last_ts_all), max(last_ts_all)
    den = (t_max - t_min) if t_max > t_min else 1

    for st in edges.values():
        recency = (st["last_ts"] - t_min) / den
        has_rare = any(st["rare_flags"].values())
        st["weight"] = (
            (10.0 if has_rare else 0.0)
            + math.log1p(st["cnt_total"])
            + 0.5 * recency
        )

    obj = {
        "meta": {
            "base": BASE,
            "parts": PARTS,
            "common_events": sorted(COMMON_EVENTS),
            "rare_events": sorted(RARE_EVENTS),
        },
        "nodes": nodes,
        "edges": edges,
    }

    with open(OUT_FILE, "wb") as f:
        pickle.dump(obj, f)

    print("[DONE]")
    print(" nodes:", len(nodes))
    print(" edges:", len(edges))
    print(" saved:", OUT_FILE)


if __name__ == "__main__":
    main()
