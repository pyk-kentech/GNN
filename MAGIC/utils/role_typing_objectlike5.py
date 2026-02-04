#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Retype SRCSINK_UNKNOWN object nodes into 5 classes:
- OBJECT_NETLIKE
- OBJECT_FILELIKE
- OBJECT_MIXED_FILEDOM  (file-dominant + small net evidence)
- OBJECT_MIXED_NETDOM   (net-dominant  + small file evidence)
- OBJECT_OTHERLIKE

✅ Fix vs previous version:
- For BOTH(net>0 & file>0), we check MIXED first (transition signal),
  then apply dominance (NETLIKE/FILELIKE), then OTHER.
- ONLY_NET / ONLY_FILE are handled explicitly first (no ratio needed).

Input pkl schema (your case):
obj["nodes"] : dict[node_id] -> dict, must contain "type"
obj["edges"] : dict[(src_id, dst_id)] -> dict with:
  - cnt_common: dict[event_name] -> int
  - rare_flags: dict[event_name] -> bool
"""

import argparse
import pickle
from collections import Counter

NET_COMMON = {"EVENT_RECVMSG", "EVENT_SENDMSG"}
FILE_COMMON = {"EVENT_READ", "EVENT_WRITE", "EVENT_OPEN", "EVENT_CLOSE"}

NET_RARE = {"EVENT_CONNECT", "EVENT_ACCEPT"}
FILE_RARE = {
    "EVENT_UNLINK",
    "EVENT_CREATE_OBJECT",
    "EVENT_TRUNCATE",
    "EVENT_RENAME",
    "EVENT_LOADLIBRARY",
}


def score_edge_attr(attr: dict, rare_weight: int = 3):
    cnt_common = attr.get("cnt_common", {}) or {}
    rare_flags = attr.get("rare_flags", {}) or {}

    net = 0
    fil = 0

    for ev, c in cnt_common.items():
        if not c:
            continue
        if ev in NET_COMMON:
            net += c
        elif ev in FILE_COMMON:
            fil += c

    for ev, flag in rare_flags.items():
        if not flag:
            continue
        if ev in NET_RARE:
            net += rare_weight
        elif ev in FILE_RARE:
            fil += rare_weight

    return net, fil


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--unknown_type", default="SRCSINK_UNKNOWN")

    ap.add_argument("--net_label", default="OBJECT_NETLIKE")
    ap.add_argument("--file_label", default="OBJECT_FILELIKE")
    ap.add_argument("--mixed_filedom_label", default="OBJECT_MIXED_FILEDOM")
    ap.add_argument("--mixed_netdom_label", default="OBJECT_MIXED_NETDOM")
    ap.add_argument("--other_label", default="OBJECT_OTHERLIKE")

    # dominance (applied AFTER mixed for BOTH)
    ap.add_argument("--dom_ratio", type=float, default=1.2)
    ap.add_argument("--dom_min", type=int, default=10)

    # mixed transition signal (applied FIRST for BOTH)
    ap.add_argument("--mix_small", type=int, default=1)
    ap.add_argument("--mix_big", type=int, default=10)  # ✅ default=10 (as agreed)

    ap.add_argument("--min_total", type=int, default=1)
    ap.add_argument("--rare_weight", type=int, default=3)
    ap.add_argument("--log_every", type=int, default=1_000_000)
    args = ap.parse_args()

    print("[LOAD]", args.inp)
    obj = pickle.load(open(args.inp, "rb"))
    nodes = obj["nodes"]
    edges = obj["edges"]

    unk = [nid for nid, v in nodes.items() if v.get("type") == args.unknown_type]
    unk_set = set(unk)

    print("total nodes:", len(nodes))
    print("total edges:", len(edges))
    print("unknown nodes:", len(unk))

    net = Counter()
    fil = Counter()

    scanned = 0
    for (u, v), attr in edges.items():
        scanned += 1
        if args.log_every and scanned % args.log_every == 0:
            print(f"  scanned edges: {scanned:,}")
        if v in unk_set:
            n, f = score_edge_attr(attr, rare_weight=args.rare_weight)
            net[v] += n
            fil[v] += f

    print("[STATS DONE] scanned edges:", scanned)

    changed = 0
    dist = Counter()
    debug = Counter()

    for nid in unk:
        n = net[nid]
        f = fil[nid]
        total = n + f

        if total < args.min_total:
            new_t = args.other_label
            debug["other_low_total"] += 1

        # single-side evidence
        elif n > 0 and f == 0:
            new_t = args.net_label
            debug["only_net"] += 1
        elif f > 0 and n == 0:
            new_t = args.file_label
            debug["only_file"] += 1

        else:
            # BOTH: ✅ MIXED first
            if f >= args.mix_big and n >= args.mix_small:
                new_t = args.mixed_filedom_label
                debug["mixed_filedom"] += 1
            elif n >= args.mix_big and f >= args.mix_small:
                new_t = args.mixed_netdom_label
                debug["mixed_netdom"] += 1
            else:
                # then dominance
                if n >= f * args.dom_ratio and n >= args.dom_min:
                    new_t = args.net_label
                    debug["net_dom"] += 1
                elif f >= n * args.dom_ratio and f >= args.dom_min:
                    new_t = args.file_label
                    debug["file_dom"] += 1
                else:
                    new_t = args.other_label
                    debug["other_ambiguous"] += 1

        if nodes[nid].get("type") != new_t:
            nodes[nid]["type"] = new_t
            changed += 1
        dist[new_t] += 1

    print("[ROLE ASSIGN DONE] changed:", changed)
    print("role distribution:")
    for k, v in dist.most_common():
        print(f"  {k:24s} {v}")

    print("debug counts:")
    for k, v in debug.most_common():
        print(f"  {k:24s} {v}")

    print("[SAVE]", args.out)
    pickle.dump(obj, open(args.out, "wb"))
    print("[DONE]")


if __name__ == "__main__":
    main()
