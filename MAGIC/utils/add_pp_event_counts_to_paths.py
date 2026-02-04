#!/usr/bin/env python3
import argparse
import pickle
from collections import Counter
import pandas as pd

def norm_counter(x):
    # pkl에서 Counter가 그대로 들어있거나 dict일 수 있음
    if x is None:
        return {}
    if isinstance(x, Counter):
        return dict(x)
    if isinstance(x, dict):
        return x
    return {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paths-csv", required=True)
    ap.add_argument("--pp-pkl", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--max-nodes", type=int, default=200)
    args = ap.parse_args()

    df = pd.read_csv(args.paths_csv)
    if "path" not in df.columns:
        raise SystemExit("ERROR: input csv has no 'path' column")

    obj = pickle.load(open(args.pp_pkl, "rb"))
    pp_edges = obj["edges"]

    # 관심 이벤트 (CDM 이벤트명 기준)
    E_EXEC = "EVENT_EXECUTE"
    E_PRIV = "EVENT_CHANGE_PRINCIPAL"
    E_CONN = "EVENT_CONNECT"

    out_exec_c = []
    out_priv_c = []
    out_conn_c = []
    out_exec_r = []
    out_priv_r = []
    out_conn_r = []
    out_rare_total = []
    out_cnt_total_sum = []

    for path_str in df["path"].astype(str).tolist():
        uuids = [u.strip().upper() for u in path_str.split("->") if u.strip()]
        uuids = uuids[:args.max_nodes]

        exec_c = priv_c = conn_c = 0
        exec_r = priv_r = conn_r = 0
        rare_total = 0
        cnt_total_sum = 0

        for u, v in zip(uuids[:-1], uuids[1:]):
            attr = pp_edges.get((u, v))
            if not attr:
                # pp-graph에 없는 간선이면 그냥 스킵 (경로는 DAG 기반이라 일부 mismatch 가능)
                continue

            cc = norm_counter(attr.get("cnt_common"))
            rs = norm_counter(attr.get("rare_support"))

            exec_c += int(cc.get(E_EXEC, 0))
            priv_c += int(cc.get(E_PRIV, 0))
            conn_c += int(cc.get(E_CONN, 0))

            exec_r += int(rs.get(E_EXEC, 0))
            priv_r += int(rs.get(E_PRIV, 0))
            conn_r += int(rs.get(E_CONN, 0))

            rare_total += int(sum(rs.values()))
            cnt_total_sum += int(attr.get("cnt_total", 0) or 0)

        out_exec_c.append(exec_c)
        out_priv_c.append(priv_c)
        out_conn_c.append(conn_c)
        out_exec_r.append(exec_r)
        out_priv_r.append(priv_r)
        out_conn_r.append(conn_r)
        out_rare_total.append(rare_total)
        out_cnt_total_sum.append(cnt_total_sum)

    df["pp_exec_common"] = out_exec_c
    df["pp_priv_common"] = out_priv_c
    df["pp_connect_common"] = out_conn_c
    df["pp_exec_rare"] = out_exec_r
    df["pp_priv_rare"] = out_priv_r
    df["pp_connect_rare"] = out_conn_r
    df["pp_rare_total"] = out_rare_total
    df["pp_cnt_total_sum"] = out_cnt_total_sum

    df.to_csv(args.out_csv, index=False)
    print("[OK] wrote", args.out_csv)
    print("[INFO] added cols: pp_exec_common, pp_priv_common, pp_connect_common, pp_exec_rare, pp_priv_rare, pp_connect_rare, pp_rare_total, pp_cnt_total_sum")

if __name__ == "__main__":
    main()
