#!/usr/bin/env python3
import argparse
import ast
import pandas as pd

def norm_cmd(x: str) -> str:
    if not isinstance(x, str) or not x:
        return ""
    s = x.strip()
    if s.startswith("{") and "string" in s:
        try:
            obj = ast.literal_eval(s)
            if isinstance(obj, dict) and "string" in obj and isinstance(obj["string"], str):
                return obj["string"].strip()
        except Exception:
            pass
    return s

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--paths-csv", required=True)
    ap.add_argument("--proc-map-csv", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--max-nodes", type=int, default=50)
    args=ap.parse_args()

    df=pd.read_csv(args.paths_csv)
    mp=pd.read_csv(args.proc_map_csv)

    #m=dict(zip(mp["proc_uuid"].astype(str).str.upper(), mp["cmdLine"].fillna("").astype(str)))
    mp["cmdLine"] = mp["cmdLine"].fillna("").astype(str).map(norm_cmd)
    m = dict(zip(mp["proc_uuid"].astype(str).str.upper(), mp["cmdLine"]))


    def concat_cmd(path_str):
        if not isinstance(path_str, str):
            return ""
        uuids=[u.strip().upper() for u in path_str.split("->") if u.strip()]
        uuids=uuids[:args.max_nodes]
        cmds=[m.get(u,"") for u in uuids]
        cmds=[c for c in cmds if c]
        return " || ".join(cmds)

    if "path" not in df.columns:
        raise SystemExit("ERROR: paths csv has no 'path' column")

    df["path_cmdline_concat"]=df["path"].apply(concat_cmd)
    df.to_csv(args.out_csv, index=False)
    print("[OK] wrote", args.out_csv)

if __name__=="__main__":
    main()
