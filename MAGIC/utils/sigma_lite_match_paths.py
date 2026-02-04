#!/usr/bin/env python3
import argparse, os, yaml, re
import pandas as pd

def load_rules(sigma_dir):
    rules=[]
    for root,_,files in os.walk(sigma_dir):
        for fn in files:
            if not (fn.endswith(".yml") or fn.endswith(".yaml")):
                continue
            path=os.path.join(root, fn)
            try:
                data=yaml.safe_load(open(path, encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            det=data.get("detection", {})
            rules.append({
                "path": path,
                "id": data.get("id") or data.get("title") or fn,
                "title": data.get("title",""),
                "tags": data.get("tags", []) or [],
                "detection": det,
            })
    return rules

def extract_needles(det):
    # selection* 블록에서 문자열/리스트 문자열을 최대한 긁어오기
    needles=[]
    if not isinstance(det, dict):
        return needles
    for k,v in det.items():
        if not str(k).lower().startswith("selection"):
            continue
        if isinstance(v, dict):
            for kk, vv in v.items():
                # 연산자 포함 키: CommandLine|contains, Image|endswith 등
                if isinstance(vv, str):
                    needles.append((kk, vv))
                elif isinstance(vv, list):
                    for x in vv:
                        if isinstance(x, str):
                            needles.append((kk, x))
        # selection이 list인 케이스는 거의 없지만 방어
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    needles.append((str(k), item))
    return needles

def match_one(field_op, pat, text):
    op=str(field_op).lower()
    p=str(pat)
    t=text
    if "|re" in op or op.endswith("|regex"):
        try:
            return re.search(p, t) is not None
        except re.error:
            return False
    # endswith
    if "|endswith" in op:
        return t.endswith(p.lower())
    # contains (default)
    return p.lower() in t

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--paths-csv", required=True)
    ap.add_argument("--sigma-dir", required=True)
    ap.add_argument("--text-col", default="path_cmdline_concat")
    ap.add_argument("--out-csv", required=True)
    args=ap.parse_args()

    df=pd.read_csv(args.paths_csv)
    rules=load_rules(args.sigma_dir)
    print("[INFO] rules loaded:", len(rules))

    # pre-extract needles
    compiled=[]
    for r in rules:
        nd=extract_needles(r["detection"])
        if not nd:
            continue
        compiled.append((r["id"], r["tags"], nd))
    print("[INFO] rules with selection needles:", len(compiled))

    # output columns
    df["sigma_lite_hits_total"]=0
    df["sigma_lite_rules_distinct"]=0

    # tag counters: attack.*만 만들기(있을 때)
    all_tags=set()
    for _,tags,_ in compiled:
        for t in tags:
            if isinstance(t,str) and t.startswith("attack."):
                all_tags.add(t)
    for t in sorted(all_tags):
        df[f"{t}_hits"]=0

    for i,row in df.iterrows():
        text=str(row.get(args.text_col,"") or "").lower()
        hit_rules=0
        hit_total=0
        tag_counts={}
        for rid, tags, needles in compiled:
            ok=False
            for field_op, pat in needles:
                if match_one(field_op, pat, text):
                    ok=True
                    break
            if ok:
                hit_rules += 1
                hit_total += 1
                for t in tags:
                    if isinstance(t,str) and t.startswith("attack."):
                        tag_counts[t]=tag_counts.get(t,0)+1
        df.at[i,"sigma_lite_hits_total"]=hit_total
        df.at[i,"sigma_lite_rules_distinct"]=hit_rules
        for t,c in tag_counts.items():
            df.at[i,f"{t}_hits"]=c

    df.to_csv(args.out_csv, index=False)
    print("[OK] wrote", args.out_csv)

if __name__=="__main__":
    main()
