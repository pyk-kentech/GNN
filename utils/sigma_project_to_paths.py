#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, os, pickle, re, sys
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional

import yaml
import pandas as pd

sys.path.append(str(Path(__file__).resolve().parents[1]))
from utils.mitre_ttp_mapper import TTPMapper
SYSCALL_TO_EVENT = {
    "execve": "EVENT_EXECUTE",
    "execveat": "EVENT_EXECUTE",
    "clone": "EVENT_CLONE",
    "fork": "EVENT_FORK",
}

def normalize_counter(x: Any) -> Counter:
    if isinstance(x, Counter):
        return x
    if isinstance(x, dict):
        return Counter({k: int(v) for k, v in x.items()})
    return Counter()

@dataclass
class SigmaRule:
    path: str
    title: str
    rule_id: str
    tags: List[str]
    product: str
    service: str
    detection: Dict[str, Any]

def load_sigma_rules(sigma_dir: str) -> List[SigmaRule]:
    rules: List[SigmaRule] = []
    for root, _dirs, files in os.walk(sigma_dir):
        for fn in files:
            if not fn.endswith((".yml", ".yaml")):
                continue
            p = os.path.join(root, fn)
            try:
                y = yaml.safe_load(open(p, "r", encoding="utf-8")) or {}
            except Exception:
                continue

            tags = [t for t in (y.get("tags") or []) if isinstance(t, str) and t.startswith("attack.")]
            logsource = y.get("logsource") or {}
            rules.append(SigmaRule(
                path=p,
                title=str(y.get("title","") or ""),
                rule_id=str(y.get("id","") or ""),
                tags=tags,
                product=str(logsource.get("product","") or ""),
                service=str(logsource.get("service","") or ""),
                detection=y.get("detection") or {},
            ))
    return rules

def extract_selection_blocks(detection: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Sigma detection에서 selection 블록을 최대한 폭넓게 수집:
    - 키가 'selection' 또는 'selection*' 로 시작하는 dict
    """
    if not isinstance(detection, dict):
        return []
    blocks = []
    for k, v in detection.items():
        if isinstance(k, str) and k.lower().startswith("selection") and isinstance(v, dict):
            blocks.append(v)
    return blocks

def rule_is_useful(rule: SigmaRule, mode: str) -> Tuple[bool, str]:
    """
    strict: selection 블록 중 syscall 키가 있고, 우리가 지원하는 syscall이어야 함
    weak  : selection 구조가 복잡해도 rule의 tags를 사용할 수 있으면 OK
    """
    det = rule.detection or {}
    blocks = extract_selection_blocks(det)
    if not blocks:
        # selection이 아예 없으면 weak에서도 쓰기 애매(룰 자체가 다른 형태)
        return (False, "no_selection_block")

    if mode == "weak":
        return (True, "ok_weak")

    # strict
    supported = False
    for b in blocks:
        sc = b.get("syscall")
        if not sc:
            continue
        scs = sc if isinstance(sc, list) else [sc]
        for s in scs:
            if str(s).lower() in SYSCALL_TO_EVENT:
                supported = True
                break
        if supported:
            break

    if not supported:
        return (False, "no_supported_syscall_in_any_selection")
    return (True, "ok_strict")

def pp_edge_has_event(pp_attr: Dict[str, Any], ev: str) -> bool:
    cc = normalize_counter(pp_attr.get("cnt_common", {}))
    rs = normalize_counter(pp_attr.get("rare_support", {}))
    return (cc.get(ev, 0) > 0) or (rs.get(ev, 0) > 0)

def edge_matches_rule(pp_attr: Dict[str, Any], rule: SigmaRule, mode: str) -> bool:
    det = rule.detection or {}
    blocks = extract_selection_blocks(det)

    if mode == "weak":
        return False

    # strict: selection 블록들 중 하나라도 (지원 syscall) 만족하면 hit
    for b in blocks:
        sc = b.get("syscall")
        if not sc:
            continue
        scs = sc if isinstance(sc, list) else [sc]
        for s in scs:
            ev = SYSCALL_TO_EVENT.get(str(s).lower())
            if ev and pp_edge_has_event(pp_attr, ev):
                return True
    return False

def load_dag_edges_jsonl(path: str):
    children = defaultdict(list)
    parents = defaultdict(list)
    dag_edges = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            u, v = r["parent"], r["child"]
            children[u].append(v)
            parents[v].append(u)
            dag_edges.append((u, v, r))
    roots = [n for n in children if n not in parents]
    leaves = [n for n in parents if n not in children]
    return children, parents, dag_edges, roots, leaves

def enumerate_paths(children, root: str, max_depth: int) -> List[List[str]]:
    paths = []
    def dfs(cur, path):
        if (len(path)-1) >= max_depth or cur not in children:
            paths.append(path); return
        for nxt in children[cur]:
            if nxt in path:  # cycle guard
                continue
            dfs(nxt, path + [nxt])
    dfs(root, [root])
    return paths

def load_pp_edges(pp_pkl: str):
    obj = pickle.load(open(pp_pkl, "rb"))
    return obj["edges"]

def basic_path_features(path: List[str], dag_edge_map: Dict[Tuple[str, str], Dict[str, Any]]) -> Dict[str, Any]:
    length = len(path)-1
    t0=t1=None
    rare_sum=0.0
    rare_cnt=0
    for u,v in zip(path[:-1], path[1:]):
        e = dag_edge_map.get((u,v), {})
        feats = e.get("features", {})
        r = float(feats.get("rare_score", 0.0))
        rare_sum += r
        if r>0: rare_cnt += 1
        fts = int(e.get("first_ts", 0))
        lts = int(e.get("last_ts", 0))
        if t0 is None: t0 = fts
        t1 = lts
    dur = (t1-t0) if (t0 is not None and t1 is not None) else 0
    return {
        "path_length": length,
        "path_duration_ns": dur,
        "rare_sum_dag": rare_sum,
        "rare_count_dag": rare_cnt,
        "rare_density_dag": rare_cnt / max(1,length),
    }

def project_sigma_to_path(path: List[str], pp_edges, rules: List[SigmaRule], mode: str,
                          ttp_mapper: TTPMapper) -> Dict[str, Any]:
    tag_hits = Counter()
    rule_hits = Counter()

    for u,v in zip(path[:-1], path[1:]):
        attr = pp_edges.get((u,v))
        if not attr:
            continue
        for rule in rules:
            if edge_matches_rule(attr, rule, mode):
                rid = rule.rule_id or rule.title or os.path.basename(rule.path)
                rule_hits[rid] += 1
                for t in rule.tags:
                    tag_hits[t] += 1

    out = {f"{t}_hits": int(c) for t, c in tag_hits.items()}
    out["sigma_rule_hits_total"] = int(sum(rule_hits.values()))
    out["sigma_rules_distinct"] = int(len(rule_hits))
    if ttp_mapper:
        tactic_hits = Counter()
        tactic_name_hits = Counter()
        technique_hits = Counter()
        technique_name_hits = Counter()
        for tag, count in tag_hits.items():
            for info in ttp_mapper.map_tags([tag]):
                if info.tactic:
                    tactic_hits[info.tactic] += count
                if info.tactic_name:
                    tactic_name_hits[info.tactic_name] += count
                technique_hits[info.technique_id] += count
                if info.name:
                    technique_name_hits[info.name] += count
        out["ttp_tactic_hits_total"] = int(sum(tactic_hits.values()))
        out["ttp_tactic_name_hits_total"] = int(sum(tactic_name_hits.values()))
        out["ttp_technique_hits_total"] = int(sum(technique_hits.values()))
        out["ttp_technique_name_hits_total"] = int(sum(technique_name_hits.values()))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["strict","weak"], default="weak")
    ap.add_argument("--sigma-dir", required=True)
    ap.add_argument("--dag-edges", required=True)
    ap.add_argument("--pp-pkl", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--out-report", required=True)
    ap.add_argument("--max-depth", type=int, default=10)
    ap.add_argument("--top-k-paths", type=int, default=200)
    ap.add_argument("--mitre-gml", help="MITRE ATT&CK GML path for tactic/technique mapping")
    ap.add_argument("--mitre-link-map", help="CSV link map for MITRE GML (optional)")
    ap.add_argument("--keag-root", help="Knowledge-enhanced-Attack-Graph root (for default MITRE GML lookup)")
    args = ap.parse_args()

    rules = load_sigma_rules(args.sigma_dir)
    usable = []
    skipped = Counter()
    for r in rules:
        ok, reason = rule_is_useful(r, args.mode)
        if ok:
            usable.append(r)
        else:
            skipped[reason]+=1

    children, parents, dag_edges, roots, leaves = load_dag_edges_jsonl(args.dag_edges)
    dag_edge_map = {(u,v): rec for (u,v,rec) in dag_edges}
    pp_edges = load_pp_edges(args.pp_pkl)

    ttp_mapper = TTPMapper(args.mitre_gml, args.mitre_link_map, args.keag_root)
    rows = []
    for root in roots:
        for p in enumerate_paths(children, root, args.max_depth):
            base = basic_path_features(p, dag_edge_map)
            sig = project_sigma_to_path(p, pp_edges, usable, args.mode, ttp_mapper)
            rows.append({
                "root": root,
                "leaf": p[-1],
                "path": "->".join(p),
                **base,
                **sig
            })

    df = pd.DataFrame(rows).fillna(0)
    if len(df)>0:
        df = df.sort_values(by=["rare_sum_dag","path_length","path_duration_ns"], ascending=False).head(args.top_k_paths)
    df.to_csv(args.out_csv, index=False)

    report = {
        "mode": args.mode,
        "num_rules_total": len(rules),
        "num_rules_usable": len(usable),
        "num_rules_skipped": len(rules)-len(usable),
        "skip_reasons_top": skipped.most_common(20),
        "dag": {"num_roots": len(roots), "num_leaves": len(leaves), "num_edges_jsonl": len(dag_edges)},
        "pp": {"num_pp_edges": len(pp_edges)}
    }
    json.dump(report, open(args.out_report,"w",encoding="utf-8"), indent=2)

    print("[OK] wrote:", args.out_csv)
    print("[OK] wrote:", args.out_report)
    print("[INFO] sigma rules total:", len(rules), "usable:", len(usable), "skipped:", len(rules)-len(usable))
    print(df.head(5).to_string(index=False))

if __name__ == "__main__":
    main()
