#!/usr/bin/env python3
import json, csv, argparse

def it_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            yield i, line

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max", type=int, default=0, help="0 means no limit")
    args = ap.parse_args()

    seen=set()
    rows=0
    bad=0

    with open(args.out, "w", newline="", encoding="utf-8") as fo:
        w = csv.writer(fo)
        w.writerow(["proc_uuid","cmdLine","parentSubject","startTimestampNanos"])

        for lineno, line in it_lines(args.raw):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue

            d = rec.get("datum", {})
            if not (isinstance(d, dict) and len(d)==1):
                continue

            kind = next(iter(d.keys()))
            body = d[kind]

            # Subject 레코드만
            if "Subject" not in str(kind):
                continue
            if not isinstance(body, dict):
                continue
            if body.get("type") != "SUBJECT_PROCESS":
                continue

            pu = body.get("uuid")
            if not pu or pu in seen:
                continue

            seen.add(pu)
            cmd = body.get("cmdLine", "")
            parent = body.get("parentSubject", "")
            ts = body.get("startTimestampNanos", "")

            w.writerow([pu, cmd, parent, ts])
            rows += 1
            if args.max and rows >= args.max:
                break

    print(f"[OK] wrote: {args.out} rows={rows:,} bad_json_lines_skipped={bad:,}")

if __name__ == "__main__":
    main()
