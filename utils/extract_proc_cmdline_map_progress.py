#!/usr/bin/env python3
import json, csv, argparse, time

def iter_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line:
                yield i, line

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--progress-every", type=int, default=200000,
                    help="print progress every N non-empty lines")
    ap.add_argument("--flush-every", type=int, default=5000,
                    help="flush output every N rows (safer on Ctrl-C)")
    ap.add_argument("--skip-bad-json", action="store_true", default=True,
                    help="skip bad json lines (default true)")
    args = ap.parse_args()

    seen=set()
    rows=0
    bad=0
    nonempty=0

    t0=time.time()
    last_t=t0
    last_nonempty=0

    with open(args.out, "w", newline="", encoding="utf-8") as fo:
        w = csv.writer(fo)
        w.writerow(["proc_uuid","cmdLine","parentSubject","startTimestampNanos"])

        try:
            for lineno, line in iter_lines(args.raw):
                nonempty += 1
                if nonempty % args.progress_every == 0:
                    now=time.time()
                    dt=now-last_t
                    dtotal=now-t0
                    rate=(nonempty-last_nonempty)/dt if dt>0 else 0.0
                    print(f"[PROG] raw_line={lineno:,} nonempty={nonempty:,} rows={rows:,} bad={bad:,} "
                          f"rate={rate:,.1f} lines/s elapsed={dtotal/60:.1f} min")
                    last_t=now
                    last_nonempty=nonempty

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

                if rows % args.flush_every == 0:
                    fo.flush()

        except KeyboardInterrupt:
            fo.flush()
            now=time.time()
            print(f"\n[INTERRUPTED] nonempty={nonempty:,} rows={rows:,} bad={bad:,} elapsed={(now-t0)/60:.1f} min")
            print(f"[PARTIAL] wrote: {args.out}")
            return

    now=time.time()
    print(f"[DONE] wrote: {args.out} rows={rows:,} bad_json_lines_skipped={bad:,} elapsed={(now-t0)/60:.1f} min")

if __name__ == "__main__":
    main()
