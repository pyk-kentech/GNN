#!/usr/bin/env python3
import argparse
import numpy as np
import pandas as pd

def mad(x: np.ndarray) -> float:
    """Median Absolute Deviation (scaled optional; 여기서는 스케일만 쓰므로 raw MAD)"""
    med = np.median(x)
    return np.median(np.abs(x - med))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp-csv", required=True, help="path-level feature csv")
    ap.add_argument("--out-csv", required=True, help="output csv with anomaly scores")
    ap.add_argument("--topk", type=int, default=20, help="print top-k rows")
    ap.add_argument("--eps", type=float, default=1e-9)
    ap.add_argument("--use-cols", default="",
                    help="comma-separated feature columns to use. empty => auto numeric cols")
    args = ap.parse_args()

    df = pd.read_csv(args.inp_csv)

    # 1) 사용할 feature 컬럼 선택
    if args.use_cols.strip():
        cols = [c.strip() for c in args.use_cols.split(",") if c.strip()]
        missing = [c for c in cols if c not in df.columns]
        if missing:
            raise SystemExit(f"ERROR: missing columns: {missing}")
    else:
        # 자동: 숫자형 컬럼 중 식별자/길이 아닌 것까지 포함되면 위험하니 필터링
        # 우선 numeric만, 그리고 sigma 관련/문자열 컬럼 제외
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        drop_like = {"sigma_rule_hits_total","sigma_rules_distinct",
                     "sigma_lite_hits_total","sigma_lite_rules_distinct"}
        cols = [c for c in numeric_cols if c not in drop_like]

    if not cols:
        raise SystemExit("ERROR: no numeric feature columns selected")

    if "path_duration_ns" in df.columns:
        df["path_duration_ns"] = df["path_duration_ns"].clip(lower=0)

    X = df[cols].to_numpy(dtype=float)
    # NaN/inf 방어
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # 2) Robust 표준화: median / MAD
    med = np.median(X, axis=0)
    mads = np.array([mad(X[:, i]) for i in range(X.shape[1])], dtype=float)
    mads = np.where(mads < args.eps, 1.0, mads)  # 0 MAD 방지
    Z = (X - med) / (mads + args.eps)

    # 3) 점수 계산
    # 3-A) 대각선(상관 무시): L2 norm
    score_diag = np.sqrt((Z * Z).sum(axis=1))

    # 3-B) Mahalanobis (상관 고려): 공분산 추정 + 역행렬
    # 샘플 수가 적으면 공분산이 불안정하니 shrinkage(레도이트-울프)를 사용
    try:
        from sklearn.covariance import LedoitWolf
        lw = LedoitWolf().fit(Z)
        cov = lw.covariance_
    except Exception:
        # sklearn 없거나 실패 시: 기본 공분산 + 작은 정규화
        cov = np.cov(Z, rowvar=False)
        cov = cov + np.eye(cov.shape[0]) * 1e-6

    # 역행렬(안정화)
    try:
        inv_cov = np.linalg.inv(cov)
    except np.linalg.LinAlgError:
        inv_cov = np.linalg.pinv(cov)

    score_maha = np.sqrt(np.einsum("bi,ij,bj->b", Z, inv_cov, Z))

    # 4) 결과 저장
    df["anomaly_score_diag"] = score_diag
    df["anomaly_score_maha"] = score_maha

    df.to_csv(args.out_csv, index=False)
    print("[OK] wrote", args.out_csv)
    print("[INFO] used feature cols:", cols)

    # 5) top-k 출력
    k = min(args.topk, len(df))
    show_cols = [c for c in ["root","leaf","path","path_length","path_duration_ns","rare_sum_dag","rare_density_dag",
                             "anomaly_score_maha","anomaly_score_diag","path_cmdline_concat"] if c in df.columns]
    top = df.sort_values("anomaly_score_maha", ascending=False).head(k)
    print("\n[TOP by anomaly_score_maha]")
    print(top[show_cols].to_string(index=False))

if __name__ == "__main__":
    main()
