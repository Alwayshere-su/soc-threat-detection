"""调节每类概率系数以最大化官方分数。

加载已训练模型，在验证集上预测概率，然后扫描 benign/suspicious/malicious
概率的乘数（cb, cs, cm），并最大化 score.py 中的官方综合评分。
"""
import os, sys, pickle, argparse
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from fe import build_features
from score import official_score_idx, LABELS, threat_binary_metrics, class_recalls
from config import BASE

CAT_COLS = ["pipeline", "product_name", "vendor_name", "action", "protocol"]


def load_probs(model_path):
    X = pd.read_parquet(f"{BASE}/features/valid_features.parquet")
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    cats = model.get("cats", {})
    for c in CAT_COLS:
        if c in X.columns:
            cats_c = cats.get(c)
            if cats_c:
                X[c] = pd.Categorical(X[c].fillna("").astype(str), categories=cats_c).codes.astype(np.float32)
    X = X.drop(columns=[c for c in ["event_id", "label_binary"] if c in X.columns])
    common = model["common_cols"]
    X = X[common]
    models = model.get("models")
    clf = model.get("clf")
    if models is not None:
        prob = np.mean([m.predict_proba(X) for m in models], axis=0)
    else:
        prob = clf.predict_proba(X)
    ans = pd.read_parquet(f"{BASE}/data/验证集答案/valid_answer_private.parquet")
    yv = pd.read_parquet(f"{BASE}/features/valid_features.parquet", columns=["event_id"])["event_id"]
    yv = ans.set_index("event_id").reindex(yv)["label_binary"].values
    return prob, yv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=f"{BASE}/exp/model_ensemble.pkl")
    ap.add_argument("--grid", type=int, default=0,
                    help="0=粗略(0.4..2.0 步长0.1), 1=精细(0.7..1.6 步长0.05)")
    args = ap.parse_args()

    prob, yv = load_probs(args.model)
    yt = np.array([LABELS.index(x) for x in yv])   # 0/1/2
    print("prob", prob.shape, "y dist", np.bincount(yt))
    base_pred = prob.argmax(1)
    base_score, _ = official_score_idx(yt, base_pred)
    print("baseline (1,1,1) official score =", round(base_score, 5))

    if args.grid == 0:
        grid = np.round(np.arange(0.40, 2.01, 0.1), 2)
    else:
        grid = np.round(np.arange(0.70, 1.61, 0.05), 2)

    best, bcoef = -1, None
    # 保持 benign 系数固定为 1.0，扫描 suspicious/malicious 乘数
    for cs in grid:
        for cm in grid:
            if cs < 0.5 and cm < 0.5:
                continue  # 跳过过于偏向 benign 的组合（会丢失威胁召回）
            pred = (prob * np.array([1.0, cs, cm])).argmax(1)
            s, _ = official_score_idx(yt, pred, verbose=False)
            if s > best:
                best, bcoef = s, (cs, cm)
    print(f"\nBEST official score = {best:.5f}  coefs(susp,mal)={bcoef}")
    bp = (prob * np.array([1.0, bcoef[0], bcoef[1]])).argmax(1)
    official_score_idx(yt, bp)
    tb_f1, tb_rec = threat_binary_metrics(yv, np.array(LABELS)[bp])
    rec = class_recalls(yv, np.array(LABELS)[bp])
    print(f"  -> Threat-Binary-F1={tb_f1:.4f} Recall={tb_rec:.4f}"
          f"  rec(mal)={rec['malicious']:.4f} rec(sus)={rec['suspicious']:.4f}")

    # 保存用于对比的调优后预测
    pd.DataFrame({"event_id": pd.read_parquet(f"{BASE}/features/valid_features.parquet", columns=["event_id"])["event_id"].values,
                  "pred_label": np.array(LABELS)[bp]}).to_csv(f"{BASE}/exp/valid_pred_tuned.csv", index=False)
    print("saved -> exp/valid_pred_tuned.csv")


if __name__ == "__main__":
    main()
