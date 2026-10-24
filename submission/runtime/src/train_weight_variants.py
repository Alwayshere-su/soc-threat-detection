"""在官方分数上对比不同类别权重方案，测试模型层面（而非仅决策规则）
能否在不引入误报的情况下提升威胁召回。"""
import sys, time, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from score import official_score_idx, LABELS
from train import load_xy
from config import BASE


def main():
    X, y, cats = load_xy(f"{BASE}/features/train_features.parquet")
    count = np.bincount(y)  # benign, suspicious, malicious
    idx = np.arange(len(y))
    tr, va = train_test_split(idx, test_size=0.1, stratify=y, random_state=42)

    Xv, _, _ = load_xy(f"{BASE}/features/valid_features.parquet", cats)
    veid = pd.read_parquet(f"{BASE}/features/valid_features.parquet", columns=["event_id"])["event_id"]
    an = pd.read_parquet(f"{BASE}/data/验证集答案/valid_answer_private.parquet")
    yv = an.set_index("event_id").reindex(veid)["label_binary"].map({k: i for i, k in enumerate(LABELS)}).to_numpy()

    # 各类别权重方案（balanced / sqrt / 高权重malicious / 高权重sus+mal / uniform / 仅高mal）
    schemes = {
        "balanced": lambda c: len(y) / (3 * c),
        "sqrt": lambda c: 1.0 / np.sqrt(c),
        "mal_high": lambda c: len(y) / (3 * c) * np.array([1.0, 1.0, 4.0]),
        "sus_mal_high": lambda c: len(y) / (3 * c) * np.array([1.0, 1.5, 4.0]),
        "uniform": lambda c: np.ones(3),
        "mal_only_high": lambda c: len(y) / (3 * c) * np.array([1.0, 1.0, 10.0]),
    }
    print("Train counts:", count)
    for name, fn in schemes.items():
        w = fn(count.astype(float))
        sw = w[y].astype(np.float32)
        t = time.time()
        clf = lgb.LGBMClassifier(objective="multiclass", num_class=3, n_estimators=3000,
                                 learning_rate=0.05, num_leaves=127, colsample_bytree=0.8,
                                 subsample=0.8, subsample_freq=1, min_child_samples=50,
                                 random_state=42, n_jobs=-1, verbose=-1)
        clf.fit(X.iloc[tr], y[tr], eval_set=[(X.iloc[va], y[va])], eval_metric="multi_logloss",
                sample_weight=sw[tr], callbacks=[lgb.early_stopping(100, verbose=0)])
        prob = clf.predict_proba(Xv)
        s, comp = official_score_idx(yv, prob.argmax(1), verbose=False)
        print(f"  {name:22s} weights={np.round(w,2)}  official={s:.5f}  "
              f"tb_rec={comp['tb_rec']:.4f} rec_mal={comp['rec']['malicious']:.4f} "
              f"rec_sus={comp['rec']['suspicious']:.4f} ({time.time()-t:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
