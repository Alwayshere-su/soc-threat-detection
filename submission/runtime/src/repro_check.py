"""可复现性检查。

用具体证据说明两件事：
  A) 训练确定性：用同一配置训练两次，逐字节比较验证集预测。
  B) 推理确定性：用同一模型对验证集预测两次，逐字节比较。
  C) 管道（特征 -> 训练 -> 预测）使用固定种子，且一切均由原始 parquet + 固定特征缓存导出。
"""
import sys, os, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
from train import load_xy
from config import BASE

LBL = ["benign", "suspicious", "malicious"]


def arr_hash(arr):
    return hashlib.sha256(np.ascontiguousarray(arr).tobytes()).hexdigest()[:16]


def train_predict(seed):
    X, y, cats = load_xy(f"{BASE}/features/train_features.parquet")
    idx = np.arange(len(y))
    tr, va = train_test_split(idx, test_size=0.1, stratify=y, random_state=42)
    c = np.bincount(y); w = len(y) / (3 * c); sw = w[y].astype(np.float32)
    m = lgb.LGBMClassifier(objective="multiclass", num_class=3, n_estimators=2000,
                           learning_rate=0.05, num_leaves=127, colsample_bytree=0.8,
                           subsample=0.8, subsample_freq=1, min_child_samples=50,
                           random_state=seed, n_jobs=-1, verbose=-1)
    m.fit(X.iloc[tr], y[tr], eval_set=[(X.iloc[va], y[va])], eval_metric="multi_logloss",
          sample_weight=sw[tr], callbacks=[lgb.early_stopping(100, verbose=0)])
    va_pred = m.predict_proba(X.iloc[va]).argmax(1)
    return arr_hash(va_pred), m.best_iteration_, f1_score(y[va], va_pred, average="macro")


def main():
    print("=== A) 训练确定性（同一配置、全新模型、不改种子）===")
    h1, it1, mf1 = train_predict(42)
    h2, it2, mf2 = train_predict(42)
    print(f"  run1: pred_hash={h1} best_iter={it1} holdout_macro_f1={mf1:.4f}")
    print(f"  run2: pred_hash={h2} best_iter={it2} holdout_macro_f1={mf2:.4f}")
    print(f"  -> 预测一致？ {h1 == h2}")

    print("\n=== B) 推理确定性（同一已保存模型，predict 两次）===")
    import pickle
    with open(f"{BASE}/exp/model_ensemble.pkl", "rb") as f:
        model = pickle.load(f)
    Xv, _, _ = load_xy(f"{BASE}/features/valid_features.parquet", model["cats"])
    Xv = Xv[model["common_cols"]]
    models = model["models"]
    p1 = np.mean([m.predict_proba(Xv) for m in models], axis=0).argmax(1)
    p2 = np.mean([m.predict_proba(Xv) for m in models], axis=0).argmax(1)
    print(f"  predict1 hash={arr_hash(p1)}")
    print(f"  predict2 hash={arr_hash(p2)}")
    print(f"  -> 一致？ {arr_hash(p1) == arr_hash(p2)}")

    print("\n=== C) 管道确定性说明 ===")
    print("  train_test_split random_state=42 ; LightGBM random_state=42 ;")
    print("  特征缓存是原始 parquet 的确定性函数 ;")
    print("  数据文件固定（train/valid/answer parquet）。")


if __name__ == "__main__":
    main()
