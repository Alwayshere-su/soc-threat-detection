"""过拟合 + 数据泄露审计。

检查项：
  1) 训练集内留出 vs 验证集差距（过拟合特征）
  2) 5 折交叉验证 macro-F1 分布
  3) 早停学习曲线（验证 logloss 是否发散）
  4) 特征消融：模型是依赖 product/vendor（易泄露）还是消息内容？分别删除后重新测验证集 macro-F1。
  5) 训练/验证消息模板重叠度（是否属于模板级泛化）
"""
import sys, os, time, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import f1_score, accuracy_score
from train import load_xy, LBL
from config import BASE

LGB_KW = dict(objective="multiclass", num_class=3, num_leaves=127, learning_rate=0.05,
              colsample_bytree=0.8, subsample=0.8, subsample_freq=1, min_child_samples=50,
              reg_alpha=0.0, reg_lambda=0.0, n_jobs=-1, verbose=-1)


def new_model(seed=42, n_est=3000):
    return lgb.LGBMClassifier(**{**LGB_KW, "random_state": seed, "n_estimators": n_est})


def mf(yt, yp):
    return f1_score(yt, yp, average="macro")


def train_eval(X, y, tr, va, Xv=None, yv=None, n_est=3000, seed=42, curve=False, es=100):
    counts = np.bincount(y)
    w = len(y) / (3 * counts)
    sw = w[y].astype(np.float32)
    model = new_model(seed, n_est)
    hist = {}
    cb = [lgb.early_stopping(es, verbose=0)]
    if curve:
        cb.append(lgb.log_evaluation(0))
        cb.append(lgb.record_evaluation(hist))
    model.fit(X.iloc[tr], y[tr], eval_set=[(X.iloc[va], y[va])], eval_metric="multi_logloss",
              sample_weight=sw[tr], callbacks=cb)
    hp = model.predict_proba(X.iloc[va]).argmax(1)
    res = dict(train_holdout_mf=mf(y[va], hp), best_iter=model.best_iteration_,
               best_score=model.best_score_)
    if Xv is not None:
        vp = model.predict_proba(Xv).argmax(1)
        res["valid_mf"] = mf(yv, vp)
        res["valid_acc"] = accuracy_score(yv, vp)
    if curve:
        res["curve"] = hist
    return res


def main():
    X, y, cats = load_xy(f"{BASE}/features/train_features.parquet")
    Xv, _, _ = load_xy(f"{BASE}/features/valid_features.parquet", cats)
    veid = pd.read_parquet(f"{BASE}/features/valid_features.parquet", columns=["event_id"])["event_id"]
    an = pd.read_parquet(f"{BASE}/data/验证集答案/valid_answer_private.parquet")
    yv = an.set_index("event_id").reindex(veid)["label_binary"].map({k: i for i, k in enumerate(LBL)}).to_numpy()
    print("train", X.shape, "valid", Xv.shape, "counts", np.bincount(y), flush=True)

    # ---- 1) 训练集内留出 vs 验证集 ----
    idx = np.arange(len(y)); tr, va = train_test_split(idx, test_size=0.1, stratify=y, random_state=42)
    r1 = train_eval(X, y, tr, va, Xv, yv)
    print(f"[1] train-holdout macro_f1={r1['train_holdout_mf']:.4f} | valid macro_f1={r1['valid_mf']:.4f} "
          f"acc={r1['valid_acc']:.4f} best_iter={r1['best_iter']}", flush=True)

    # ---- 2) 5 折交叉验证 ----
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cvmf = []
    for fold, (tr, va) in enumerate(skf.split(X, y)):
        r = train_eval(X, y, tr, va, n_est=1500, seed=fold)
        cvmf.append(r["train_holdout_mf"])
    cvmf = np.array(cvmf)
    print(f"[2] 5-fold CV macro_f1: mean={cvmf.mean():.4f} std={cvmf.std():.4f} "
          f"min={cvmf.min():.4f} max={cvmf.max():.4f}", flush=True)
    # 恢复原始的 10% 留出切分（CV 循环重新绑定了 tr/va）
    tr, va = train_test_split(idx, test_size=0.1, stratify=y, random_state=42)

    # ---- 3) 学习曲线（每轮迭代的验证 logloss）----
    r3 = train_eval(X, y, tr, va, curve=True)
    try:
        cvv = [v for v in r3["curve"]["valid"]["multi_logloss"] if v is not None]
    except Exception:
        cvv = list(r3.get("best_score", {}).items())
    if cvv and isinstance(cvv[0], float):
        xs = np.array(cvv)
        best_i = int(np.argmin(xs))
        print(f"[3] early stopping: best_iter={r3['best_iter']} (min valid logloss at {best_i}); "
              f"first={xs[0]:.4f} best={xs[best_i]:.4f} last={xs[-1]:.4f} "
              f"overfit_rise={xs[-1] > xs[best_i] + 0.001}", flush=True)
    else:
        print(f"[3] best_score={r3.get('best_score')}  (curve unavailable)", flush=True)

    # ---- 4) 特征消融 ----
    vocab = {
        "product_vendor": ["product_name", "vendor_name"],
        "message_composition": ["msg_len", "msg_words", "n_cred", "n_org", "n_user", "n_ips"],
        "family_flags": [c for c in X.columns if c.startswith("is_")],
    }
    base = r1["valid_mf"]
    print(f"[4] feature ablation (valid macro_f1): full={base:.4f}", flush=True)
    for name, cols in vocab.items():
        drop = [c for c in cols if c in X.columns]
        Xn = X.drop(columns=drop); Xvn = Xv.drop(columns=drop)
        rr = train_eval(Xn, y, tr, va, Xvn, yv)
        print(f"    drop {name:20s} ({len(drop)}): valid_macro_f1={rr['valid_mf']:.4f} "
              f"(delta {rr['valid_mf']-base:+.4f})", flush=True)

    # ---- 5) 消息模板重叠度 ----
    def tpl(m):
        s = str(m)
        s = re.sub(r"[A-Z]{2,10}-\d+", "TOK", s)
        s = re.sub(r"\d+", "#", s)
        s = re.sub(r"([A-Za-z_]{1,3})\1", r"\1", s)
        return s[:60]
    trm = set(pd.read_parquet(f"{BASE}/data/训练集/train.parquet", columns=["message_sanitized"])["message_sanitized"].map(tpl))
    vam = pd.read_parquet(f"{BASE}/data/验证集/valid_input.parquet", columns=["message_sanitized"])["message_sanitized"].map(tpl)
    in_tr = vam.isin(trm).mean()
    print(f"[5] message-template overlap: valid templates present in train = {in_tr*100:.2f}%", flush=True)


if __name__ == "__main__":
    main()
