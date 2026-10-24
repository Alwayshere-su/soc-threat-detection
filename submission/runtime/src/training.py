"""Isolated candidate training: training-only encoding, raw argmax, auditable outputs."""
import argparse
import pickle
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from config import BASE
from pipeline import (LABELS, align_truth, atomic_csv, encode_features, fit_categories,
                      metrics, sha256, validate_submission, write_json)


def run(ensemble=False):
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default=f"{BASE}/features/train_features.parquet")
    ap.add_argument("--valid", default=f"{BASE}/features/valid_features.parquet")
    ap.add_argument("--valid-answer", default=f"{BASE}/data/验证集答案/valid_answer_private.parquet")
    ap.add_argument("--num-rounds", type=int, default=3000)
    ap.add_argument("--lr", type=float, default=.05)
    ap.add_argument("--num-leaves", type=int, default=127)
    ap.add_argument("--weight-mode", choices=["none", "balanced", "sqrt"], default="balanced")
    ap.add_argument("--val-frac", type=float, default=.1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-jobs", type=int, default=8)
    ap.add_argument("--feature-version", choices=["portable_v1"], default="portable_v1")
    kind = "ensemble" if ensemble else "dense"
    ap.add_argument("--save-model", default=f"{BASE}/exp/model_{kind}.pkl")
    ap.add_argument("--save-pred")
    ap.add_argument("--first-model", help="Reuse an identically configured candidate single model as seed 42")
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()
    path = Path(args.save_model)
    prediction_path = Path(args.save_pred) if args.save_pred else path.with_name(
        "valid_pred_ensemble.csv" if ensemble else "valid_pred.csv")
    for target in [path,prediction_path,path.with_suffix(".metrics.json")]:
        if target.exists() and not args.overwrite:
            raise FileExistsError(f"Refusing to replace {target}")
    if len({p.resolve() for p in [path,prediction_path,path.with_suffix('.metrics.json')]}) != 3:
        raise ValueError("Training outputs must be distinct")
    inputs = [Path(p).resolve() for p in [args.train,args.valid,args.valid_answer]]
    if any(p.resolve() in inputs for p in [path,prediction_path,path.with_suffix('.metrics.json')]):
        raise ValueError("Training cannot overwrite inputs")
    path.parent.mkdir(parents=True, exist_ok=True)
    for cache in [args.train, args.valid]:
        sidecar = Path(cache).with_suffix(".json")
        if sidecar.exists():
            import json
            metadata = json.loads(sidecar.read_text(encoding="utf-8"))
            if metadata["feature_version"] != args.feature_version:
                raise ValueError("Cache feature version does not match requested model version")
            if metadata.get("sha256") != sha256(cache):
                raise ValueError("Cache content does not match its recorded hash")
        else:
            raise ValueError("Features require a versioned cache sidecar")

    train = pd.read_parquet(args.train)
    valid = pd.read_parquet(args.valid)
    y = train.label_binary.map(dict(zip(LABELS, range(3)))).to_numpy()
    if pd.isna(y).any() or set(np.unique(y)) != {0, 1, 2}:
        raise ValueError("Training needs all three valid classes")
    tr, va = train_test_split(np.arange(len(y)), test_size=args.val_frac, stratify=y, random_state=args.seed)
    columns = [c for c in train.columns if c not in ["event_id", "label_binary"]]
    # Inner holdout also reuses only the vocabulary learned from its training partition.
    cats = fit_categories(train.iloc[tr])
    X = encode_features(train, cats, columns)
    Xv = encode_features(valid, cats, columns)
    answer = pd.read_parquet(args.valid_answer)
    truth = align_truth(answer, valid.event_id)
    counts = np.bincount(y[tr], minlength=3)
    weights = len(tr) / (3 * counts) if args.weight_mode == "balanced" else (
        1 / np.sqrt(counts) if args.weight_mode == "sqrt" else np.ones(3))
    sample_w = weights[y[tr]].astype(np.float32)
    configs = [(42,127,.05,.8), (1,63,.06,.7), (777,255,.04,.9)] if ensemble else [
        (args.seed,args.num_leaves,args.lr,.8)]
    metadata = {"train_sha256": sha256(args.train), "feature_version": args.feature_version,
                "split_seed": args.seed, "val_frac": args.val_frac, "weight_mode": args.weight_mode,
                "num_rounds": args.num_rounds, "unknown_category": -1,
                "encoding": "training_vocabulary_numeric_v1", "valid_sha256": sha256(args.valid)}
    models = []
    prob = np.zeros((len(valid),3), dtype=np.float64)
    hold_prob = np.zeros((len(va),3), dtype=np.float64)
    report = {"metadata": metadata, "models": []}
    print(f"train={X.shape} valid={Xv.shape} class_counts={counts.tolist()}", flush=True)
    for i, (seed, leaves, lr, colsample) in enumerate(configs):
        started = time.time()
        if i == 0 and ensemble and args.first_model:
            with open(args.first_model, "rb") as stream:
                saved = pickle.load(stream)
            if saved.get("metadata") != metadata or saved["cats"] != cats or saved["common_cols"] != columns:
                raise ValueError("First model metadata, vocabulary or feature schema does not match")
            clf = saved["clf"]
            params = clf.get_params()
            if (params["random_state"],params["num_leaves"],params["learning_rate"],params["colsample_bytree"]) != (seed,leaves,lr,colsample):
                raise ValueError("First model hyperparameters do not match seed-42 configuration")
            print("Reusing verified seed-42 candidate", flush=True)
        else:
            clf = lgb.LGBMClassifier(objective="multiclass", num_class=3, n_estimators=args.num_rounds,
                num_leaves=leaves, learning_rate=lr, colsample_bytree=colsample,
                subsample=.8, subsample_freq=1, min_child_samples=50,
                random_state=seed, n_jobs=args.n_jobs, verbose=-1)
            clf.fit(X.iloc[tr], y[tr], sample_weight=sample_w,
                eval_set=[(X.iloc[va],y[va])], eval_metric="multi_logloss",
                callbacks=[lgb.early_stopping(100,verbose=False),lgb.log_evaluation(200)])
        clf.set_params(n_jobs=args.n_jobs)
        prob += clf.predict_proba(Xv) / len(configs)
        hold_prob += clf.predict_proba(X.iloc[va]) / len(configs)
        models.append(clf)
        report["models"].append({"seed":seed,"leaves":leaves,"learning_rate":lr,
                                  "best_iteration":clf.best_iteration_,"seconds":time.time()-started})
        print(f"model={i} best_iteration={clf.best_iteration_} seconds={time.time()-started:.1f}", flush=True)
    prediction = np.asarray(LABELS)[prob.argmax(1)]
    report["raw"] = metrics(truth,prediction)
    report["holdout"] = metrics(np.asarray(LABELS)[y[va]],np.asarray(LABELS)[hold_prob.argmax(1)])
    saved = {"cats":cats,"common_cols":columns,"coef":[1.,1.,1.],
             "feature_version":args.feature_version,"metadata":metadata}
    saved["models" if ensemble else "clf"] = models if ensemble else models[0]
    with path.open("wb") as stream:
        pickle.dump(saved,stream)
    output = pd.DataFrame({"event_id":valid.event_id.to_numpy(),"pred_label":prediction})
    validate_submission(output,valid.event_id)
    atomic_csv(output,prediction_path)
    report["model_sha256"] = sha256(path)
    write_json(path.with_suffix(".metrics.json"),report)
    print(f"RAW {report['raw']}\nSAVED {path}", flush=True)
