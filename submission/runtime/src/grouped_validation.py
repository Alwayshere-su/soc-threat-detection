"""Compare random and complete-message-template holdouts on the same uniform training sample."""
import argparse
import hashlib
import re

import lightgbm as lgb
import numpy as np
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from fe import build_features
from inspect_input import sample_parquet
from pipeline import LABELS, encode_features, fit_categories, metrics, write_json


def template_hash(message):
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b","IP",str(message))
    text = re.sub(r"[A-Z]{2,10}-\d+(?:-\d+)*","TOKEN",text)
    text = re.sub(r"\b[0-9a-fA-F]{16,}\b","HEX",text)
    text = re.sub(r"\d+","#",text)
    text = re.sub(r"\s+"," ",text).strip().lower()
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--sample-size",type=int,default=120000)
    ap.add_argument("--num-rounds",type=int,default=800)
    ap.add_argument("--n-jobs",type=int,default=8)
    args = ap.parse_args()
    frame,_ = sample_parquet(args.train,args.sample_size)
    y = frame.label_binary.map(dict(zip(LABELS,range(3)))).to_numpy()
    features = build_features(frame,feature_version="portable_v1")
    groups = frame.message_sanitized.map(template_hash).to_numpy()
    index = np.arange(len(y))
    random_split = train_test_split(index,test_size=.2,stratify=y,random_state=42)
    group_split = None
    # Require all three labels in both partitions; do not choose splits by model score.
    for tr,va in GroupShuffleSplit(n_splits=50,test_size=.2,random_state=42).split(features,y,groups):
        if set(y[tr])=={0,1,2} and set(y[va])=={0,1,2}:
            group_split = (tr,va)
            break
    if group_split is None:
        raise ValueError("No group holdout retaining all classes; inspect template/class concentration")
    report = {"sample_rows":len(frame),"sample_seed":42,"unique_templates":len(set(groups)),
              "template_definition":"Full message with anonymized tokens, IPs, long hex, digits and whitespace normalized",
              "feature_version":"portable_v1","num_rounds":args.num_rounds,
              "limitation":"Sampled training-data stress test; does not establish performance on official new sources"}
    for name,(tr,va) in [("random",random_split),("grouped",group_split)]:
        cats = fit_categories(features.iloc[tr])
        X = encode_features(features,cats)
        counts = np.bincount(y[tr],minlength=3)
        weights = len(tr)/(3*counts)
        model = lgb.LGBMClassifier(objective="multiclass",num_class=3,n_estimators=args.num_rounds,
            learning_rate=.05,num_leaves=63,colsample_bytree=.8,subsample=.8,subsample_freq=1,
            min_child_samples=50,random_state=42,n_jobs=args.n_jobs,verbose=-1)
        model.fit(X.iloc[tr],y[tr],sample_weight=weights[y[tr]],eval_set=[(X.iloc[va],y[va])],
                  callbacks=[lgb.early_stopping(50,verbose=False)])
        prediction = model.predict(X.iloc[va])
        overlap = len(set(groups[tr]) & set(groups[va]))
        result = metrics(np.asarray(LABELS)[y[va]],np.asarray(LABELS)[prediction])
        result.update({"train_rows":len(tr),"validation_rows":len(va),
                       "train_class_counts":counts.tolist(),"validation_class_counts":np.bincount(y[va],minlength=3).tolist(),
                       "overlapping_template_groups":overlap,"best_iteration":model.best_iteration_})
        report[name] = result
        print(name,result,flush=True)
    write_json(args.out,report)


if __name__ == "__main__":
    main()
