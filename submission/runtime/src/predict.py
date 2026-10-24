"""Batch inference with versioned features, raw/final outputs and strict ID checks."""
import argparse
import json
import pickle
import time
from pathlib import Path
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from fe import build_features
from pipeline import (LABELS, align_truth, atomic_csv, metrics, predict_probabilities,
                      sha256, validate_submission, write_json)
from score import apply_threat_rule
from config import BASE

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--model", default=f"{BASE}/exp/model_ensemble.pkl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw-out")
    ap.add_argument("--answer", help="Optional answer with exactly the input IDs")
    ap.add_argument("--features", help="Optional verified feature cache for this exact input and feature version")
    ap.add_argument("--batch-size", type=int, default=50000)
    ap.add_argument("--n-jobs", type=int, default=8)
    ap.add_argument("--no-rule", action="store_true")
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()
    if args.batch_size < 1:
        ap.error("batch-size must be positive")
    output = Path(args.out)
    raw_output = Path(args.raw_out) if args.raw_out else output.with_name(output.stem + ".raw.csv")
    report_path = output.with_suffix(".metrics.json")
    protected = {Path(p).resolve() for p in [args.input,args.model] + ([args.answer] if args.answer else []) + ([args.features] if args.features else [])}
    targets = [output,raw_output,report_path]
    if len({p.resolve() for p in targets}) != len(targets) or any(p.resolve() in protected for p in targets):
        raise ValueError("Outputs must be distinct and cannot overwrite an input/model/answer")
    for target in targets:
        if target.exists() and not args.overwrite:
            raise FileExistsError(f"Refusing to replace {target}; use a new directory or --overwrite")
    with open(args.model,"rb") as stream:
        model = pickle.load(stream)
    version = model.get("feature_version")
    if version != "portable_v1" or model.get("metadata",{}).get("encoding") != "training_vocabulary_numeric_v1":
        raise ValueError("Only the corrected portable_v1 model is supported")
    cached_features = None
    input_hash = sha256(args.input)
    if args.features:
        cache_metadata = json.loads(Path(args.features).with_suffix(".json").read_text(encoding="utf-8"))
        if (cache_metadata["feature_version"] != version or cache_metadata["source_sha256"] != input_hash
                or cache_metadata["sha256"] != sha256(args.features)):
            raise ValueError("Cache does not match the exact input, content hash or feature version")
        cached_features = pd.read_parquet(args.features)
    chunks = []
    started = time.time()
    completed = 0
    for number,batch in enumerate(pq.ParquetFile(args.input).iter_batches(batch_size=args.batch_size),1):
        frame = batch.to_pandas()
        if cached_features is None:
            features = build_features(frame,feature_version=version)
        else:
            cached_batch = cached_features.iloc[completed:completed+len(frame)]
            if not np.array_equal(cached_batch.event_id.to_numpy(),frame.event_id.to_numpy()):
                raise ValueError("Cached feature IDs/order differ from input")
            features = cached_batch.drop(columns=[c for c in ["event_id","label_binary"] if c in cached_batch])
        prob = predict_probabilities(model,features,n_jobs=args.n_jobs)
        raw = np.asarray(LABELS)[prob.argmax(1)]
        final = raw.copy() if args.no_rule else apply_threat_rule(raw,frame.message_sanitized.to_numpy())
        chunks.append(pd.DataFrame({"event_id":frame.event_id.to_numpy(),"raw_label":raw,"pred_label":final}))
        completed += len(frame)
        print(f"batch={number} rows={completed} elapsed={time.time()-started:.1f}s",flush=True)
    if not chunks:
        raise ValueError("Input is empty")
    if cached_features is not None and len(cached_features)!=completed:
        raise ValueError("Cached feature row count differs from input")
    combined = pd.concat(chunks,ignore_index=True)
    final_frame = combined[["event_id","pred_label"]]
    raw_frame = combined[["event_id","raw_label"]].rename(columns={"raw_label":"pred_label"})
    expected = pd.read_parquet(args.input,columns=["event_id"]).event_id
    validate_submission(final_frame,expected)
    validate_submission(raw_frame,expected)
    report = {"input":str(Path(args.input).resolve()),"input_sha256":input_hash,
              "model":str(Path(args.model).resolve()),"model_sha256":sha256(args.model),
              "feature_version":version,"rows":len(combined),"rule_enabled":not args.no_rule,
              "rule_changes":int((combined.raw_label != combined.pred_label).sum()),
              "prediction_counts":final_frame.pred_label.value_counts().to_dict(),
              "seconds":time.time()-started}
    if args.features:
        report["feature_cache_sha256"] = sha256(args.features)
    if args.answer:
        truth = align_truth(pd.read_parquet(args.answer),expected)
        report["raw"] = metrics(truth,combined.raw_label)
        report["final"] = metrics(truth,combined.pred_label)
        report["answer_sha256"] = sha256(args.answer)
        report["rule_added_benign_false_positives"] = int(((truth=="benign") &
            (combined.raw_label.to_numpy()=="benign") & (combined.pred_label.to_numpy()!="benign")).sum())
    atomic_csv(raw_frame,raw_output)
    atomic_csv(final_frame,output)
    report["prediction_sha256"] = sha256(output)
    write_json(report_path,report)
    print(f"SAVED {output}\nREPORT {report}",flush=True)

if __name__ == "__main__":
    main()
