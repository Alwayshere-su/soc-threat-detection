"""Preflight a new official input; distribution summaries are explicitly sampled."""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from fe import build_features
from pipeline import CAT_COLS, sha256, validate_ids, write_json

REQUIRED = ["event_id","message_sanitized","pipeline","product_name","vendor_name",
            "src_ip","dst_ip","src_host","dst_host","username"]


def sample_parquet(path, size=50000, seed=42, columns=None):
    file = pq.ParquetFile(path)
    total = file.metadata.num_rows
    if not total:
        raise ValueError("Empty input")
    positions = np.sort(np.random.default_rng(seed).choice(total,min(size,total),replace=False))
    parts = []
    offset = 0
    for batch in file.iter_batches(batch_size=50000,columns=columns):
        start = np.searchsorted(positions,offset)
        end = np.searchsorted(positions,offset+len(batch))
        if end > start:
            parts.append(batch.to_pandas().iloc[positions[start:end]-offset])
        offset += len(batch)
    return pd.concat(parts,ignore_index=True),positions


def main():
    import pickle
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",required=True)
    ap.add_argument("--model",required=True)
    ap.add_argument("--out-dir",required=True)
    ap.add_argument("--sample-size",type=int,default=50000)
    ap.add_argument("--reference-features")
    args = ap.parse_args()
    if args.sample_size < 1:
        ap.error("sample-size must be positive")
    schema = pq.ParquetFile(args.input).schema_arrow.names
    missing = sorted(set(REQUIRED)-set(schema))
    if missing:
        raise ValueError(f"Missing required fields: {missing}")
    ids = pd.read_parquet(args.input,columns=["event_id"]).event_id
    validate_ids(ids)
    with open(args.model,"rb") as stream:
        model = pickle.load(stream)
    frame,positions = sample_parquet(args.input,args.sample_size,columns=REQUIRED)
    features = build_features(frame,feature_version=model["feature_version"])
    report = {"input":str(Path(args.input).resolve()),"input_sha256":sha256(args.input),
              "model_sha256":sha256(args.model),"rows":len(ids),"columns":schema,
              "sample_rows":len(frame),"sample_seed":42,
              "distribution_scope":"uniform row sample; ID validity checked over all rows",
              "sample_missing_fraction":frame.isna().mean().to_dict(),"categorical":{},"numeric":{}}
    reference = None
    if args.reference_features:
        reference,_ = sample_parquet(args.reference_features,args.sample_size)
        report["reference_features_sha256"] = sha256(args.reference_features)
    for c in CAT_COLS:
        values = features[c].fillna("").astype(str)
        unknown = ~values.isin(model["cats"][c])
        report["categorical"][c] = {"unknown_fraction":float(unknown.mean()),
            "unknown_counts":values[unknown].value_counts().to_dict(),
            "counts":values.value_counts().to_dict()}
    for c in features.select_dtypes(include="number"):
        info = {"quantiles":{str(q):float(v) for q,v in features[c].quantile([0,.5,.95,1]).items()},
                "positive_fraction":float((features[c]>0).mean())}
        if reference is not None and c in reference:
            info["reference_positive_fraction"] = float((reference[c]>0).mean())
            info["reference_quantiles"] = {str(q):float(v) for q,v in reference[c].quantile([0,.5,.95,1]).items()}
        report["numeric"][c] = info
    out = Path(args.out_dir)
    write_json(out/"input_report.json",report)
    frame.insert(0,"original_row",positions)
    out.mkdir(parents=True,exist_ok=True)
    frame.head(200).to_csv(out/"sample.csv",index=False)
    print(f"Rows={len(ids)} sample={len(frame)} report={out/'input_report.json'}",flush=True)
    print("Unknown category fractions:",{c:v["unknown_fraction"] for c,v in report["categorical"].items()})


if __name__ == "__main__":
    main()
