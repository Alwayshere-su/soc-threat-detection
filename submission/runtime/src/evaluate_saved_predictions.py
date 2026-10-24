"""Apply the same inference rule to saved raw predictions, checking full input/answer IDs."""
import argparse
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

from pipeline import align_truth, atomic_csv, metrics, sha256, validate_submission, write_json
from score import apply_threat_rule


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",required=True)
    ap.add_argument("--raw-pred",required=True)
    ap.add_argument("--answer",required=True)
    ap.add_argument("--out",required=True)
    args = ap.parse_args()
    out = Path(args.out)
    if out.exists() or out.with_suffix(".metrics.json").exists():
        raise FileExistsError(out)
    raw = pd.read_csv(args.raw_pred)
    ids = pd.read_parquet(args.input,columns=["event_id"]).event_id
    validate_submission(raw,ids)
    raw = raw.set_index("event_id").loc[ids].reset_index()
    truth = align_truth(pd.read_parquet(args.answer),ids)
    parts = []
    offset = 0
    for batch in pq.ParquetFile(args.input).iter_batches(batch_size=50000,columns=["message_sanitized"]):
        messages = batch.to_pandas().message_sanitized.to_numpy()
        parts.append(apply_threat_rule(raw.pred_label.to_numpy()[offset:offset+len(messages)],messages))
        offset += len(messages)
        print(f"rules: rows={offset}",flush=True)
    import numpy as np
    final = raw.copy()
    final["pred_label"] = np.concatenate(parts)
    validate_submission(final,ids)
    changes = raw.pred_label.to_numpy()!=final.pred_label.to_numpy()
    report = {"input_sha256":sha256(args.input),"raw_prediction_sha256":sha256(args.raw_pred),
              "raw":metrics(truth,raw.pred_label),"final":metrics(truth,final.pred_label),
              "rule_changes":int(changes.sum()),"rule_added_benign_false_positives":int((changes & (truth=="benign")).sum())}
    atomic_csv(final,out)
    report["prediction_sha256"] = sha256(out)
    write_json(out.with_suffix(".metrics.json"),report)
    print(report,flush=True)


if __name__ == "__main__":
    main()
