"""Compare two versions by ID, without treating class proportions as quality scores."""
import argparse
from pathlib import Path

import pandas as pd

from pipeline import align_truth, atomic_csv, metrics, validate_submission, write_json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--left",required=True)
    ap.add_argument("--right",required=True)
    ap.add_argument("--answer")
    ap.add_argument("--input",help="Attach original log context to disagreement rows")
    ap.add_argument("--out-dir",required=True)
    args = ap.parse_args()
    left = pd.read_csv(args.left)
    right = pd.read_csv(args.right)
    validate_submission(left,left.event_id)
    validate_submission(right,left.event_id)
    right = right.set_index("event_id").loc[left.event_id].reset_index()
    difference = left.pred_label.to_numpy()!=right.pred_label.to_numpy()
    disagreements = pd.DataFrame({"event_id":left.event_id.to_numpy(),
        "left_label":left.pred_label.to_numpy(),"right_label":right.pred_label.to_numpy()})
    report = {"rows":len(left),"disagreements":int(difference.sum()),
              "left_counts":left.pred_label.value_counts().to_dict(),
              "right_counts":right.pred_label.value_counts().to_dict(),
              "interpretation":"Unlabelled disagreement and class counts do not establish which model is better"}
    if args.answer:
        truth = align_truth(pd.read_parquet(args.answer),left.event_id)
        report["left"] = metrics(truth,left.pred_label)
        report["right"] = metrics(truth,right.pred_label)
        disagreements["label_binary"] = truth
    disagreements = disagreements[difference].copy()
    if args.input:
        import pyarrow.parquet as pq
        ids = pd.read_parquet(args.input,columns=["event_id"]).event_id
        validate_submission(left,ids)
        fields = [c for c in ["event_id","pipeline","product_name","vendor_name","message_sanitized"]
                  if c in pq.ParquetFile(args.input).schema_arrow.names]
        wanted = set(disagreements.event_id)
        parts = []
        if wanted:
            for batch in pq.ParquetFile(args.input).iter_batches(batch_size=50000,columns=fields):
                frame = batch.to_pandas()
                matched = frame[frame.event_id.isin(wanted)]
                if len(matched):
                    parts.append(matched)
        context = pd.concat(parts,ignore_index=True) if parts else pd.DataFrame(columns=fields)
        disagreements = disagreements.merge(context,on="event_id",how="left",validate="one_to_one")
    out = Path(args.out_dir)
    atomic_csv(disagreements,out/"disagreements.csv")
    write_json(out/"comparison.json",report)
    print(report,flush=True)


if __name__ == "__main__":
    main()
