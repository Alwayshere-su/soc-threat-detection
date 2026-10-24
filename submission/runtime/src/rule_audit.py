"""Full-data audit of keyword hits, labels and potentially negated threat statements."""
import argparse
import re

import pandas as pd
import pyarrow.parquet as pq

from pipeline import LABELS, align_truth, atomic_csv, write_json
from score import THREAT_TOKEN_RE

NEGATION = re.compile(r"\b(?:no|not|without|zero)\b.{0,50}(?:malware|threat|ransomware|trojan|ioc)|"
                      r"(?:malware|threat|ransomware|trojan|ioc).{0,50}(?:not found|disabled|false positive)",re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",required=True)
    ap.add_argument("--answer")
    ap.add_argument("--out-dir",required=True)
    args = ap.parse_args()
    ids = pd.read_parquet(args.input,columns=["event_id"]).event_id
    truth = None
    if args.answer:
        truth = align_truth(pd.read_parquet(args.answer),ids)
    elif "label_binary" in pq.ParquetFile(args.input).schema_arrow.names:
        truth = pd.read_parquet(args.input,columns=["label_binary"]).label_binary.to_numpy()
    report = {"rows":len(ids),"keyword_hits":0,"negated_hit_candidates":0,
              "labels_available":truth is not None,
              "hit_labels":{label:0 for label in LABELS} if truth is not None else None,"hit_scope":"all rows",
              "note":"Negation patterns flag examples for review; they do not alter predictions"}
    samples = []
    offset = 0
    for batch in pq.ParquetFile(args.input).iter_batches(batch_size=50000,columns=["event_id","message_sanitized"]):
        frame = batch.to_pandas()
        hit = frame.message_sanitized.fillna("").astype(str).str.contains(THREAT_TOKEN_RE,case=False,regex=True)
        negated = hit & frame.message_sanitized.fillna("").astype(str).str.contains(NEGATION)
        report["keyword_hits"] += int(hit.sum())
        report["negated_hit_candidates"] += int(negated.sum())
        if truth is not None:
            labels = truth[offset:offset+len(frame)]
            for label in LABELS:
                report["hit_labels"][label] += int((hit.to_numpy() & (labels==label)).sum())
            frame["label_binary"] = labels
        frame["negated_candidate"] = negated.to_numpy()
        interesting = negated | (hit & (frame.label_binary=="benign")) if truth is not None else negated
        if sum(len(x) for x in samples)<200:
            samples.append(frame[interesting].head(200-sum(len(x) for x in samples)))
        offset += len(frame)
    from pathlib import Path
    out = Path(args.out_dir)
    write_json(out/"rule_audit.json",report)
    if samples:
        atomic_csv(pd.concat(samples,ignore_index=True),out/"rule_review_samples.csv")
    print(report,flush=True)


if __name__ == "__main__":
    main()
