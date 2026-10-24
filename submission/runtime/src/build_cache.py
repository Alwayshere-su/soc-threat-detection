"""Build separate, versioned feature caches without changing original datasets."""
import argparse
import time
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
from config import BASE
from fe import build_features
from pipeline import sha256, write_json

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feature-version",choices=["portable_v1"],default="portable_v1")
    ap.add_argument("--output-dir",default=f"{BASE}/features")
    ap.add_argument("--batch-size",type=int,default=50000)
    ap.add_argument("--overwrite",action="store_true")
    args = ap.parse_args()
    if args.batch_size < 1:
        ap.error("batch-size must be positive")
    out = Path(args.output_dir)
    out.mkdir(parents=True,exist_ok=True)
    for name,source in [("train",Path(BASE)/"data/训练集/train.parquet"),
                        ("valid",Path(BASE)/"data/验证集/valid_input.parquet")]:
        target = out/f"{name}_features.parquet"
        if target.exists() and not args.overwrite:
            raise FileExistsError(target)
        if target.resolve()==source.resolve():
            raise ValueError("Cannot replace original input")
        temp = target.with_name(target.name+".tmp")
        writer = None
        rows = 0
        started = time.time()
        try:
            for batch in pq.ParquetFile(source).iter_batches(batch_size=args.batch_size):
                frame = batch.to_pandas()
                features = build_features(frame,feature_version=args.feature_version)
                features.insert(0,"event_id",frame.event_id.to_numpy())
                if "label_binary" in frame:
                    features["label_binary"] = frame.label_binary.to_numpy()
                table = pa.Table.from_pandas(features,preserve_index=False)
                if writer is None:
                    writer = pq.ParquetWriter(temp,table.schema)
                writer.write_table(table)
                rows += len(frame)
                print(f"{name}: rows={rows} elapsed={time.time()-started:.1f}s",flush=True)
        finally:
            if writer is not None:
                writer.close()
        if writer is None:
            raise ValueError("Input is empty")
        temp.replace(target)
        write_json(target.with_suffix(".json"),{"source":str(source),"source_sha256":sha256(source),
                   "feature_version":args.feature_version,"rows":rows,"sha256":sha256(target)})

if __name__ == "__main__":
    main()
