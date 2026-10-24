"""Verify release integrity and the reference submission, without inference."""
import json
from pathlib import Path
from reproduce import verify_package,sha,EXPECTED,ROOT
def main():
 import pandas as pd
 n=verify_package();p=ROOT/'res.csv';d=pd.read_csv(p,dtype=str,keep_default_na=False)
 assert sha(p)==EXPECTED and d.shape==(55837,2) and d.event_id.is_unique and list(d.columns)==['event_id','pred_label'] and d.pred_label.isin(['benign','suspicious','malicious']).all()
 print(json.dumps(dict(passed=True,files=n,rows=len(d),prediction_sha256=EXPECTED)))
if __name__=='__main__':main()
