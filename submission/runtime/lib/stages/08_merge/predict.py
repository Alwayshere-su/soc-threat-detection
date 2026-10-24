"""Reproduce reviewed69 from models, then replay the disjoint reviewed68 scope."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import pandas as pd

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
P69=ROOT/'lib/stages/06_evidence_review'
P68=ROOT/'lib/stages/07_secondary_review'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def load68():
    spec=importlib.util.spec_from_file_location('reviewed68',P68/'predict.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def replay(raw,parent69):
    return load68().replay(raw,parent69,read(P68/'content_decisions.json'),read(P68/'decision_policy.json'))
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    source=Path(a.input).resolve(strict=True);out=Path(a.out).resolve()
    assert out!=ROOT/'res.csv' and out!=source and not out.exists()
    policy=read(HERE/'decision_policy.json')
    for directory in [HERE,P68,P69]:
        for name,digest in read(directory/'artifact_manifest.json').items():assert sha(directory/name)==digest,name
    for name,digest in policy['component_manifest_hashes'].items():assert sha(ROOT/name)==digest
    assert sha(source) in policy['allowed_input_hashes']
    root_sha=sha(ROOT/'res.csv');out.parent.mkdir(parents=True,exist_ok=True)
    parent=out.with_suffix('.parent69.csv');assert not parent.exists()
    subprocess.run([sys.executable,str(P69/'predict.py'),'--input',str(source),'--out',str(parent)],cwd=ROOT,check=True)
    assert sha(parent)==policy['parent69_prediction_sha256']
    raw=pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig') if source.suffix.lower()=='.csv' else pd.read_parquet(source)
    result,changes=replay(raw,pd.read_csv(parent,dtype=str))
    result.to_csv(out,index=False,lineterminator='\n')
    assert sha(out)==policy['expected_prediction_sha256'] and sha(ROOT/'res.csv')==root_sha
    print(json.dumps(dict(status='reproduced',rows=len(result),merged_changes=137,sha256=sha(out),new_API_calls=0)))
if __name__=='__main__':main()
