"""Fresh .97031485 baseline plus recomputed reviewed request evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pandas as pd
from content_policy import assess
from request_recovery import recover,decode_part
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
PARENT=ROOT/'lib/stages/08_merge'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def replay(raw,parent,decisions,policy):
    assert raw.event_id.equals(parent.event_id) and raw.event_id.is_unique
    result=parent.copy();changes=[];used=set();rank={'benign':0,'suspicious':1,'malicious':2}
    for i in range(len(raw)):
        if raw.pipeline.iloc[i]!='payload':continue
        message=raw.message_sanitized.iloc[i];key=hashlib.sha256(message.encode()).hexdigest()
        if key not in decisions:continue
        d=decisions[key];f=assess(message,recover,decode_part)
        assert f and f.label==d['label'] and f.category==d['category']
        assert hashlib.sha256(f.evidence.encode()).hexdigest()==d['evidence_sha256']
        before=result.pred_label.iloc[i];assert before==d['before'] and rank[f.label]>rank[before]
        result.loc[i,'pred_label']=f.label;used.add(key)
        changes.append(dict(event_id=raw.event_id.iloc[i],before=before,after=f.label,category=f.category,reason=f.reason,reference=f.reference,content_sha256=key,evidence_sha256=d['evidence_sha256']))
    assert len(changes)==policy['approved_rows'] and len(used)==policy['distinct_content_keys']
    core=raw.pipeline.ne('payload');assert core.sum()==50000 and result.loc[core].equals(parent.loc[core])
    return result,pd.DataFrame(changes)
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    source=Path(a.input).resolve(strict=True);out=Path(a.out).resolve();policy=read(HERE/'decision_policy.json')
    assert out!=ROOT/'res.csv' and out!=source and not out.exists() and sha(source) in policy['allowed_input_hashes']
    for name,digest in read(HERE/'artifact_manifest.json').items():assert sha(HERE/name)==digest,name
    for name,digest in policy['parent_artifacts'].items():assert sha(PARENT/name)==digest,name
    root_before=sha(ROOT/'res.csv');out.parent.mkdir(parents=True,exist_ok=True);parentfile=out.with_suffix('.parent.csv');assert not parentfile.exists()
    subprocess.run([sys.executable,str(PARENT/'predict.py'),'--input',str(source),'--out',str(parentfile)],cwd=ROOT,check=True)
    assert sha(parentfile)==policy['parent_sha256']
    raw=pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig') if source.suffix.lower()=='.csv' else pd.read_parquet(source)
    result,changes=replay(raw,pd.read_csv(parentfile,dtype=str),read(HERE/'content_decisions.json'),policy)
    result.to_csv(out,index=False,lineterminator='\n');changes.to_csv(out.with_suffix('.changes.csv'),index=False,encoding='utf-8-sig')
    assert sha(out)==policy['prediction_sha256'] and sha(ROOT/'res.csv')==root_before
    print(json.dumps(dict(status='reproduced',rows=len(result),changes=len(changes),sha256=sha(out))))
if __name__=='__main__':main()
