"""Recompute immutable v5, then replay only frozen content-based review decisions."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pandas as pd

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PARENT=ROOT/'lib/stages/04_semantic14b'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))

def replay(raw,parent,decisions,policy):
    assert len(raw)==len(parent) and raw.event_id.equals(parent.event_id)
    assert raw.event_id.is_unique and parent.columns.tolist()==['event_id','pred_label']
    labels=parent.pred_label.to_numpy(dtype=object).copy();changes=[];used=set()
    for i in range(len(raw)):
        if raw.pipeline.iloc[i]!='payload':continue
        key=hashlib.sha256(raw.message_sanitized.iloc[i].encode()).hexdigest()
        if key not in decisions:continue
        decision=decisions[key];used.add(key)
        assert labels[i]==decision['parent_label'] and labels[i]!=decision['label']
        assert decision['confidence']=='high' and decision['label'] in ['benign','malicious','suspicious']
        changes.append(dict(event_id=raw.event_id.iloc[i],before=labels[i],after=decision['label'],
            category=decision['category'],reason=decision['reason'],content_sha256=key,
            evidence_sha256=decision['evidence_sha256']))
        labels[i]=decision['label']
    assert len(used)==policy['distinct_content_keys'] and len(changes)==policy['approved_rows']
    result=pd.DataFrame(dict(event_id=raw.event_id,pred_label=labels))
    core=raw.pipeline.ne('payload')
    assert core.sum()==50000 and result.loc[core].equals(parent.loc[core])
    assert set(result.pred_label)<=set(['benign','malicious','suspicious'])
    return result,pd.DataFrame(changes)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True);parser.add_argument('--out',required=True)
    args=parser.parse_args();source=Path(args.input).resolve(strict=True);target=Path(args.out).resolve()
    assert not target.exists() and target!=ROOT/'res.csv' and target!=source
    assert not target.with_suffix('.parent.csv').exists()
    policy=read(HERE/'decision_policy.json')
    for name,digest in read(HERE/'artifact_manifest.json').items():assert sha(HERE/name)==digest,name
    for name,digest in policy['baseline_artifacts'].items():assert sha(PARENT/name)==digest,name
    assert sha(source) in policy['allowed_input_hashes']
    root_sha=sha(ROOT/'res.csv')
    target.parent.mkdir(parents=True,exist_ok=True)
    parentfile=target.with_suffix('.parent.csv')
    subprocess.run([sys.executable,str(PARENT/'predict.py'),'--input',str(source),'--out',str(parentfile)],cwd=ROOT,check=True)
    assert sha(parentfile)==policy['baseline_prediction_sha256']
    raw=pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig') if source.suffix.lower()=='.csv' else pd.read_parquet(source)
    parent=pd.read_csv(parentfile,dtype=str,keep_default_na=False)
    result,changes=replay(raw,parent,read(HERE/'content_decisions.json'),policy)
    result.to_csv(target,index=False,lineterminator='\n')
    changes.to_csv(target.with_suffix('.changes.csv'),index=False,encoding='utf-8-sig')
    assert sha(target)==policy['expected_prediction_sha256']
    assert sha(ROOT/'res.csv')==root_sha
    print(json.dumps(dict(status='reproduced',rows=len(result),changes=len(changes),sha256=sha(target),new_API_calls=0),ensure_ascii=False))

if __name__=='__main__':main()
