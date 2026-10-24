"""Fresh scored-parent inference followed by scoped, recomputed content evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pandas as pd
from payload_policy import assess
from request_recovery import recover,decode_part

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
PARENT=ROOT/'lib/stages/05_primary_review'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))

def replay(raw,parent,decisions,policy):
    assert raw.event_id.equals(parent.event_id) and raw.event_id.is_unique
    assert parent.columns.tolist()==['event_id','pred_label']
    labels=parent.pred_label.to_numpy(dtype=object).copy();changes=[];used=set()
    for i in range(len(raw)):
        if raw.pipeline.iloc[i]!='payload':continue
        message=raw.message_sanitized.iloc[i];key=hashlib.sha256(message.encode()).hexdigest()
        if key not in decisions:continue
        expected=decisions[key];actual=assess(message,recover,decode_part);used.add(key)
        assert labels[i]=='benign' and actual.label in ['suspicious','malicious']
        assert actual.label==expected['label'] and actual.category==expected['category']
        assert hashlib.sha256(actual.evidence.encode()).hexdigest()==expected['evidence_sha256']
        changes.append(dict(event_id=raw.event_id.iloc[i],before=labels[i],after=actual.label,
            category=actual.category,reason=actual.reason,evidence_grade=actual.grade,reference=actual.reference,
            content_sha256=key,evidence_sha256=expected['evidence_sha256']))
        labels[i]=actual.label
    assert len(used)==policy['distinct_content_keys'] and len(changes)==policy['approved_rows']
    result=pd.DataFrame(dict(event_id=raw.event_id,pred_label=labels));core=raw.pipeline.ne('payload')
    assert core.sum()==50000 and result.loc[core].equals(parent.loc[core])
    assert set(result.pred_label)<=set(['benign','suspicious','malicious'])
    return result,pd.DataFrame(changes)

def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    source=Path(a.input).resolve(strict=True);target=Path(a.out).resolve()
    assert source!=target and target!=ROOT/'res.csv' and not target.exists()
    assert not target.with_suffix('.parent.csv').exists()
    policy=read(HERE/'decision_policy.json')
    for name,digest in read(HERE/'artifact_manifest.json').items():assert sha(HERE/name)==digest,name
    for name,digest in policy['baseline_artifacts'].items():assert sha(PARENT/name)==digest,name
    assert sha(source) in policy['allowed_input_hashes']
    root_sha=sha(ROOT/'res.csv');target.parent.mkdir(parents=True,exist_ok=True)
    parentfile=target.with_suffix('.parent.csv')
    subprocess.run([sys.executable,str(PARENT/'predict.py'),'--input',str(source),'--out',str(parentfile)],cwd=ROOT,check=True)
    assert sha(parentfile)==policy['baseline_prediction_sha256']
    raw=pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig') if source.suffix.lower()=='.csv' else pd.read_parquet(source)
    result,changes=replay(raw,pd.read_csv(parentfile,dtype=str),read(HERE/'content_decisions.json'),policy)
    result.to_csv(target,index=False,lineterminator='\n');changes.to_csv(target.with_suffix('.changes.csv'),index=False,encoding='utf-8-sig')
    assert sha(target)==policy['expected_prediction_sha256'] and sha(ROOT/'res.csv')==root_sha
    print(json.dumps(dict(status='reproduced',rows=len(result),changes=len(changes),sha256=sha(target),new_API_calls=0),ensure_ascii=False))

if __name__=='__main__':main()
