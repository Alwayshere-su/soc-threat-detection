"""Reproduce deep148, withdraw one unsubstantiated probe and apply five additional evidence decisions."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
import pandas as pd
from followup_policy import assess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
PARENT=ROOT/'lib/stages/13_deep_rules'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))

def replay(raw,parent,decisions,policy):
    assert raw.event_id.equals(parent.event_id) and raw.event_id.is_unique
    result=parent.copy();used=set();changes=[]
    for i,r in enumerate(raw.itertuples(index=False)):
        if r.pipeline!='payload':continue
        key=hashlib.sha256(r.message_sanitized.encode()).hexdigest()
        if key not in decisions:continue
        expected=decisions[key];f=assess(r.message_sanitized)
        assert f and f.label==expected['after'] and f.category==expected['category']
        assert hashlib.sha256(f.evidence.encode()).hexdigest()==expected['evidence_sha256']
        before=result.pred_label.iloc[i];assert before==expected['before'] and before!=f.label
        assert (before,f.label) in [('benign','malicious'),('benign','suspicious'),('suspicious','benign')]
        if f.label=='benign':assert f.category=='withdraw_kubeview_route_only_probe'
        result.loc[i,'pred_label']=f.label;used.add(key)
        changes.append(dict(event_id=r.event_id,before=before,after=f.label,category=f.category,
            reason=f.reason,reference=f.reference,content_sha256=key,evidence_sha256=expected['evidence_sha256']))
    assert len(changes)==policy['new_rows'] and len(used)==policy['new_content_keys']
    core=raw.pipeline.ne('payload');assert int(core.sum())==50000
    assert result.loc[core].equals(parent.loc[core])
    return result,pd.DataFrame(changes)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    source=Path(a.input).resolve(strict=True);out=Path(a.out).resolve()
    policy=read(HERE/'decision_policy.json')
    assert sha(source) in policy['allowed_input_hashes']
    assert not out.exists() and out!=ROOT/'res.csv' and out!=source
    for name,digest in read(HERE/'artifact_manifest.json').items():assert sha(HERE/name)==digest,name
    for name,digest in policy['parent_artifacts'].items():assert sha(PARENT/name)==digest,name
    baseline_sha=sha(ROOT/'res.csv');out.parent.mkdir(parents=True,exist_ok=True)
    parentfile=out.with_suffix('.parent148.csv');assert not parentfile.exists()
    subprocess.run([sys.executable,str(PARENT/'predict.py'),'--input',str(source),'--out',str(parentfile)],cwd=ROOT,check=True)
    assert sha(parentfile)==policy['parent_prediction_sha256']
    raw=pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig') if source.suffix.lower()=='.csv' else pd.read_parquet(source)
    result,changes=replay(raw,pd.read_csv(parentfile,dtype=str),read(HERE/'content_decisions.json'),policy)
    result.to_csv(out,index=False,lineterminator='\n')
    assert sha(out)==policy['prediction_sha256'] and sha(ROOT/'res.csv')==baseline_sha
    print(json.dumps(dict(status='reproduced',rows=len(result),new_changes=6,sha256=sha(out))))
if __name__=='__main__':main()
