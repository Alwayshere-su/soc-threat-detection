"""Replay the frozen56 model chain, then apply content-verified family refinements."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
import pandas as pd
from family_policy import assess

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
PARENT=ROOT/'lib/stages/09_content_evidence'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))


def replay(raw,parent,decisions,policy):
    assert raw.event_id.equals(parent.event_id) and raw.event_id.is_unique
    result=parent.copy();used=set();changes=[]
    for i,r in enumerate(raw.itertuples(index=False)):
        if r.pipeline!='payload':continue
        key=hashlib.sha256(r.message_sanitized.encode()).hexdigest()
        if key not in decisions:continue
        expected=decisions[key];finding=assess(r.message_sanitized)
        assert finding and finding.label==expected['after'] and finding.category==expected['category']
        assert hashlib.sha256(finding.evidence.encode()).hexdigest()==expected['evidence_sha256']
        before=result.pred_label.iloc[i];assert before==expected['before']
        assert before in ['benign','suspicious'] and finding.label in ['suspicious','malicious']
        assert before!=finding.label and (before!='suspicious' or finding.label=='malicious')
        result.loc[i,'pred_label']=finding.label;used.add(key)
        changes.append({'event_id':r.event_id,'before':before,'after':finding.label,
            'category':finding.category,'reason':finding.reason,'reference':finding.reference,
            'content_sha256':key,'evidence_sha256':expected['evidence_sha256']})
    assert len(changes)==policy['new_rows'] and len(used)==policy['new_content_keys']
    core=raw.pipeline.ne('payload');assert int(core.sum())==50000 and result.loc[core].equals(parent.loc[core])
    return result,pd.DataFrame(changes)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--input',required=True);parser.add_argument('--out',required=True);a=parser.parse_args()
    source=Path(a.input).resolve(strict=True);out=Path(a.out).resolve()
    policy=read(HERE/'decision_policy.json')
    assert sha(source) in policy['allowed_input_hashes']
    assert not out.exists() and out!=ROOT/'res.csv' and source!=out
    for name,digest in read(HERE/'artifact_manifest.json').items():assert sha(HERE/name)==digest,name
    for name,digest in policy['parent_artifacts'].items():assert sha(PARENT/name)==digest,name
    before=sha(ROOT/'res.csv');out.parent.mkdir(parents=True,exist_ok=True)
    parentfile=out.with_suffix('.parent56.csv');assert not parentfile.exists()
    subprocess.run([sys.executable,str(PARENT/'predict.py'),'--input',str(source),'--out',str(parentfile)],cwd=ROOT,check=True)
    assert sha(parentfile)==policy['parent_prediction_sha256']
    raw=pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig') if source.suffix.lower()=='.csv' else pd.read_parquet(source)
    result,changes=replay(raw,pd.read_csv(parentfile,dtype=str),read(HERE/'content_decisions.json'),policy)
    result.to_csv(out,index=False,lineterminator='\n');changes.to_csv(out.with_suffix('.changes.csv'),index=False,encoding='utf-8-sig')
    assert sha(out)==policy['prediction_sha256'] and sha(ROOT/'res.csv')==before
    print(json.dumps({'status':'reproduced','rows':len(result),'new_changes_from56':len(changes),'sha256':sha(out)}))


if __name__=='__main__':main()
