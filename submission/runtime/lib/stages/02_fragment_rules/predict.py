"""Freshly reconstruct the scored second B version, then apply fragment coverage and selective subclasses."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import pandas as pd

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT/'lib/stages/01_native_semantic'))
sys.path.insert(0,str(HERE))
from pipeline import sha256,write_json,validate_submission,atomic_csv
from payload_policy_v3 import VERSION,apply
from selective_subclass import apply as selective_apply, VERSION as SUBCLASS_VERSION

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True)
    parser.add_argument('--out',required=True)
    parser.add_argument('--probe-mode',choices=['balanced','selective','all_malicious'],default='selective')
    args=parser.parse_args()
    source=Path(args.input).resolve(strict=True)
    output=Path(args.out).resolve()
    for suffix in ['.csv','.parent.csv','.balanced.csv','.audit.csv','.subclass_audit.csv','.report.json']:
        if output.with_suffix(suffix).exists():raise FileExistsError('Use a fresh output directory')
    meta=json.loads((HERE/'decision_policy.json').read_text(encoding='utf-8'))
    if sha256(source) not in meta['allowed_input_hashes']:raise ValueError('Input must be the verified B input')
    parent=ROOT/'lib/stages/01_native_semantic'
    for name,digest in meta['parent_artifacts'].items():
        if sha256(parent/name)!=digest:raise ValueError('Scored parent artifact changed: '+name)
    manifest=HERE/'artifact_manifest.json'
    if manifest.exists():
        for name,digest in json.loads(manifest.read_text(encoding='utf-8')).items():
            if name.endswith('.py') or name=='decision_policy.json':
                if sha256(HERE/name)!=digest:raise ValueError('Frozen third-version artifact changed: '+name)
    raw=(pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig')
         if source.suffix.lower()=='.csv' else pd.read_parquet(source))
    parent_csv=output.with_suffix('.parent.csv')
    subprocess.run([sys.executable,str(parent/'predict.py'),'--input',str(source),'--out',str(parent_csv)],cwd=ROOT,check=True)
    if sha256(parent_csv)!=meta['parent_prediction_sha256']:raise ValueError('Parent reproduction differs')
    before=pd.read_csv(parent_csv,dtype=str)
    validate_submission(before,raw.event_id)
    if not before.event_id.equals(raw.event_id):raise ValueError('Parent input order mismatch')
    labels,decisions=apply(raw,before.pred_label.to_numpy(dtype=object))
    balanced=np.asarray(labels,dtype=object)
    labels=balanced.copy()
    payload=raw.pipeline.eq('payload').to_numpy()
    subclass_decisions=[]
    if args.probe_mode=='selective':
        labels,subclass_decisions=selective_apply(raw,balanced)
        labels=np.asarray(labels,dtype=object)
    elif args.probe_mode=='all_malicious':
        labels[payload & (labels=='suspicious')]='malicious'
    subclass_audit=pd.DataFrame([dict(event_id=raw.event_id.iloc[i],before=balanced[i],after=labels[i],
        reason=d.reason,evidence_sha256=hashlib.sha256(d.evidence.encode()).hexdigest() if d.evidence else '')
        for i,d in subclass_decisions],columns=['event_id','before','after','reason','evidence_sha256'])
    atomic_csv(subclass_audit,output.with_suffix('.subclass_audit.csv'))
    if not np.array_equal(labels[~payload],before.pred_label.to_numpy()[~payload]):raise ValueError('Non-payload scope violation')
    result=pd.DataFrame({'event_id':raw.event_id,'pred_label':labels})
    validate_submission(result,raw.event_id)
    atomic_csv(result,output)
    actual=pd.read_csv(output,dtype=str)
    if not actual.equals(result):raise ValueError('Roundtrip changed output')
    atomic_csv(pd.DataFrame({'event_id':raw.event_id,'pred_label':balanced}),output.with_suffix('.balanced.csv'))
    audit=pd.DataFrame([dict(event_id=raw.event_id.iloc[i],before=before.pred_label.iloc[i],
                            balanced=balanced[i],after=labels[i],reason=d.reason,context=d.context,
                            evidence_sha256=hashlib.sha256(d.evidence.encode()).hexdigest() if d.evidence else '')
                        for i,d in decisions])
    atomic_csv(audit,output.with_suffix('.audit.csv'))
    changes=result.assign(before=before.pred_label).loc[result.pred_label.ne(before.pred_label)]
    new_coverage=audit[audit.before.ne(audit.balanced)]
    report=dict(dataset_stage='B',status='unsubmitted',rows=len(result),input_sha256=sha256(source),
        prediction_sha256=sha256(output),parent_official_score=0.94865293,parent_sha256=sha256(parent_csv),
        prediction_counts=result.pred_label.value_counts().to_dict(),
        payload_counts=result.loc[payload,'pred_label'].value_counts().to_dict(),
        additional_threat_predictions=len(new_coverage),coverage_reasons=new_coverage.reason.value_counts().to_dict(),
        threat_subclass_mapping_changes=int((labels!=balanced).sum()),probe_mode=args.probe_mode,
        changes_from_scored_parent=len(changes),transitions=changes.groupby(['before','pred_label']).size().reset_index(name='rows').to_dict('records'),
        policy_version=VERSION,subclass_policy=SUBCLASS_VERSION,changed_non_payload_rows=0,parent_recomputed=True,
        retained_payload_suspicious=int((payload & (labels=='suspicious')).sum()),
        subclass_promotion_reasons=subclass_audit.loc[subclass_audit.before.ne(subclass_audit.after),'reason'].value_counts().to_dict(),
        private_answers_read=False,official_B_labels_available=False,official_score=None,
        external_model_inference_used=False,parent_local_model_cache_replayed=True,
        limitations=['New detections and subclass mapping are hypotheses, not proven corrections.',
                     'The two known aggregate scores do not determine per-row labels.',
                     'Casefolded-base64 signatures are byte-pattern matches, not lossless decoding.',
                     'Selective subclasses follow evidence strength but remain unvalidated against official B labels.'])
    write_json(output.with_suffix('.report.json'),report)
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
