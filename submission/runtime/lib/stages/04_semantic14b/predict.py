"""Recompute scored parent, recover direct evidence, and replay gated local review."""
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
PARENT=ROOT/'lib/stages/03_semantic8b'
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(PARENT))
import semantic8b
sys.path.insert(0,str(HERE))
from pipeline import sha256,write_json,atomic_csv,validate_submission
from payload_policy_v5 import apply as native_apply,VERSION as NATIVE_VERSION
from default_credential_probe import apply as default_apply,VERSION as DEFAULT_VERSION
from outer_context_guard import apply as outer_apply,VERSION as OUTER_VERSION
from semantic14b import view,PROFILE_SHA
from semantic14b_gate import proposal,VERSION as SEMANTIC_VERSION

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True);parser.add_argument('--out',required=True)
    parser.add_argument('--semantic',choices=['reviewed','native_only'],default='reviewed')
    args=parser.parse_args()
    source=Path(args.input).resolve(strict=True);target=Path(args.out).resolve()
    if target==source:raise ValueError('Output must differ from input')
    suffixes=['.csv','.parent.csv','.native.csv','.native_audit.csv','.default_audit.csv','.outer_audit.csv','.semantic_audit.csv','.changes.csv','.report.json']
    if any(target.with_suffix(suffix).exists() for suffix in suffixes):raise FileExistsError('Use a fresh output directory')
    policy=json.loads((HERE/'decision_policy.json').read_text(encoding='utf-8'))
    for name,digest in policy['parent_artifacts'].items():
        if sha256(PARENT/name)!=digest:raise ValueError('Scored parent changed: '+name)
    manifest_path=HERE/'artifact_manifest.json'
    if manifest_path.exists():
        for name,digest in json.loads(manifest_path.read_text(encoding='utf-8')).items():
            if name.endswith('.py') or name in ['decision_policy.json','semantic14b_cache_manifest.json','semantic14b_frozen.json']:
                if sha256(HERE/name)!=digest:raise ValueError('Frozen runtime changed: '+name)
    meta=json.loads((HERE/'semantic14b_cache_manifest.json').read_text(encoding='utf-8'))
    for name,digest in meta['frozen_dependency_hashes'].items():
        if sha256(HERE/name)!=digest:raise ValueError('Local review dependency changed: '+name)
    if sha256(HERE/'semantic14b_frozen.json')!=meta['frozen_cache_sha256']:raise ValueError('Local-model cache changed')
    if meta['profile_sha256']!=PROFILE_SHA:raise ValueError('Unexpected local-model profile')
    input_hash=sha256(source)
    if input_hash not in meta['allowed_input_hashes']:raise ValueError('Input must be reviewed B data')
    raw=(pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig') if source.suffix.lower()=='.csv' else pd.read_parquet(source))
    parent_file=target.with_suffix('.parent.csv')
    subprocess.run([sys.executable,str(PARENT/'predict.py'),'--input',str(source),'--out',str(parent_file)],cwd=ROOT,check=True)
    if sha256(parent_file)!=meta['parent_prediction_sha256']:raise ValueError('Scored parent reproduction differs')
    parent=pd.read_csv(parent_file,dtype=str,keep_default_na=False);validate_submission(parent,raw.event_id)
    if not parent.event_id.equals(raw.event_id):raise ValueError('Input order mismatch')
    labels,native=native_apply(raw,parent.pred_label.to_numpy(dtype=object))
    native_audit=pd.DataFrame([dict(event_id=raw.event_id.iloc[i],before=parent.pred_label.iloc[i],after=labels[i],
        reason=d.reason,context=d.context,evidence_sha256=hashlib.sha256(d.evidence.encode()).hexdigest()) for i,d in native])
    labels_before=list(labels);labels,defaults=default_apply(raw,labels)
    default_audit=pd.DataFrame([dict(event_id=raw.event_id.iloc[i],before=labels_before[i],after=labels[i],reason=d.reason) for i,d in defaults],columns=['event_id','before','after','reason'])
    labels_before=list(labels);labels,outer=outer_apply(raw,labels)
    outer_audit=pd.DataFrame([dict(event_id=raw.event_id.iloc[i],before=labels_before[i],after=labels[i],reason=d.reason,
        evidence_sha256=hashlib.sha256(d.evidence.encode()).hexdigest()) for i,d in outer],columns=['event_id','before','after','reason','evidence_sha256'])
    for audit,suffix in [(native_audit,'.native_audit.csv'),(default_audit,'.default_audit.csv'),(outer_audit,'.outer_audit.csv')]:atomic_csv(audit,target.with_suffix(suffix))
    atomic_csv(pd.DataFrame(dict(event_id=raw.event_id,pred_label=labels)),target.with_suffix('.native.csv'))
    if sha256(target.with_suffix('.native.csv'))!=meta['intermediate_native_sha256']:raise ValueError('Native stage reproduction differs')
    cache=json.loads((HERE/'semantic14b_frozen.json').read_text(encoding='utf-8'))
    if len(cache)!=meta['total_requests']:raise ValueError('Incomplete local-model cache')
    semantic_audit=[];used=set()
    for position in raw.index[raw.pipeline.eq('payload') & parent.pred_label.ne('malicious')]:
        message=raw.message_sanitized.iloc[position];text=view(message)
        if text is None:continue
        key=hashlib.sha256(text.encode()).hexdigest()
        if key not in cache:raise ValueError('Unreviewed request view')
        result=cache[key];used.add(key)
        if 'error' in result or result.get('prompt_sha256')!=PROFILE_SHA:raise ValueError('Invalid local review response')
        before=labels[position];proposed,why=proposal(message,result)
        if args.semantic=='reviewed' and proposed is not None and (proposed=='malicious' or labels[position]=='benign'):labels[position]=proposed
        semantic_audit.append(dict(event_id=raw.event_id.iloc[position],semantic_key=key,before=before,after=labels[position],
            model_label=result['label'],confidence=result['confidence'],reason=result.get('reason',''),
            evidence_anchor_verified=result.get('evidence_anchor_verified'),evidence_sha256=result.get('evidence_sha256',''),
            gate_label=proposed,gate_reason=why))
    if len(used)!=len(cache):raise ValueError('Unexpected or unused cached requests')
    semantic_audit=pd.DataFrame(semantic_audit);atomic_csv(semantic_audit,target.with_suffix('.semantic_audit.csv'))
    labels=np.asarray(labels,dtype=object);payload=raw.pipeline.eq('payload').to_numpy()
    if not np.array_equal(labels[~payload],parent.pred_label.to_numpy()[~payload]):raise ValueError('Core 50000 scope violation')
    allowed_downgrades={i for i,_ in outer}
    changed_mal=np.flatnonzero(parent.pred_label.eq('malicious').to_numpy() & (labels!='malicious'))
    if any(i not in allowed_downgrades or labels[i]!='benign' for i in changed_mal):raise ValueError('Unexplained malicious downgrade')
    result=pd.DataFrame(dict(event_id=raw.event_id,pred_label=labels));validate_submission(result,raw.event_id)
    atomic_csv(result,target)
    if not pd.read_csv(target,dtype=str,keep_default_na=False).equals(result):raise ValueError('CSV roundtrip changed')
    if sha256(source)!=input_hash:raise ValueError('Input changed during inference')
    changes=result.assign(before=parent.pred_label).loc[result.pred_label.ne(parent.pred_label)];atomic_csv(changes,target.with_suffix('.changes.csv'))
    report=dict(dataset_stage='B',status='prepared_unsubmitted',rows=len(raw),input_sha256=input_hash,
        prediction_sha256=sha256(target),label_counts=result.pred_label.value_counts().to_dict(),
        payload_label_counts=result.loc[payload,'pred_label'].value_counts().to_dict(),
        parent_official_score=0.96164352,parent_prediction_sha256=sha256(parent_file),
        changed_rows_from_scored_best=len(changes),transitions=changes.groupby(['before','pred_label']).size().reset_index(name='rows').to_dict('records'),
        native_recovery_changes=len(native),default_credential_changes=len(defaults),outer_context_corrections=len(outer),
        semantic_changes=int(semantic_audit.before.ne(semantic_audit.after).sum()),semantic_affected_rows=len(semantic_audit),semantic_distinct_requests=len(cache),
        new_threat_predictions=int((parent.pred_label.eq('benign') & result.pred_label.ne('benign')).sum()),
        threat_to_benign_context_corrections=len(changed_mal),non_payload_rows_unchanged=50000,core7_not_merged=True,
        native_policy=NATIVE_VERSION,default_policy=DEFAULT_VERSION,outer_policy=OUTER_VERSION,semantic_gate=SEMANTIC_VERSION,semantic_mode=args.semantic,
        fresh_original_models_recomputed=True,frozen_local_llm_records_replayed=True,fresh_local_generation_repeated_this_run=False,
        local_model='Qwen/Qwen3-14B IQ3_XS',model_weights_sha256=meta['model_weights_sha256'],semantic_cache_sha256=sha256(HERE/'semantic14b_frozen.json'),
        private_answers_read=False,official_B_labels_available=False,new_training_performed=False,external_log_inference_used=False,
        official_score=None,CSV_reloaded_and_verified=True,input_order_preserved=True,
        limitations=['No official B per-row labels; manual judgements and author controls are not accuracy estimates.',
            'Frozen local-model replay is reproducible; fresh GPU generation may vary.',
            'No guaranteed score or top-10 rank; the leaderboard threshold can change.'])
    write_json(target.with_suffix('.report.json'),report)
    print(json.dumps({key:report[key] for key in ['rows','prediction_sha256','label_counts','payload_label_counts','changed_rows_from_scored_best','native_recovery_changes','default_credential_changes','outer_context_corrections','semantic_changes','transitions']},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
