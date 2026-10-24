"""Recompute the scored parent and replay evidence-gated local review of B."""
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
PARENT=ROOT/'lib/stages/02_fragment_rules'
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT/'lib/stages/01_native_semantic'))
sys.path.insert(0,str(PARENT))
sys.path.insert(0,str(HERE))
from pipeline import sha256,write_json,atomic_csv,validate_submission
from payload_policy_v4 import apply as native_apply,VERSION as NATIVE_VERSION
from semantic8b import view,PROFILE_SHA
from semantic8b_gate import proposal_label,VERSION as GATE_VERSION


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True)
    parser.add_argument('--out',required=True)
    parser.add_argument('--semantic',choices=['reviewed','native_only'],default='reviewed')
    args=parser.parse_args()
    source=Path(args.input).resolve(strict=True);target=Path(args.out).resolve()
    paths={key:target.with_suffix(suffix) for key,suffix in {
        'output':'.csv','parent':'.parent.csv','native':'.native.csv',
        'native_audit':'.native_audit.csv','semantic_audit':'.semantic_audit.csv',
        'changes':'.changes.csv','report':'.report.json'}.items()}
    if any(path.exists() for path in paths.values()):raise FileExistsError('Use a fresh output directory')
    policy=json.loads((HERE/'decision_policy.json').read_text(encoding='utf-8'))
    manifest_file=HERE/'artifact_manifest.json'
    if manifest_file.exists():
        manifest=json.loads(manifest_file.read_text(encoding='utf-8'))
        for name,digest in manifest.items():
            if name.endswith('.py') or name in ['decision_policy.json','semantic8b_cache_manifest.json','semantic8b_frozen.json']:
                if sha256(HERE/name)!=digest:raise ValueError('Frozen runtime changed: '+name)
    for name,digest in policy['parent_artifacts'].items():
        if sha256(PARENT/name)!=digest:raise ValueError('Scored parent artifact changed: '+name)
    cache_meta=json.loads((HERE/'semantic8b_cache_manifest.json').read_text(encoding='utf-8'))
    for name,digest in cache_meta['frozen_dependency_hashes'].items():
        if sha256(HERE/name)!=digest:raise ValueError('Local review dependency changed: '+name)
    if sha256(HERE/'semantic8b_frozen.json')!=cache_meta['frozen_cache_sha256']:
        raise ValueError('Local review cache changed')
    input_hash=sha256(source)
    if input_hash not in cache_meta['allowed_input_hashes']:raise ValueError('Cache is bound to reviewed B content; new input requires new inference')
    if PROFILE_SHA!=cache_meta['profile_sha256']:raise ValueError('Unexpected local-model profile')
    raw=(pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig')
         if source.suffix.lower()=='.csv' else pd.read_parquet(source))
    subprocess.run([sys.executable,str(PARENT/'predict.py'),'--input',str(source),'--out',str(paths['parent'])],cwd=ROOT,check=True)
    if sha256(paths['parent'])!=cache_meta['parent_prediction_sha256']:raise ValueError('Parent model reproduction differs')
    parent=pd.read_csv(paths['parent'],dtype=str,keep_default_na=False)
    validate_submission(parent,raw.event_id)
    if not raw.event_id.equals(parent.event_id):raise ValueError('Parent order mismatch')
    labels,decisions=native_apply(raw,parent.pred_label.to_numpy(dtype=object))
    native=np.asarray(labels,dtype=object)
    native_frame=pd.DataFrame({'event_id':raw.event_id,'pred_label':native})
    atomic_csv(native_frame,paths['native'])
    if sha256(paths['native'])!=cache_meta['native_prediction_sha256']:raise ValueError('Native lineage differs from local model generation')
    native_audit=pd.DataFrame([dict(event_id=raw.event_id.iloc[i],before=parent.pred_label.iloc[i],after=native[i],
        reason=d.reason,context=d.context,evidence_sha256=hashlib.sha256(d.evidence.encode()).hexdigest() if d.evidence else '') for i,d in decisions])
    atomic_csv(native_audit,paths['native_audit'])
    labels=native.copy();semantic_audit=[]
    cache=json.loads((HERE/'semantic8b_frozen.json').read_text(encoding='utf-8'))
    if len(cache)!=cache_meta['total_requests']:raise ValueError('Local review cache count changed')
    for position in raw.index[raw.pipeline.eq('payload') & (native!='malicious')]:
        message=raw.message_sanitized.iloc[position]
        text=view(message)
        if text is None:continue
        key=hashlib.sha256(text.encode()).hexdigest()
        if key not in cache:raise ValueError('Missing local-model request content key')
        result=cache[key]
        if result['prompt_sha256']!=PROFILE_SHA:raise ValueError('Unexpected inference profile')
        proposed,reason=proposal_label(message,result)
        if args.semantic=='reviewed' and proposed is not None and (proposed=='malicious' or labels[position]=='benign'):
            labels[position]=proposed
        semantic_audit.append(dict(event_id=raw.event_id.iloc[position],semantic_key=key,before=native[position],after=labels[position],
            model_label=result.get('label'),confidence=result.get('confidence'),model_reason=result.get('reason',''),
            evidence_anchor_verified=result.get('evidence_anchor_verified'),evidence_sha256=result.get('evidence_sha256',''),
            gate_proposal=proposed,gate_reason=reason,invalid_response='error' in result))
    semantic_audit=pd.DataFrame(semantic_audit)
    atomic_csv(semantic_audit,paths['semantic_audit'])
    payload=raw.pipeline.eq('payload').to_numpy()
    if not np.array_equal(labels[~payload],parent.pred_label.to_numpy()[~payload]):raise ValueError('Non-payload scope violation')
    if not np.array_equal(labels[parent.pred_label.eq('malicious').to_numpy()],parent.pred_label.to_numpy()[parent.pred_label.eq('malicious').to_numpy()]):
        raise ValueError('Existing malicious decision changed')
    result=pd.DataFrame({'event_id':raw.event_id,'pred_label':labels})
    validate_submission(result,raw.event_id)
    atomic_csv(result,target)
    actual=pd.read_csv(target,dtype=str,keep_default_na=False)
    if not actual.equals(result):raise ValueError('CSV roundtrip differs')
    if sha256(source)!=input_hash:raise ValueError('Input changed during inference')
    changes=result.assign(before=parent.pred_label).loc[result.pred_label.ne(parent.pred_label)]
    atomic_csv(changes,paths['changes'])
    native_changes=native_audit[native_audit.before.ne(native_audit.after)]
    semantic_changes=semantic_audit[semantic_audit.before.ne(semantic_audit.after)]
    report=dict(dataset_stage='B',status='generated_unsubmitted',rows=len(raw),input_sha256=input_hash,
        prediction_sha256=sha256(target),label_counts=result.pred_label.value_counts().to_dict(),
        payload_label_counts=result.loc[payload,'pred_label'].value_counts().to_dict(),
        parent_official_score=0.95655532,parent_prediction_sha256=sha256(paths['parent']),
        native_prediction_sha256=sha256(paths['native']),native_changes=len(native_changes),
        native_change_reasons=native_changes.reason.value_counts().to_dict(),
        semantic_mode=args.semantic,semantic_eligible_rows=len(semantic_audit),semantic_distinct_requests=len(cache),
        semantic_changes=len(semantic_changes),semantic_gate_reasons=semantic_audit.gate_reason.value_counts().to_dict(),
        invalid_local_responses=int(semantic_audit.invalid_response.sum()),
        changed_rows_from_scored_best=len(changes),new_threat_predictions=int((parent.pred_label.eq('benign') & result.pred_label.ne('benign')).sum()),
        transitions=changes.groupby(['before','pred_label']).size().reset_index(name='rows').to_dict('records'),
        changed_non_payload_rows=0,native_policy=NATIVE_VERSION,semantic_gate=GATE_VERSION,
        fresh_original_models_recomputed=True,frozen_local_llm_records_replayed=True,
        new_local_llm_generation_repeated_this_run=False,local_llm='Qwen/Qwen3-8B Q4_K_M',
        model_weights_sha256=cache_meta['model_weights_sha256'],semantic_cache_sha256=sha256(HERE/'semantic8b_frozen.json'),
        external_log_inference_used=False,new_training_performed=False,private_answers_read=False,official_B_labels_available=False,
        official_score=None,CSV_reloaded_and_verified=True,input_order_preserved=True,
        limitations=['Manual reviews and author controls are not official B accuracy.',
                     'The independent model suggested many false positives; only evidence-gated proposals are used.',
                     'This pipeline replays frozen local-model outputs; fresh GPU generation may not be byte-identical.',
                     'The three aggregate official scores cannot identify per-row mistakes or guarantee a score above 0.97.'])
    write_json(paths['report'],report)
    print(json.dumps({key:report[key] for key in ['rows','prediction_sha256','label_counts','payload_label_counts','native_changes','semantic_changes','changed_rows_from_scored_best','new_threat_predictions','transitions']},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
