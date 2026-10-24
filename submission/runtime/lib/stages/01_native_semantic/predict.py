"""Recompute native predictions and apply provenance-bound local semantic inference."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'src'))
from pipeline import sha256, write_json, atomic_csv, validate_submission
from semantic_tasks import view
from semantic_gate import eligible_proposal, VERSION as GATE_VERSION


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--probe-mode', choices=['balanced','all_malicious'], default='balanced')
    args = parser.parse_args()
    source = Path(args.input).resolve(strict=True)
    target = Path(args.out).resolve()
    report_path = target.with_suffix('.report.json')
    audit_path = target.with_suffix('.semantic_audit.csv')
    changes_path = target.with_suffix('.semantic_changes.csv')
    native_path = target.with_suffix('.native.csv')
    if any(path.exists() for path in [target,report_path,audit_path,changes_path,native_path]):
        raise FileExistsError('Use a new output path')
    cache_meta = json.loads((HERE/'semantic_cache_manifest.json').read_text(encoding='utf-8'))
    input_hash = sha256(source)
    if input_hash not in cache_meta['allowed_input_hashes']:
        raise ValueError('This semantic cache is bound to the reviewed B content. New data requires fresh local semantic inference.')
    runtime_files = ['semantic_predictions_frozen.json','semantic_cache_manifest.json','semantic_gate.py',
                     'semantic_tasks.py','request_context.py','payload_policy_v2.py','previous_payload_policy.py']
    manifest_path = HERE/'artifact_manifest.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        for name in runtime_files:
            if sha256(HERE/name) != manifest[name]:
                raise ValueError('Frozen semantic artifact changed: '+name)
    raw = (pd.read_csv(source,dtype=str,keep_default_na=False,encoding='utf-8-sig')
           if source.suffix.lower()=='.csv' else pd.read_parquet(source))
    subprocess.run([sys.executable,str(HERE/'native_predict.py'),'--input',str(source),
                    '--expected-input-sha256',input_hash,'--out',str(native_path)],cwd=ROOT,check=True)
    if sha256(native_path) != cache_meta['native_prediction_sha256']:
        raise ValueError('Fresh native predictions differ from the semantic run parent')
    native = pd.read_csv(native_path,dtype=str,keep_default_na=False)
    validate_submission(native,raw.event_id)
    if not raw.event_id.equals(native.event_id):
        raise ValueError('Native/input order mismatch')
    cache = json.loads((HERE/'semantic_predictions_frozen.json').read_text(encoding='utf-8'))
    labels = native.pred_label.to_numpy(dtype=object).copy()
    audit = []
    for position in raw.index[raw.pipeline.eq('payload') & native.pred_label.eq('benign')]:
        message = raw.message_sanitized.iloc[position]
        text = view(message)
        if text is None:
            continue
        key = hashlib.sha256(text.encode()).hexdigest()
        if key not in cache:
            raise ValueError('Missing semantic prediction for an eligible request')
        result = cache[key]
        if result['prompt_sha256'] not in cache_meta['allowed_inference_profiles']:
            raise ValueError('Unexpected semantic inference profile')
        accepted,reason = eligible_proposal(message,result)
        if accepted:
            labels[position] = result['label']
        audit.append({'event_id':raw.event_id.iloc[position],'semantic_key':key,
                      'model_label':result.get('label'),'confidence':result.get('confidence'),
                      'evidence_anchor_verified':result.get('evidence_anchor_verified'),
                      'evidence_sha256':result.get('evidence_sha256',''),
                      'model_reason':result.get('reason',''),'gate_reason':reason,
                      'before':native.pred_label.iloc[position],'after':labels[position],
                      'invalid_response':'error' in result})
    before_probe_mapping = labels.copy()
    if args.probe_mode == 'all_malicious':
        labels[raw.pipeline.eq('payload').to_numpy() & (labels=='suspicious')] = 'malicious'
    mask = raw.pipeline.eq('payload').to_numpy()
    if not np.array_equal(labels[~mask],native.pred_label.to_numpy()[~mask]):
        raise ValueError('Non-payload rows changed')
    result = pd.DataFrame({'event_id':raw.event_id,'pred_label':labels})
    validate_submission(result,raw.event_id)
    atomic_csv(result,target)
    actual = pd.read_csv(target,dtype=str,keep_default_na=False)
    validate_submission(actual,raw.event_id)
    if not actual.equals(result):
        raise ValueError('CSV roundtrip mismatch')
    audit = pd.DataFrame(audit)
    atomic_csv(audit,audit_path)
    changes = audit[audit.before.ne(audit.after)]
    atomic_csv(changes,changes_path)
    report = {
        'dataset_stage':'B','status':'unsubmitted','input':str(source),'input_sha256':input_hash,
        'rows':len(raw),'prediction_sha256':sha256(target),'counts':result.pred_label.value_counts().to_dict(),
        'payload_counts':pd.Series(labels[mask]).value_counts().to_dict(),
        'native_prediction_sha256':sha256(native_path),'fresh_native_models_recomputed':True,
        'semantic_inference_cache_sha256':sha256(HERE/'semantic_predictions_frozen.json'),
        'semantic_cache_manifest_sha256':sha256(HERE/'semantic_cache_manifest.json'),
        'semantic_inference_engine':'local Qwen3-4B-Instruct-2507 Q4_K_M, not fitted on competition answers',
        'semantic_eligible_rows':len(audit),'semantic_changes_from_native':len(changes),
        'semantic_transitions':changes.groupby(['before','after']).size().reset_index(name='rows').to_dict('records'),
        'semantic_gate_version':GATE_VERSION,'semantic_gate_reasons':audit.gate_reason.value_counts().to_dict(),
        'invalid_semantic_responses_retained_native':int(audit.invalid_response.sum()),
        'probe_mode':args.probe_mode,'probe_mapping_changes':int((labels!=before_probe_mapping).sum()),
        'changed_non_payload_rows':0,'csv_reloaded_and_verified':True,'input_order_preserved':True,
        'official_score':None,'development_answers_read':False,'B_labels_available':False,
        'external_log_inference_used':False,'LLM_original_generation_repeated_this_run':False,
        'limitations':['No labeled payload evaluation: model confidence and semantic controls do not establish official accuracy.',
                       'This run replays hashed local-LLM predictions and freshly recomputes the native model stage.',
                       'B score alone does not reveal per-row labels or the correct malicious/suspicious convention.']}
    write_json(report_path,report)
    print(json.dumps({k:report[k] for k in ['rows','prediction_sha256','counts','payload_counts','semantic_changes_from_native','semantic_transitions','probe_mapping_changes']},ensure_ascii=False,indent=2),flush=True)


if __name__=='__main__':main()
