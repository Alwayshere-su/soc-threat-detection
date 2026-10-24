"""Fresh train-only model inference plus contextual payload rules; no ID rules or labels."""
import argparse
import hashlib
import json
from pathlib import Path
import pickle
import sys
import time

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
import base_predict as base
from payload_policy import VERSION, apply
from pipeline import LABELS, atomic_csv, sha256, validate_ids, validate_submission, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--mode', choices=['balanced', 'all_malicious', 'all_suspicious'], default='balanced')
    parser.add_argument('--expected-input-sha256')
    args = parser.parse_args()
    started = time.time()
    source = Path(args.input).resolve(strict=True)
    output = Path(args.out).resolve()
    report_file = output.with_suffix('.report.json')
    audit_file = output.with_suffix('.payload_audit.csv')
    changes_file = output.with_suffix('.changes.csv')
    base_file = output.with_suffix('.base.csv')
    outputs = [output, report_file, audit_file, changes_file, base_file]
    if any(path.exists() for path in outputs):
        raise FileExistsError('Use a fresh output directory; outputs are never overwritten')
    if source in outputs:
        raise ValueError('Output/input collision')
    dependencies = json.loads((HERE / 'project_dependencies.json').read_text(encoding='utf-8'))
    for relative, expected in dependencies.items():
        if sha256(ROOT / relative) != expected:
            raise ValueError('Project dependency changed: ' + relative)
    manifest_path = HERE / 'artifact_manifest.json'
    if manifest_path.exists():
        expected_artifacts = json.loads(manifest_path.read_text(encoding='utf-8'))
        for name in [key for key in expected_artifacts if key.endswith('.py') and not key.startswith('test_')] + ['model.pkl', 'champion_model.pkl']:
            if sha256(HERE / name) != expected_artifacts[name]:
                raise ValueError('Frozen inference artifact changed: ' + name)
    input_hash = sha256(source)
    if args.expected_input_sha256 and input_hash != args.expected_input_sha256:
        raise ValueError('Unexpected input hash')
    raw = (pd.read_csv(source, dtype=str, keep_default_na=False, encoding='utf-8-sig')
           if source.suffix.lower() == '.csv' else pd.read_parquet(source))
    required = {'event_id', 'message_sanitized', 'pipeline', 'product_name', 'vendor_name',
                'src_ip', 'dst_ip', 'src_host', 'dst_host', 'username', 'src_port', 'timestamp'}
    if not required.issubset(raw.columns) or {'label', 'label_binary', 'pred_label'} & set(raw.columns):
        raise ValueError('Expected unlabeled official input schema')
    validate_ids(raw.event_id)
    if raw.empty:
        raise ValueError('Empty input')
    semantic = pickle.loads((HERE / 'model.pkl').read_bytes())
    champion = pickle.loads((HERE / 'champion_model.pkl').read_bytes())
    if semantic['metadata']['feature_code_sha256'] != sha256(HERE / 'semantic_features.py'):
        raise ValueError('Model/feature code mismatch')
    features = base.fresh_features(raw)
    old_prob = base.probabilities(champion, features)
    new_prob = base.probabilities(semantic, features)
    original = base.champion_decision(old_prob, features)
    before = base.route(features, original, base.keyword_decision(new_prob, features))
    after, decisions = apply(raw, before)
    if args.mode != 'balanced':
        mapped_label = 'malicious' if args.mode == 'all_malicious' else 'suspicious'
        for position, decision in decisions:
            if decision.label is not None and before[position] != 'malicious':
                after[position] = mapped_label
    after = np.asarray(after, dtype=object)
    payload = raw.pipeline.eq('payload').to_numpy()
    if not np.array_equal(after[~payload], before[~payload]):
        raise ValueError('Non-payload predictions changed')
    audit = []
    for position, decision in decisions:
        audit.append({'event_id': raw.event_id.iloc[position], 'before': before[position],
                      'after': after[position], 'semantic_label': decision.label,
                      'reason': decision.reason, 'context': decision.context,
                      'evidence_sha256': hashlib.sha256(decision.evidence.encode('utf-8')).hexdigest() if decision.evidence else ''})
    audit = pd.DataFrame(audit, columns=['event_id', 'before', 'after', 'semantic_label', 'reason', 'context', 'evidence_sha256'])
    result = pd.DataFrame({'event_id': raw.event_id, 'pred_label': after})
    baseline = pd.DataFrame({'event_id': raw.event_id, 'pred_label': before})
    validate_submission(result, raw.event_id)
    validate_submission(baseline, raw.event_id)
    if sha256(source) != input_hash:
        raise ValueError('Input changed while predicting')
    atomic_csv(result, output)
    actual = pd.read_csv(output, dtype=str, keep_default_na=False)
    validate_submission(actual, raw.event_id)
    if not actual.equals(result):
        raise ValueError('CSV roundtrip mismatch')
    atomic_csv(baseline, base_file)
    atomic_csv(audit, audit_file)
    changes = audit.loc[audit.before.ne(audit.after)].copy()
    atomic_csv(changes, changes_file)
    report = {
        'dataset_stage': 'B', 'status': 'generated_unsubmitted', 'input': str(source), 'input_sha256': input_hash,
        'rows': len(raw), 'columns': ['event_id', 'pred_label'], 'prediction_sha256': sha256(output),
        'prediction_counts': result.pred_label.value_counts().to_dict(), 'payload_rows': int(payload.sum()),
        'payload_prediction_counts': pd.Series(after[payload]).value_counts().to_dict(),
        'payload_policy_version': VERSION, 'mode': args.mode, 'changed_rows_from_semantic_guarded': len(changes),
        'changed_non_payload_rows': int((after[~payload] != before[~payload]).sum()),
        'change_reasons': changes.reason.value_counts().to_dict(),
        'transitions': changes.groupby(['before', 'after']).size().reset_index(name='rows').to_dict('records'),
        'model_sha256': sha256(HERE / 'model.pkl'), 'champion_model_sha256': sha256(HERE / 'champion_model.pkl'),
        'inference_code_sha256': sha256(Path(__file__)), 'payload_code_sha256': sha256(HERE / 'payload_policy.py'),
        'payload_extension_code_sha256': sha256(HERE / 'payload_policy_v2.py'),
        'base_prediction_sha256': sha256(base_file), 'csv_reloaded_and_verified': True,
        'input_order_preserved': True, 'id_coverage_verified': True,
        'training_scope': 'Frozen official-training-only models; no extra fitting or early stopping',
        'development_answer_read': False, 'B_labels_available': False, 'official_score': None,
        'A_cache_used': False, 'prediction_cache_used': False,
        'audit_evidence_storage': 'Only event IDs, rule reasons, context and one-way evidence hashes; no raw attack text copied into CSV audits',
        'limitations': [
            'Payload rules are security-semantic hypotheses without labeled payload validation.',
            'Request evidence does not prove exploitation succeeded or reveal the official class convention.',
            'Rules were developed after examining unlabeled B examples; manual controls do not estimate B accuracy.',
            'Uncertain requests retain base predictions; known original keyword decisions are not automatically downgraded.'
        ],
        'seconds': time.time() - started}
    write_json(report_file, report)
    print(json.dumps({k: report[k] for k in ['rows', 'prediction_sha256', 'prediction_counts',
                                           'payload_prediction_counts', 'changed_rows_from_semantic_guarded',
                                           'changed_non_payload_rows', 'change_reasons']}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
