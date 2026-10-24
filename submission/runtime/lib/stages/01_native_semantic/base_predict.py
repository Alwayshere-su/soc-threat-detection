"""Reproducible semantic candidate, optionally routed over the scored champion."""
import argparse,json,pickle,sys,time
from pathlib import Path
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from fe import build_features
from pipeline import LABELS,encode_features,sha256,write_json,atomic_csv,validate_submission,align_truth,metrics
from score import THREAT_TOKEN_RE
from semantic_features import VERSION,extras
from model_utils import predict_compact

def probabilities(model,frame):
    X=encode_features(frame,model['cats'],model['common_cols'])
    models=model.get('models') or [model['clf']]
    p=np.zeros((len(frame),3))
    for clf in models:
        clf.set_params(n_jobs=6)
        if list(clf.classes_)!=[0,1,2]:raise ValueError('Class order mismatch')
        p+=predict_compact(clf,X)/len(models)
    return p*np.asarray(model.get('coef',[1.,1.,1.]))

def keyword_decision(p,frame):
    pred=np.asarray(LABELS,dtype=object)[p.argmax(1)]
    pred[(pred=='benign')&frame.aux_threat_hit.to_numpy().astype(bool)]='malicious'
    return pred

def champion_decision(p,frame):
    pred=keyword_decision(p,frame)
    mask=(pred=='benign')&frame.aux_winlogbeat_guard.to_numpy().astype(bool)&(6*p[:,2]>np.maximum(p[:,0],p[:,1]))
    pred[mask]='malicious'
    return pred

def route(frame,base,proposal):
    win=(frame.aux_winlogbeat_guard.to_numpy().astype(bool)&frame.effective_win_event_id.eq(4625).to_numpy()&frame.audit_failure.eq(1).to_numpy())
    guard=win | (
        frame.pipeline.fillna('').eq('syslog').to_numpy() & frame.meta_product_missing.eq(1).to_numpy() & frame.family_duo.eq(1).to_numpy())
    final=np.asarray(base,dtype=object).copy()
    mask=guard&(final=='benign')&(proposal=='malicious')
    final[mask]='malicious'
    return final

def fresh_features(raw):
    base=build_features(raw)
    sem=extras(raw,base)
    frame=pd.concat([base,sem],axis=1)
    frame.insert(0,'event_id',raw.event_id.to_numpy())
    frame['aux_threat_hit']=raw.message_sanitized.fillna('').astype('string[pyarrow]').str.contains(THREAT_TOKEN_RE,case=False,regex=True).astype(np.int8)
    frame['aux_winlogbeat_guard']=(raw.pipeline.fillna('').eq('syslog')&raw.product_name.fillna('').astype(str).str.strip().eq('')&base.is_elk_json.eq(1)).astype(np.int8)
    frame['aux_source_family']=np.select([sem.family_duo.eq(1),base.is_elk_json.eq(1),base.is_cef.eq(1)],['duo','winlogbeat','cef'],default='other')
    return frame

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--input',required=True)
    ap.add_argument('--model',default=str(HERE/'model.pkl'))
    ap.add_argument('--mode',choices=['global','source_router'],default='source_router')
    ap.add_argument('--duo-weight',type=float,choices=[1.,3.],default=1.)
    ap.add_argument('--champion-model',default=str(HERE/'champion_model.pkl' if (HERE/'champion_model.pkl').exists() else ROOT/'exp/model_ensemble.pkl'))
    ap.add_argument('--out',required=True)
    ap.add_argument('--features')
    ap.add_argument('--baseline')
    ap.add_argument('--baseline-sha256')
    ap.add_argument('--answer')
    args=ap.parse_args()
    if args.mode=='global' and args.duo_weight!=1.:raise ValueError('Duo calibration is source-router-only')
    output=Path(args.out)
    report_path=output.with_suffix('.report.json')
    changes_path=output.with_name(output.stem+'.changes.csv')
    prob_path=output.with_suffix('.probabilities.npy')
    for p in [output,report_path,changes_path,prob_path]:
        if p.exists():raise FileExistsError(p)
    inputs={Path(p).resolve() for p in [args.input,args.model,args.champion_model,args.features,args.baseline,args.answer] if p}
    if any(p.resolve() in inputs for p in [output,report_path,changes_path,prob_path]):raise ValueError('Output/input collision')
    model=pickle.loads(Path(args.model).read_bytes())
    if model['feature_version']!=VERSION or model['metadata']['feature_code_sha256']!=sha256(HERE/'semantic_features.py'):
        raise ValueError('Semantic feature/model version mismatch')
    champion=pickle.loads(Path(args.champion_model).read_bytes())
    input_hash=sha256(args.input)
    baseline=None
    if args.baseline:
        if not args.baseline_sha256 or sha256(args.baseline)!=args.baseline_sha256:raise ValueError('Baseline hash required/mismatch')
        baseline=pd.read_csv(args.baseline)
    if args.features:
        meta=json.loads(Path(args.features).with_suffix('.json').read_text(encoding='utf-8-sig'))
        if (meta['source_sha256']!=input_hash or meta['feature_version']!=VERSION or
            meta['sha256']!=sha256(args.features) or meta['extra_source_sha256']!=sha256(HERE/'semantic_features.py')):
            raise ValueError('Feature cache provenance mismatch')
        batches=pq.ParquetFile(args.features).iter_batches(batch_size=50000)
        ids=pd.read_parquet(args.input,columns=['event_id']).event_id
    else:
        batches=pq.ParquetFile(args.input).iter_batches(batch_size=25000)
        ids=pd.read_parquet(args.input,columns=['event_id']).event_id
    results=[];changes=[];position=0;probability_parts=[];start=time.time()
    for number,batch in enumerate(batches,1):
        data=batch.to_pandas()
        frame=data if args.features else fresh_features(data)
        end=position+len(frame)
        if not np.array_equal(frame.event_id.to_numpy(),ids.iloc[position:end].to_numpy()):raise ValueError('Feature/input IDs differ')
        if baseline is not None:
            if not np.array_equal(frame.event_id.to_numpy(),baseline.event_id.iloc[position:end].to_numpy()):raise ValueError('Baseline/input IDs differ')
            before=baseline.pred_label.iloc[position:end].to_numpy()
        else:before=champion_decision(probabilities(champion,frame),frame)
        p=probabilities(model,frame)
        decision_p=p
        if args.duo_weight!=1.:
            decision_p=p.copy()
            duo=frame.meta_product_missing.eq(1).to_numpy()&frame.family_duo.eq(1).to_numpy()
            decision_p[duo,2]*=args.duo_weight
        proposal=keyword_decision(decision_p,frame)
        pred=proposal if args.mode=='global' else route(frame,before,proposal)
        results.append(pd.DataFrame({'event_id':frame.event_id.to_numpy(),'pred_label':pred}))
        probability_parts.append(p)
        mask=pred!=before
        if mask.any():
            detail=frame.loc[mask,['event_id','pipeline','product_name','vendor_name','aux_source_family','family_duo','meta_product_missing','is_elk_json','is_cef']].copy()
            detail['before']=before[mask];detail['after']=pred[mask]
            for i,label in enumerate(LABELS):detail['new_p_'+label]=p[mask,i]
            changes.append(detail)
        position=end
        if position%500000==0:print(args.mode,'rows',position,'seconds',round(time.time()-start,1),flush=True)
    if position!=len(ids):raise ValueError('Incomplete input/cache')
    result=pd.concat(results,ignore_index=True)
    validate_submission(result,ids)
    if baseline is not None:validate_submission(baseline,ids)
    atomic_csv(result,output)
    actual=pd.read_csv(output)
    validate_submission(actual,ids)
    if not actual.equals(result):raise ValueError('CSV serialization mismatch')
    detail=pd.concat(changes,ignore_index=True) if changes else pd.DataFrame(columns=['event_id','before','after'])
    detail.to_csv(changes_path,index=False)
    np.save(prob_path,np.concatenate(probability_parts))
    report={'input':str(Path(args.input).resolve()),'input_sha256':input_hash,'rows':len(ids),
        'model_sha256':sha256(args.model),'champion_model_sha256':sha256(args.champion_model),
        'mode':args.mode,'duo_malicious_weight':args.duo_weight,'changed_rows_from_champion':len(detail),'prediction_counts':result.pred_label.value_counts().to_dict(),
        'prediction_sha256':sha256(output),'probabilities_sha256':sha256(prob_path),
        'csv_reloaded_and_verified':True,'input_order_preserved':True,'labels_available':bool(args.answer),
        'official_score':None,'seconds':time.time()-start,'training_scope':'official train only; development answers evaluation-only',
        'feature_version':VERSION,'feature_source_sha256':sha256(HERE/'semantic_features.py'),
        'feature_cache':str(Path(args.features).resolve()) if args.features else None,
        'feature_cache_sha256':sha256(args.features) if args.features else None,
        'change_sources':detail.groupby(['aux_source_family','before','after']).size().reset_index(name='count').to_dict('records') if len(detail) else [],
        'source_router_rule':'Only upgrade champion benign when new model says malicious and source is missing-product Duo, or missing-product Winlogbeat with event code 4625 and failure evidence; no record-ID list.'}
    if args.answer:
        y=align_truth(pd.read_parquet(args.answer),ids)
        report['evaluation']=metrics(y,result.pred_label.to_numpy())
    write_json(report_path,report)
    print('DONE',json.dumps({k:report[k] for k in ['mode','rows','changed_rows_from_champion','prediction_sha256']},ensure_ascii=False),flush=True)

if __name__=='__main__':main()
