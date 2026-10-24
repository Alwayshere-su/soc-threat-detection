import sys
from pathlib import Path
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'src'))
from pipeline import LABELS,encode_features,metrics

def predict_compact(clf,X):
    arr=X.to_numpy(dtype=np.float32)
    values,indices,inverse=np.unique(arr,axis=0,return_index=True,return_inverse=True)
    unique=X.iloc[indices]
    p=clf.predict_proba(unique)[inverse]
    sample=np.unique(np.linspace(0,len(X)-1,min(64,len(X)),dtype=int))
    direct=clf.predict_proba(X.iloc[sample])
    if not np.allclose(p[sample],direct,atol=1e-14,rtol=1e-13):
        raise ValueError('Deduplicated prediction mismatch')
    return p

def decisions(prob,frame,policy='keyword'):
    result=np.asarray(LABELS,dtype=object)[prob.argmax(1)]
    result[(result=='benign')&frame.aux_threat_hit.to_numpy().astype(bool)]='malicious'
    if policy=='keyword_winlog6':
        mask=(result=='benign')&frame.aux_winlogbeat_guard.to_numpy().astype(bool)&(6*prob[:,2]>np.maximum(prob[:,0],prob[:,1]))
        result[mask]='malicious'
    return result

def evaluate(prob,frame,truth,policies=('keyword','keyword_winlog6')):
    reports={}
    for policy in policies:
        pred=decisions(prob,frame,policy)
        reports[policy]=metrics(truth,pred)
        reports[policy]['source_errors']={}
        masks={
            'duo':frame.aux_source_family.eq('duo'),
            'duo_missing_product':frame.aux_source_family.eq('duo')&frame.meta_product_missing.eq(1),
            'symantec_dlp':frame.product_name.fillna('').eq('Symantec Data Loss Prevention'),
            'missing_winlogbeat':frame.aux_winlogbeat_guard.eq(1),
            'cef':frame.is_cef.eq(1),
        }
        y=np.asarray(truth)
        for name,mask in masks.items():
            m=mask.to_numpy()
            reports[policy]['source_errors'][name]={'rows':int(m.sum()),'errors':int((y[m]!=pred[m]).sum()),
                'benign_false_positives':int(((y[m]=='benign')&(pred[m]!='benign')).sum()),
                'threat_false_negatives':int(((y[m]!='benign')&(pred[m]=='benign')).sum())}
    return reports
