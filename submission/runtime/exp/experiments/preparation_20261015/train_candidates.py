"""Fixed train-only experiments. Development answers are read only for evaluation."""
import argparse,gc,json,pickle,sys,time
from pathlib import Path
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split,GroupShuffleSplit

ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from pipeline import LABELS,fit_categories,encode_features,align_truth,metrics,sha256,write_json
from model_utils import predict_compact,evaluate
from semantic_features import VERSION

def load_data():
    frames=[]
    for name in ['train','valid']:
        path=OUT/f'{name}_semantic.parquet'
        m=json.loads(path.with_suffix('.json').read_text(encoding='utf-8'))
        if sha256(path)!=m['sha256'] or m['extra_source_sha256']!=sha256(OUT/'semantic_features.py'):
            raise ValueError('Semantic cache provenance mismatch')
        frames.append(pd.read_parquet(path))
    return frames

def make_splits(train,y):
    random=train_test_split(np.arange(len(y)),test_size=.1,stratify=y,random_state=42)
    groups=train.aux_template_group.to_numpy()
    grouped=None
    for tr,va in GroupShuffleSplit(n_splits=40,test_size=.15,random_state=20261015).split(np.zeros(len(y)),y,groups):
        counts=np.bincount(y[va],minlength=3)
        frac=counts/np.bincount(y,minlength=3)
        if set(y[tr])=={0,1,2} and set(y[va])=={0,1,2} and .04<len(va)/len(y)<.3 and (frac>.01).all() and (frac<.6).all():
            grouped=(tr,va);break
    if grouped is None:raise ValueError('No balanced-enough template split')
    splitfile=OUT/'fixed_splits.npz'
    if splitfile.exists():
        old=np.load(splitfile)
        for key,value in [('random_train',random[0]),('random_holdout',random[1]),('group_train',grouped[0]),('group_holdout',grouped[1])]:
            if not np.array_equal(old[key],value):raise ValueError('Fixed split mismatch')
    else:np.savez_compressed(splitfile,random_train=random[0],random_holdout=random[1],group_train=grouped[0],group_holdout=grouped[1])
    write_json(OUT/'validation_protocol.json',{'training_source':'data/训练集/train.parquet','development_labels':'evaluation_only',
        'random':{'train_rows':len(random[0]),'holdout_rows':len(random[1]),'seed':42},
        'grouped':{'train_rows':len(grouped[0]),'holdout_rows':len(grouped[1]),'seed':20261015,
            'overlapping_groups':len(set(groups[grouped[0]])&set(groups[grouped[1]])),
            'train_class_counts':np.bincount(y[grouped[0]],minlength=3).tolist(),'holdout_class_counts':np.bincount(y[grouped[1]],minlength=3).tolist()},
        'limitation':'Normalized-template grouping reduces repeat leakage. Previously inspected development data is not untouched blind validation.'})
    return {'random':random,'grouped':grouped}

def fit_one(name,train,valid,y,truth,split,columns,augmentation=False,n_jobs=6,rounds=1400,native=False):
    destination=OUT/name
    if destination.exists():raise FileExistsError(destination)
    destination.mkdir()
    tr,va=split
    cats=fit_categories(train.iloc[tr])
    X=encode_features(train,cats,columns)
    Xv=encode_features(valid,cats,columns)
    XT=X.iloc[tr].copy()
    yt=y[tr].copy()
    aug_count=0
    if augmentation:
        rng=np.random.default_rng(20261015)
        select=rng.choice(len(XT),int(.2*len(XT)),replace=False)
        aug=XT.iloc[select].copy()
        unknown=rng.random(len(aug))<.5
        for column,flag in [('product_name','meta_product_missing'),('vendor_name','meta_vendor_missing')]:
            empty=cats[column].index('') if '' in cats[column] else -1
            aug[column]=np.where(unknown,-1,empty).astype(np.float32)
            if flag in aug:aug[flag]=(~unknown).astype(np.float32)
        XT=pd.concat([XT,aug],ignore_index=True)
        yt=np.concatenate([yt,yt[select]])
        aug_count=len(aug)
        del aug
    counts=np.bincount(yt,minlength=3)
    weights=(len(yt)/(3*counts))[yt].astype(np.float32)
    if aug_count:weights[-aug_count:]*=.5
    clf=lgb.LGBMClassifier(objective='multiclass',num_class=3,n_estimators=rounds,
        num_leaves=127,learning_rate=.05,colsample_bytree=.8,subsample=.8,subsample_freq=1,
        min_child_samples=50,random_state=42,n_jobs=n_jobs,verbose=-1)
    start=time.time()
    print('FIT',name,'rows',len(XT),'features',len(columns),'augmentation',aug_count,flush=True)
    native_cols=['pipeline','product_name','vendor_name','action','protocol']
    if native=='events':native_cols+=['win_event_id','json_win_event_id','effective_win_event_id']
    fit_options={'categorical_feature':native_cols} if native else {}
    clf.fit(XT,yt,sample_weight=weights,eval_set=[(X.iloc[va],y[va])],eval_metric='multi_logloss',
        callbacks=[lgb.early_stopping(80,verbose=False),lgb.log_evaluation(200)],**fit_options)
    del XT,weights
    gc.collect()
    print('PREDICT',name,'iteration',clf.best_iteration_,'seconds',round(time.time()-start,1),flush=True)
    hp=predict_compact(clf,X.iloc[va])
    vp=predict_compact(clf,Xv)
    np.save(destination/'development_probabilities.npy',vp)
    report={'name':name,'train_rows':len(tr),'holdout_rows':len(va),'augmentation_rows':aug_count,
        'augmentation_kind':'20pct_metadata_hidden_half_unknown_half_missing_aug_weight0.5' if augmentation else None,
        'best_iteration':int(clf.best_iteration_),'features':len(columns),'seconds':time.time()-start,
        'native_categorical_features':fit_options.get('categorical_feature',[]),
        'holdout_raw':metrics(np.asarray(LABELS)[y[va]],np.asarray(LABELS)[hp.argmax(1)]),
        'development':evaluate(vp,valid,truth),'feature_version':VERSION if len(columns)>62 else 'portable_v1',
        'training_source_sha256':sha256(ROOT/'data/训练集/train.parquet'),
        'development_use':'evaluation only; not passed to fit or used for early stopping'}
    model={'cats':cats,'common_cols':columns,'coef':[1.,1.,1.],'clf':clf,'feature_version':report['feature_version'],
        'metadata':{'encoding':'training_vocabulary_numeric_v1','experiment':name,'training_scope':'official_training_only',
                    'feature_code_sha256':sha256(OUT/'semantic_features.py'),'augmentation':report['augmentation_kind'],
                    'native_categorical_features':report['native_categorical_features']}}
    (destination/'model.pkl').write_bytes(pickle.dumps(model))
    report['model_sha256']=sha256(destination/'model.pkl')
    report['probabilities_sha256']=sha256(destination/'development_probabilities.npy')
    write_json(destination/'report.json',report)
    print('RESULT',name,'holdout',report['holdout_raw']['final_score'],
        'development',{k:(v['final_score'],v['errors']) for k,v in report['development'].items()},flush=True)
    return report

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--n-jobs',type=int,default=6)
    ap.add_argument('--rounds',type=int,default=1400)
    ap.add_argument('--only',nargs='*')
    args=ap.parse_args()
    train,valid=load_data()
    y=train.label_binary.map(dict(zip(LABELS,range(3)))).to_numpy()
    truth=align_truth(pd.read_parquet(ROOT/'data/验证集答案/valid_answer_private.parquet'),valid.event_id)
    splits=make_splits(train,y)
    oldcols=[c for c in pd.read_parquet(ROOT/'features/train_features.parquet').columns if c not in ['event_id','label_binary']]
    allcols=[c for c in train if c not in ['event_id','label_binary'] and not c.startswith('aux_')]
    configs=[('portable_grouped_control','grouped',oldcols,False),('semantic_grouped','grouped',allcols,False),
             ('semantic_augmented_grouped','grouped',allcols,True),('semantic_random','random',allcols,False)]
    reports=[]
    for name,split,cols,aug in configs:
        if args.only and name not in args.only:continue
        reports.append(fit_one(name,train,valid,y,truth,splits[split],cols,aug,args.n_jobs,args.rounds))
        gc.collect()
    write_json(OUT/'candidate_comparison.json',{'reports':reports,'baseline_development_score':0.9994530823096053,
        'baseline_official_score':0.999498,'training_labels':'official train only','development_labels':'evaluation only'})

if __name__=='__main__':main()
