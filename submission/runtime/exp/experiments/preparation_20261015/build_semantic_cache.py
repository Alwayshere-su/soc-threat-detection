"""Add features to hash-verified original caches, without recomputing portable_v1."""
import sys,time,json
from pathlib import Path
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from pipeline import sha256,write_json
from score import THREAT_TOKEN_RE
from semantic_features import extras,template_groups,VERSION

def build(name,source):
    base_path=ROOT/f'features/{name}_features.parquet'
    meta=json.loads(base_path.with_suffix('.json').read_text(encoding='utf-8-sig'))
    if meta['sha256']!=sha256(base_path) or meta['source_sha256']!=sha256(source):
        raise ValueError('Original cache provenance mismatch')
    base=pd.read_parquet(base_path)
    target=OUT/f'{name}_semantic.parquet'
    if target.exists():raise FileExistsError(target)
    temp=target.with_suffix('.parquet.tmp')
    writer=None
    position=0
    start=time.time()
    try:
        for batch in pq.ParquetFile(source).iter_batches(batch_size=25000):
            raw=batch.to_pandas()
            b=base.iloc[position:position+len(raw)].reset_index(drop=True)
            if not np.array_equal(raw.event_id.to_numpy(),b.event_id.to_numpy()):
                raise ValueError('Cache and raw IDs/order differ')
            semantic=extras(raw,b)
            data=pd.concat([b,semantic],axis=1)
            data['aux_template_group']=template_groups(raw.message_sanitized)
            msg=raw.message_sanitized.fillna('').astype('string[pyarrow]')
            data['aux_threat_hit']=msg.str.contains(THREAT_TOKEN_RE,case=False,regex=True).astype(np.int8)
            data['aux_winlogbeat_guard']=(raw.pipeline.fillna('').eq('syslog')&raw.product_name.fillna('').astype(str).str.strip().eq('')&b.is_elk_json.eq(1)).astype(np.int8)
            data['aux_source_family']=np.select([semantic.family_duo.eq(1),b.is_elk_json.eq(1),b.is_cef.eq(1)],['duo','winlogbeat','cef'],default='other')
            table=pa.Table.from_pandas(data,preserve_index=False)
            if writer is None:writer=pq.ParquetWriter(temp,table.schema,compression='zstd')
            writer.write_table(table)
            position+=len(raw)
            if position%250000==0:print(name,position,'seconds',round(time.time()-start,1),flush=True)
    finally:
        if writer:writer.close()
    if position!=len(base):raise ValueError('Row count mismatch')
    temp.replace(target)
    write_json(target.with_suffix('.json'),{'feature_version':VERSION,'rows':position,'source':str(source),
        'source_sha256':meta['source_sha256'],'base_cache_sha256':meta['sha256'],'sha256':sha256(target),
        'extra_source_sha256':sha256(OUT/'semantic_features.py'),'seconds':time.time()-start,
        'label_scope':'training labels only; development answers are evaluation-only and are not in this cache'})
    print('DONE',name,position,'seconds',round(time.time()-start,1),flush=True)

if __name__=='__main__':
    for name,path in [('train',ROOT/'data/训练集/train.parquet'),('valid',ROOT/'data/验证集/valid_input.parquet')]:build(name,path)
