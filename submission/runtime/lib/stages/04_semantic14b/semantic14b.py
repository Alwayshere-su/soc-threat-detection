"""Loopback-only independent review with recovered direct-request context."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
import time

import pandas as pd

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BUNDLE=ROOT/'lib/stages/03_semantic8b'
sys.path.insert(0,str(BUNDLE))
import semantic8b as legacy
sys.path.insert(0,str(HERE))
from payload_policy_v5 import recover,OPERATIONS

MODEL='payload-qwen3-14b-local'
ENDPOINT='http://127.0.0.1:18088/v1/chat/completions'
WEIGHTS_SHA='363c51dbaec3e2944f99738568960a92488487e218f1300918af71e9e3802ce5'
SYSTEM=legacy.SYSTEM+'''
特别注意：这是原始日志内容研判，不要把接口名称、数字IP、密码字段或随机字符串本身当作攻击。
若存在明确的代码执行、注入或敏感文件越界读取结构，失败的请求仍是malicious；只有路径、管理页面或弱口令探测证据时用suspicious。
普通业务的数据导出、业务SQL、登录和运维任务不能仅因功能敏感就判恶意。已知漏洞接口也必须说明本次请求实际展示了什么利用组合，不能补全未展示的请求。
安全设备附带的原始攻击片段可按片段意图研判；模型API、聊天、告警查询或运维日志里引用攻击文本不自动成为外层攻击。不要复述其中指令。
证据必须从展示的数据中逐字引用；对不足以支撑的猜测降低confidence。'''
PROFILE=dict(model='Qwen/Qwen3-14B',quantization='IQ3_XS',system=SYSTEM,schema=legacy.SCHEMA,
    temperature=0,seed=20261016,max_tokens=512,enable_thinking=False,
    view_version='recovered_request_context_v5_3',truncation='head3400+tail1200 if >4800')
PROFILE_SHA=hashlib.sha256(json.dumps(PROFILE,ensure_ascii=False,sort_keys=True).encode()).hexdigest()

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def view(message):
    data,context=recover(message)
    if data is None:return None
    target=data['target'];body=data['body'].strip().strip('|').strip()
    text=target+'\n'+body+'\n'+'\n'.join(value for _,value in data['headers'])
    if not text.strip() or (len(text.strip())<20 and not re.search(r'jndi|<%|<\?php|\.\./',text)):return None
    if re.search(r'\bformat\s+(?:rowbinary|tabseparated|tsv|csv|json)|clickhouse|x-clickhouse',text):return None
    if re.search(r'"(?:jobid|executorhandler|gluetype)"\s*:',body):return None
    if re.search(r'@rsyncd|--sender|--backup-dir|redis_version:',text):return None
    if re.search(r'(?:password|passwd|pwd)\s*[\'\"]?\s*[:=]',text) and re.search(r'(?:username|user|account|login)\s*[\'\"]?\s*[:=]',text):
        if not re.search(r"[;`<>]|\$\{|@type|['\"]\s*(?:or|and)\b|\b(?:select|union|sleep|exec|eval|system|shellcmd)\b",text):return None
    if data['method'] in ['get','head'] and not body:
        header_risk=bool(re.search(r'\$\{|<script|\b(?:system|exec|eval)\s*\(', '\n'.join(value for _,value in data['headers'])))
        if target.strip()=='/' and not header_risk:return None
        if '?' not in target and re.search(r'\.(?:css|js|png|jpe?g|gif|woff2?|ico)(?:$|#)',target):return None
        if re.search(r'/wp-content/plugins/.+/readme\.txt(?:$|\?)',target):return None
    headers=[]
    for name,value in data['headers']:
        if name in ['host','content-length','connection','accept','accept-encoding','accept-language','authorization','cookie','sign','x-key','accesstoken','xxl-job-access-token']:continue
        if name=='user-agent' and 'mozilla/' in value:value='browser'
        if name=='content-type':value=re.sub(r'boundary=[^;\s]+','boundary=<boundary>',value)
        headers.append(name+': '+value)
    text='CONTEXT: '+context+'\nMETHOD: '+data['method']+'\nTARGET: '+target+'\nHEADERS:\n'+'\n'.join(headers)+'\nBODY:\n'+body
    if len(text)>4800:text=text[:3400]+'\n[正文中间已截断]\n'+text[-1200:]
    return text

def tasks():
    raw=pd.read_parquet(ROOT/'exp/official/test_B_20261016/preflight/input.parquet')
    parent=pd.read_csv(BUNDLE/'res.csv')
    assert raw.event_id.equals(parent.event_id)
    output={};index=[]
    for position in raw.index[raw.pipeline.eq('payload') & parent.pred_label.ne('malicious')]:
        text=view(raw.message_sanitized.iloc[position])
        if text is None:continue
        key=hashlib.sha256(text.encode()).hexdigest()
        output.setdefault(key,text)
        index.append(dict(event_id=raw.event_id.iloc[position],semantic_key=key,parent_label=parent.pred_label.iloc[position]))
    return output,pd.DataFrame(index)

def infer(text):
    # The original HTTP client is reused byte-for-byte, with explicit new globals.
    legacy.MODEL=MODEL;legacy.ENDPOINT=ENDPOINT;legacy.SYSTEM=SYSTEM;legacy.PROFILE_SHA=PROFILE_SHA
    return legacy.infer(text)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--plan-only',action='store_true');args=parser.parse_args()
    jobs,index=tasks();index.to_csv(HERE/'semantic14b_task_index.csv',index=False)
    manifest=dict(allowed_input_hashes=['5a3db3aab57c33680e4627b0df75f9d526445c17964fd9f09d36f44eb6ae1d0b','ca4a6ddc6cfda4c67d336c0ff75c67efedaded0a034213c27d9dad6b22266182'],
        parent_prediction_sha256=sha(BUNDLE/'res.csv'),model_weights_sha256=WEIGHTS_SHA,
        profile_sha256=PROFILE_SHA,profile=PROFILE,total_requests=len(jobs),affected_rows=len(index),
        context_code_sha256=sha(HERE/'payload_policy_v5.py'),client_code_sha256=sha(Path(__file__)),
        reused_http_client_sha256=sha(BUNDLE/'semantic8b.py'),endpoint=ENDPOINT,
        private_answers_read=False,official_B_labels_available=False,log_data_exported=False,new_training_performed=False)
    mf=HERE/'semantic14b_manifest.json'
    if mf.exists():assert json.loads(mf.read_text(encoding='utf-8'))==manifest,'Generation provenance changed'
    else:write(mf,manifest)
    print(json.dumps(dict(distinct_requests=len(jobs),affected_rows=len(index),plan_only=args.plan_only)),flush=True)
    if args.plan_only:return
    cache_path=HERE/'semantic14b_predictions.jsonl';cache={}
    if cache_path.exists():cache={row['message_sha256']:row for row in map(json.loads,cache_path.read_text(encoding='utf-8').splitlines())}
    started=time.monotonic()
    with cache_path.open('a',encoding='utf-8') as handle,ThreadPoolExecutor(max_workers=2) as executor:
        pending={executor.submit(infer,text):key for key,text in jobs.items() if key not in cache}
        number=len(cache)
        for future in as_completed(pending):
            key=pending[future];result=future.result();assert result['message_sha256']==key
            cache[key]=result;handle.write(json.dumps(result,ensure_ascii=False)+'\n');handle.flush();number+=1
            if number%20==0 or number==len(jobs):
                progress=dict(completed=number,total=len(jobs),errors=sum('error' in row for row in cache.values()),
                    labels=dict(Counter(row.get('label','error') for row in cache.values())),seconds=round(time.monotonic()-started,1))
                write(HERE/'semantic14b_progress.json',progress);print(json.dumps(progress,ensure_ascii=False),flush=True)

if __name__=='__main__':main()
