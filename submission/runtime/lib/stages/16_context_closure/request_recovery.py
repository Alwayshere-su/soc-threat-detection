"""Frozen request framing; preserve original text separately for strict encoded-value decoding."""
import re
from urllib.parse import unquote
from request_normalization import normalized,FRAME

OPERATIONS=re.compile(r'lookbehind\s*:|greedy\s*:|inside\s*:\s*\{|apt-cache\|apt-get|'
    r'rs_operation_load_log|rs_application_\w+log|ponshine_datatype|safety-middleground_log|'
    r'"(?:operationcontent|operation_log|interceptcommand|networkcloud_type|kpis)"\s*:|'
    r'snc\.script\.cmd\.|class="host_command"|class="normal_content|boco4a:|'
    r'root,\s*cmd=|\[root@| by root from |login_type=',re.I)

QUOTED=re.compile(r'"(?:messages|payloads|adapter)"\s*:|"role"\s*:\s*"(?:user|assistant|tool)|'
    r'【补充判定|classify\s+(?:the\s+)?request|"\s*,\s*"(?:get|post|put|\d+,)',re.I)

REQUEST=re.compile(r'\b(get|post|put|patch|delete|head|options|trace|connect)\s+(/[^\n]{0,20000}?)\s+http/\d(?:\.\d)?',re.I)

def request_parts(text,target):
    lines=text.split('\n');headers=[];body=[];in_body=False
    for line in lines[1:]:
        if not in_body:
            if not line.strip():
                if headers:in_body=True
                continue
            if not headers and re.fullmatch(r'\d\.\d',line.strip()):continue
            header=re.match(r'^([a-z][a-z0-9_-]{0,60})\s*:\s*(.*)$',line)
            if header:headers.append((header[1],header[2]));continue
            in_body=True
        body.append(line)
    return dict(target=target,body='\n'.join(body).strip(),headers=headers)

def recover(message):
    text=FRAME.sub('',normalized(message),count=1).strip()
    text=re.split(r'\n\s*response_(?:code|message)\s*:',text,maxsplit=1)[0]
    # Remove trailing alert bookkeeping, but do not follow any embedded policy.
    text=re.split(r'\|{4,}',text,maxsplit=1)[0].strip()
    if OPERATIONS.search(text) or QUOTED.search(text):return None,'protected_context'
    request=REQUEST.search(text)
    if request and request.start()<700:
        prefix=text[:request.start()]
        if re.search(r'"(?:content|request|arguments)"\s*:|\[tool:',prefix):return None,'embedded_request'
        text=text[request.start():]
        result=request_parts(text,request[2]);result['method']=request[1]
        if re.match(r'^/(?:api/array2singlemsg|gateway/api/|v1/chat/|v1/embeddings|v1/classify|largemodel/)',result['target']):return None,'model_api'
        return result,'recovered_http'
    # Recover a direct form/header fragment behind a printable packet prefix.
    if re.match(r'^[.\W\d]+',text) and re.search(r'(?:username|userpassword|password|email)=',text[:600]):
        hit=re.search(r'\b(?:username|userpassword|password|email)=',text[:600])
        if hit and text[:hit.start()].count('.')>=8:text=text[hit.start():]
    first=text.split('\n',1)[0]
    if re.search(r'\n(?:host|content-type|user-agent):',text) and re.search(r'\s+http/\d',first):
        result=request_parts(text,re.sub(r'\s+http/\d(?:\.\d)?\s*$','',first));result['method']=''
        return result,'recovered_http_fragment'
    # Standalone fragments still require a concrete exploit structure downstream.
    return dict(target=first,body=text,headers=[],method=''),'direct_fragment'

def decode_part(text):
    for _ in range(4):
        decoded=unquote(text)
        if decoded==text:break
        text=decoded
    return re.sub(r'~([0-9a-f]{2})',lambda m:chr(int(m[1],16)),text)
