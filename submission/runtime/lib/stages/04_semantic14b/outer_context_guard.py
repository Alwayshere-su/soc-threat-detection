"""Correct explicit outer business-event reports, not quoted inner activity."""
from dataclasses import dataclass
import re
from payload_policy_v3 import normalized,FRAME
from payload_policy_v5 import request_parts

VERSION='explicit_outer_business_context_v1'

@dataclass(frozen=True)
class Decision:
    label: str | None
    reason: str
    evidence: str=''

def classify(message):
    text=FRAME.sub('',normalized(message),count=1).strip()
    match=re.match(r'post\s+(/[^\s?]*)\s+http/\d(?:\.\d)?\n',text)
    if not match:return Decision(None,'not_explicit_outer_post')
    data=request_parts(text,match[1]);body=data['body']
    if not body:return Decision(None,'no_outer_body_boundary')
    header='\n'.join(name+': '+value for name,value in data['headers'])
    # Direct attack expressions in the outer headers still take precedence.
    if re.search(r'\$\{jndi:|<script|(?:\bunion\s+select|\bwaitfor\s+delay)|\b(?:sleep|extractvalue)\s*\(',header):
        return Decision(None,'outer_attack_evidence')
    target=match[1]
    if target in ['/cdbj/cut/device/operation/report','/cdispatching/cutoplog/opreatenetlog/operatelog']:
        if all(re.search('"'+name+r'"\s*:',body) for name in ['interceptcommand','interceptscene','operationresult']):
            return Decision('benign','outer_operations_report','explicit operation-report endpoint and report schema')
    if target.startswith('/gateway/api/') or target in ['/v1/chat/completions','/v1/completions']:
        if re.search(r'"model"\s*:',body) and re.search(r'"messages"\s*:\s*\[',body):
            return Decision('benign','outer_model_chat_request','model request envelope with quoted messages')
    if target=='/api/array2singlemsg' and re.search(r'ponshine_datatype|safety-middleground_log',body):
        return Decision('benign','outer_security_log_relay','explicit security-log ingestion endpoint and schema')
    return Decision(None,'no_certain_outer_context')

def apply(frame,baseline):
    labels=list(baseline);audit=[]
    for i,(pipeline,message) in enumerate(zip(frame.pipeline,frame.message_sanitized)):
        if pipeline!='payload' or labels[i]=='benign':continue
        decision=classify(message)
        if decision.label=='benign':labels[i]='benign';audit.append((i,decision))
    return labels,audit
