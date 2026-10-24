"""Known public default pairs on explicit authentication endpoints are suspicious."""
from dataclasses import dataclass
import base64
import re
from urllib.parse import parse_qsl
from payload_policy_v5 import recover

VERSION='explicit_default_credential_probe_v1'
PAIRS={('admin','admin'),('admin','admin123'),('admin','123456'),('root','root'),('nacos','nacos'),
    ('weblogic','weblogic'),('weblogic','welcome1'),('system','manager'),('tomcat','tomcat'),('tomcat','s3cret'),
    ('admin','axis2'),('admin','password'),('admin','12345'),('admin','admin@123')}
BASIC={base64.b64encode((user+':'+password).encode()).decode().lower() for user,password in PAIRS}
USER_FIELDS={'username','user','j_username','uname','loginname','login_username','admin_name'}
PASS_FIELDS={'password','passwd','pwd','j_password','loginpass','login_password','admin_pwd'}

@dataclass(frozen=True)
class Decision:
    label: str | None
    reason: str

def classify(message):
    data,context=recover(message)
    if data is None:return Decision(None,'protected_context')
    target=data['target'];body=data['body']
    if not re.search(r'(?:login|auth|signin|j_security_check|^/manager/(?:html|text))',target):
        return Decision(None,'not_authentication_endpoint')
    values=dict(parse_qsl(target.partition('?')[2]+'&'+body,keep_blank_values=True))
    for field,value in re.findall(r'[\'\"]([a-z_]{1,30})[\'\"]\s*:\s*[\'\"]([^\'\"]{0,100})[\'\"]',body):values.setdefault(field,value)
    users=[value for name,value in values.items() if name in USER_FIELDS]
    passwords=[value for name,value in values.items() if name in PASS_FIELDS]
    if any((user,password) in PAIRS for user in users for password in passwords):
        return Decision('suspicious','public_default_pair_on_authentication_endpoint')
    for name,value in data['headers']:
        if name=='authorization' and value.startswith('basic ') and value[6:].strip() in BASIC:
            return Decision('suspicious','public_default_basic_authentication_pair')
    return Decision(None,'no_known_default_pair')

def apply(frame,baseline):
    labels=list(baseline);audit=[]
    for i,(pipeline,message) in enumerate(zip(frame.pipeline,frame.message_sanitized)):
        if pipeline!='payload' or labels[i]!='benign':continue
        decision=classify(message)
        if decision.label=='suspicious':labels[i]='suspicious';audit.append((i,decision))
    return labels,audit
