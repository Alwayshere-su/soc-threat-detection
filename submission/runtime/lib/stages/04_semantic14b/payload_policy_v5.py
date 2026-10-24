"""Recover direct request evidence and known sensitive probes; payload scope only."""
from dataclasses import dataclass
import re

from payload_policy_v3 import normalized,FRAME,classify as classify_v3
from payload_policy_v4 import classify as classify_v4,SQL_ENCODED
from payload_policy_v2 import classify as classify_v2

VERSION='direct_payload_recovery_v5'

@dataclass(frozen=True)
class Decision:
    label: str | None
    reason: str
    context: str
    evidence: str=''

OPERATIONS=re.compile(r'lookbehind\s*:|greedy\s*:|inside\s*:\s*\{|apt-cache\|apt-get|'
    r'rs_operation_load_log|rs_application_\w+log|ponshine_datatype|safety-middleground_log|'
    r'"(?:operationcontent|operation_log|interceptcommand|networkcloud_type|kpis)"\s*:|'
    r'snc\.script\.cmd\.|class="host_command"|class="normal_content|boco4a:|'
    r'root,\s*cmd=|\[root@| by root from |login_type=',re.I)
QUOTED=re.compile(r'"(?:messages|payloads|adapter)"\s*:|"role"\s*:\s*"(?:user|assistant|tool)|'
    r'【补充判定|classify\s+(?:the\s+)?request|"\s*,\s*"(?:get|post|put|\d+,)',re.I)
REQUEST=re.compile(r'\b(get|post|put|patch|delete|head|options|trace|connect)\s+(/[^\n]{0,20000}?)\s+http/\d(?:\.\d)?',re.I)
ATTACK_IN_CONTEXT=re.compile(r'\$\{jndi:(?:ldap|rmi)|<!entity|<\?php|<%@|\bunion\s+(?:all\s+)?select|'
    r'\b(?:sleep|extractvalue|updatexml)\s*\(|\bwaitfor\s+delay|/etc/(?:passwd|shadow)',re.I)

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

MALICIOUS=[
    ('download_chmod_execute_chain',r'\b(?:wget|curl)\b.{0,350}\bchmod\s+(?:\+?x|[0-7]{3,4})\s+[^;\n]{1,150};.{0,120}(?:\./|setsid\s+\./|(?:/bin/)?(?:ba)?sh\s+)'),
    ('shell_arithmetic_marker',r'`[^`\n]{0,100}\bexpr\s+\d{5,}\s+[-+*/ ]{1,8}\s*\d{5,}[^`\n]{0,50}`'),
    ('shell_chained_identity',r'(?:&&|\|\||;)\s*(?:whoami|id)(?=[\s;&|`]|$)'),
    ('sql_nested_delay_in_value',r'(?:[\'\"]\)?\s*and|\band\s*\().{0,140}\bselect\b.{0,160}\bsleep\s*\(\s*\d+\s*\)'),
    ('log4shell_fragment',r'\$\{jndi\s*:\s*(?:ldap|rmi|dns|iiop)\s*:'),
    ('xxe_sensitive_file_fragment',r'(?:<!entity|\bentity\s+\w+|^ity\s+\w+).{0,100}\bsystem\s*[\'\"]file:/+.{0,100}(?:etc/(?:passwd|shadow)|windows/win\.ini)'),
    ('ognl_static_execution',r'(?:ognl|#_memberaccess|allowstaticmethodaccess).{0,1200}(?:getruntime|processbuilder|\.exec\s*\(|servletactioncontext)'),
    ('sensitive_config_database_read',r'(?:^|/)(?:data/pbootcms\.db|messager/users\.data|application/configs/application\.ini|application\.ini|runtime/data/ms_admin\.php|vpn/\.\./vpns/cfg/smb\.conf|v1/cs/configs\?export=true|api/v1/clusters/kubeconfig/[^?\s]+)(?:[?&\s]|$)'),
    ('privileged_configuration_export',r'^/(?:cgi-bin/exportcfgwithpasswd|form/exportconfigbyhttp|level/15/exec/show/(?:config|running-config)/cr|yyoa/ext/https/getsessionlist\.jsp\?cmd=getall)(?:[?&\s]|$)'),
    ('explicit_auth_bypass_traversal',r'(?:\.\.[/\\]+|\.\.;[/\\]).{0,220}(?:web-inf/web\.xml|conf/config\.properties|config\.properties|etc/shells|server/logs/error\.log|users/log/log\d+\.dat|system/system-information)'),
    ('config_handler_source_disclosure',r'^/(?:web\.config|swnetperfmon\.db)\.i18n\.ashx(?:[?\s]|$)'),
]
PATTERNS=[(name,re.compile(pattern,re.I|re.S)) for name,pattern in MALICIOUS]
SENSITIVE_PROBE=re.compile(r'^/(?:\.idea/(?:workspace|modules)\.xml|(?:backups?|config|web|mkfile|static/js/app)\.(?:old|bak)|(?:web|sql)\.zip|test\.sql|cvs/entries|dayrui/my/config/install\.txt|easwebclient/bin/config\.jar|_cat/indices|_profiler/phpinfo|app_dev\.php/_profiler/open|(?:v2;|api/v2;)/test/api-docs|jkstatus;)(?:[?&\s]|$)',re.I)
OAST=re.compile(r'https?://[^/\s&]*\.(?:jorm0\.surf|oast\.(?:fun|site|online|live|pro)|dnslog\.(?:cn|pw)|ceye\.io|interact\.sh)(?:[/:?\s]|$)',re.I)

def classify(message):
    data,context=recover(message)
    if data is None:return Decision(None,'protected_context',context)
    target=data['target'];body=data['body'];text=target+'\n'+body+'\n'+'\n'.join(name+': '+value for name,value in data['headers'])
    if re.search(r'\bformat\s+(?:rowbinary|tabseparated|csv|tsv|json)|clickhouse|x-clickhouse',text):
        return Decision(None,'ordinary_database_client',context)
    if re.search(r'"(?:jobid|executorhandler|gluetype)"\s*:',body):return Decision(None,'scheduled_job',context)
    for name,pattern in PATTERNS:
        candidate=target if name in ['sensitive_config_database_read','privileged_configuration_export','config_handler_source_disclosure','explicit_auth_bypass_traversal'] else text
        hit=pattern.search(candidate)
        if hit:return Decision('malicious',name,context,hit[0])
    # Reuse previously validated exploit rules on recovered direct evidence.
    # Retain the original method and request view; do not wrap arbitrary text.
    clean=(data['method']+' '+target+' HTTP/1.1\n'+ '\n'.join(name+': '+value for name,value in data['headers'])+'\n\n'+body
           if data['method'] else body if context=='direct_fragment' else target+'\n\n'+body)
    for classifier in [classify_v3,classify_v4,classify_v2]:
        decision=classifier(clean)
        if decision.label=='malicious':return Decision('malicious','recovered_'+decision.reason,context,decision.evidence)
    # Base64 signatures survive known lowercasing; no claim of lossless decode.
    for token in re.findall(r'(?<![a-z0-9+/])[a-z0-9+/]{16,12000}={0,2}',target+'\n'+body):
        if any(signature in token for signature in SQL_ENCODED):return Decision('malicious','encoded_sql_in_request_value',context,'encoded SQL delay or diagnostic byte signature')
    if OAST.search(target+'\n'+body) and re.search(r'(?:url|source|src|target|callback|dest)\s*=',target+'\n'+body):
        return Decision('malicious','ssrf_out_of_band_callback',context,'out-of-band callback in a server-fetch parameter')
    if re.search(r'^/api/system/command-run(?:[?\s]|$)',target) and re.search(r'"command"\s*:\s*"(?:id|whoami)"',body):
        return Decision('malicious','direct_system_command_api',context,'system-command endpoint with identity execution request')
    if re.search(r'mstshash=nmap\b|options sip:nm\s+sip/2\.0',text):
        return Decision('suspicious','explicit_protocol_scanner',context,'explicit Nmap protocol probe marker')
    hit=SENSITIVE_PROBE.search(target)
    if hit:return Decision('suspicious','sensitive_resource_probe',context,hit[0])
    if re.search(r'(?:^|/)(?:shell\.aspx|shell\.jspx|test\.jspx|webshell\.jspx?)(?:[?\s]|$)',target):
        return Decision('suspicious','executable_shell_resource_probe',context,'explicit shell-like executable path')
    return Decision(None,'no_additional_direct_evidence',context)

def apply(frame,baseline):
    labels=list(baseline);audit=[]
    for position,(pipeline,message) in enumerate(zip(frame.pipeline,frame.message_sanitized)):
        if pipeline!='payload' or labels[position]=='malicious':continue
        decision=classify(message)
        if decision.label=='malicious' or (decision.label=='suspicious' and labels[position]=='benign'):
            labels[position]=decision.label
            audit.append((position,decision))
    return labels,audit
