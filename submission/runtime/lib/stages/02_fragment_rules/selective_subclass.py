"""Promote a probe only when the request contains direct exploitation evidence."""
from dataclasses import dataclass
import re

from request_context import extract
from payload_policy_v3 import classify as fragment_classify,normalized

VERSION='selective_payload_subclass_v1'

@dataclass(frozen=True)
class Decision:
    promote: bool
    reason: str
    evidence: str=''


SENSITIVE_FILE=re.compile(
    r'(?:^|/)(?:\.bash_history|\.env(?:\.(?:local|prod|production|backup|bak))?|'
    r'\.git/(?:config|index)|\.svn/(?:entries|wc\.db)|web-inf/web\.xml|'
    r'etc/(?:passwd|shadow)|windows/win\.ini)(?:[?&#\s\x00]|$)',re.I)


def classify(message):
    strong=fragment_classify(message)
    if strong.label=='malicious':
        return Decision(True,'explicit_fragment_'+strong.reason,strong.evidence)
    regions,context=extract(message)
    if regions is None:return Decision(False,'retain_probe_no_outer_request')
    target=normalized(regions['target'])
    # Read only the external target. Forwarded log and prompt bodies stay excluded.
    body='' if context=='outer_request_body_excluded' else normalized(regions['body'])
    text=target+'\n'+body
    match=SENSITIVE_FILE.search(target)
    if match:return Decision(True,'direct_sensitive_file_read',match[0])
    match=re.search(r'\bfile:/+(?:[a-z]:[/\\]+(?:windows|winnt)[/\\]+win\.ini|etc/(?:passwd|shadow))',text,re.I)
    if match:return Decision(True,'local_file_protocol_disclosure',match[0])
    match=re.search(r'(?:^|/)(?:actuator/(?:heapdump|env|configprops))(?:[?&#\s]|$)',target)
    if match:return Decision(True,'sensitive_management_dump',match[0])
    if (re.search(r'(?:[?&]|^)action=[^&]*(?:load_function|call_function|execute_function|run_function)',target)
            and re.search(r'(?:[?&\n]|^)(?:function|callback|func)=phpinfo(?:[&\s]|$)',text)):
        return Decision(True,'client_selected_function_loader','function-loader action plus client-selected phpinfo')
    return Decision(False,'retain_probe_without_direct_exploitation')


def apply(frame,baseline):
    labels=list(baseline)
    decisions=[]
    for position,(pipeline,message) in enumerate(zip(frame.pipeline,frame.message_sanitized)):
        if pipeline!='payload' or labels[position]!='suspicious':continue
        decision=classify(message)
        if decision.promote:labels[position]='malicious'
        decisions.append((position,decision))
    return labels,decisions
