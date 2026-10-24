"""Train-only experimental features; the scored portable_v1 extractor is unchanged."""
import re
import numpy as np
import pandas as pd

VERSION='semantic_v2'

def extras(frame,base):
    msg=frame.message_sanitized.fillna('').astype('string[pyarrow]')
    low=msg.str.lower()
    out=pd.DataFrame(index=frame.index)
    product=frame.product_name.fillna('').astype(str).str.strip()
    vendor=frame.vendor_name.fillna('').astype(str).str.strip()
    out['meta_product_missing']=product.eq('').astype(np.int8)
    out['meta_vendor_missing']=vendor.eq('').astype(np.int8)
    port=pd.to_numeric(frame.src_port,errors='coerce') if 'src_port' in frame else pd.Series(-1,index=frame.index)
    out['structured_src_port']=port.where(port.between(0,65535),-1).fillna(-1).astype(np.int32)
    out['n_host_tokens']=msg.str.count(r'HOST-\d+').astype(np.int32)
    out['family_duo']=low.str.contains(r'duo_push|duo_mobile|cisco_duo|streamname\s*=\s*duo',regex=True).astype(np.int8)
    out['family_duo_inventory']=(out.family_duo.eq(1)&base.b_asset_inventory.eq(1)).astype(np.int8)
    patterns={
        'auth_json_denied':r'"result"\s*:\s*"(?:denied|failure|failed|reject(?:ed)?)"',
        'auth_json_success':r'"(?:result|outcome)"\s*:\s*"(?:success|allowed|allow|accepted)"',
        'auth_user_denied':r'user_denied|user denied|fraudulent|fraud_report',
        'auth_no_response':r'no_response|no response|push_timeout|push timeout',
        'auth_bad_passcode':r'invalid_passcode|invalid passcode|bad password|unknown user name',
        'auth_low_trust':r'"trust_level"\s*:\s*"low"',
        'auth_unset_trust':r'"trust_level"\s*:\s*"unset"',
        'negated_detection':r'no detection|no known (?:attack|threat)|not (?:malicious|suspicious)',
        'powershell':r'powershell|pwsh',
        'encoded_command':r'encodedcommand| -enc(?:\s|oded)',
        'audit_failure':r'audit failure|audit_failure|"outcome"\s*:\s*"failure"',
        'account_failed_logon':r'an account failed to log on|failed (?:password|logon|login)',
    }
    for name,pat in patterns.items():out[name]=low.str.contains(pat,regex=True).astype(np.int8)
    json_mask=base.is_elk_json.eq(1)
    code=pd.Series(-1,index=frame.index,dtype=np.int32)
    if json_mask.any():
        values=low.loc[json_mask].str.extract(r'"(?:event_id|eventid|code)"\s*:\s*"?(\d{3,6})"?',expand=False)
        code.loc[json_mask]=pd.to_numeric(values,errors='coerce').fillna(-1).astype(np.int32)
    out['json_win_event_id']=code
    out['effective_win_event_id']=base.win_event_id.where(base.win_event_id.gt(0),code).astype(np.int32)
    for name,events in {'win_logon_failure':[4625],'win_logon_success':[4624],
                        'win_process_created':[4688],'win_special_privileges':[4672],
                        'win_log_cleared':[1102],'win_account_created':[4720]}.items():
        out[name]=out.effective_win_event_id.isin(events).astype(np.int8)
    cef=base.is_cef.eq(1)
    severity=pd.Series(-1,index=frame.index,dtype=np.int16)
    cef_name=pd.Series('',index=frame.index,dtype='string[pyarrow]')
    if cef.any():
        fields=low.loc[cef].str.extract(r'cef:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|([^|]*)\|([^|]*)\|',expand=True)
        cef_name.loc[cef]=fields[0].fillna('')
        sev=fields[1].str.strip()
        numeric=pd.to_numeric(sev,errors='coerce')
        named=sev.map({'low':3,'medium':5,'high':8,'very-high':10,'unknown':-1})
        severity.loc[cef]=numeric.fillna(named).where(lambda x:x.between(0,10),-1).fillna(-1).astype(np.int16)
    out['cef_severity']=severity
    for name,pattern in {'exfiltration':'exfiltrat','flood':'flood','concern':'concern',
                         'hoarding':'hoarding','suspicious':'suspect|suspicious',
                         'malware':'malware|ransom|trojan|exploit'}.items():
        out['cef_'+name]=cef_name.str.contains(pattern,regex=True).astype(np.int8)
    return out

def template_groups(messages):
    s=messages.fillna('').astype('string[pyarrow]')
    for pattern,replacement in [
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b','IP'),
        (r'[A-Z]{2,10}-\d+(?:-\d+)*','TOKEN'),
        (r'(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b','UUID'),
        (r'\b[0-9a-fA-F]{16,}\b','HEX'),(r'\d+','#'),(r'\s+',' ')]:
        s=s.str.replace(pattern,replacement,regex=True)
    s=s.str.strip().str.lower()
    return pd.util.hash_pandas_object(s,index=False).to_numpy(dtype=np.uint64)
