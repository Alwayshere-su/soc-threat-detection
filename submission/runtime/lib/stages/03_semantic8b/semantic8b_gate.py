"""Reject unsupported semantic suggestions; confidence alone is insufficient."""
import re
from payload_policy_v4 import regions
from semantic_gate import STRONG
from request_context import make_regions

VERSION='independent_8b_evidence_gate_v3'

def eligible(message,result):
    if result.get('label') not in ('malicious','suspicious'):return False,'no_threat_proposal'
    if not result.get('evidence_anchor_verified'):return False,'unverified_quote'
    data,context=regions(message)
    if data is None:return False,'excluded_context'
    target=data['target'];body=data['body'].strip().strip('|').strip()
    if context=='fragment' and re.search(r'\n(?:host|user-agent|content-type|connection):',body):
        target=re.sub(r'\s+http/\d(?:\.\d)?\s*$','',target)
        body=make_regions(body,target)['body'].strip().strip('|').strip()
    text=target+'\n'+body
    strong=bool(STRONG.search(text))
    corroborated=strong or bool(re.search(r'<!entity|<\?php|<%@|<%\s*(?:out\.|response\.)|'
        r'templatesimpl|ysoserial|invokertransformer|(?:@type.{0,800}(?:jdbc|c3p0|jndi))|'
        r'(?:[;|`]|\$\()\s*(?:echo|id\b|whoami|wget|curl|touch|expr|ping)|'
        r'(?:spring\.cloud\.function\.routing-expression|classloader|defineclass|findvalue\s*\()',text,re.I|re.S))
    sensitive=bool(re.search(r'(?:\.bash_history|\.git/(?:config|index)|\.htpasswd|/etc/(?:passwd|shadow)|'
        r'(?:[a-z]:[/\\]*)?(?:windows|winnt)[/\\]*win\.ini|php://filter|'
        r'(?:\.\.[/\\]){2,}.{0,150}(?:password|config|database|application|thinvnc)[\w.-]*\.(?:ini|properties|ya?ml|php)|'
        r'(?:\.\.[/\\]){2,}.{0,150}\.(?:jsp|aspx?|php)(?:[?&\s]|$))',text,re.I|re.S))
    active_primitive=corroborated or sensitive or bool(re.search(
        r'\bunion\s*\(\s*select|\b(?:and|or)\s+\d+\s*[=<>]+\s*@@version|'
        r'(?:^|\n)(?:testcmd|cmd|command)\s*:\s*(?:whoami|id)\b|'
        r'(?:(?:\.\.[/\\]){2,}.{0,120}\.txt.{0,30}pk)|'
        r'\$\{ifs\}.{0,200}(?:wget|curl|sh)|(?:wget|curl).{0,200}\$\{ifs\}',text,re.I|re.S))
    reason=result.get('reason','')
    if not corroborated and re.search(r'@rsyncd|--sender|--backup-dir|lookbehind|greedy:',text):
        return False,'normal_protocol_or_source_fragment'
    if not corroborated and ('redis_version:' in text and '# server' in text):
        return False,'server_status_output_without_exploit'
    if (not corroborated and not body and re.search(r'(?:^|[?&])dev_sn=(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?:&|$)',target)):
        return False,'device_serial_only_request'
    if not corroborated and re.search(r'编码|特殊格式|特殊字符|随机字符串|长字符串|疑似数据传输',reason):
        return False,'opaque_bytes_or_encoding_not_proof'
    if result.get('label')=='malicious' and not active_primitive:
        return False,'no_corroborating_exploit_primitive'
    if re.search(r'频繁|多次|批量|爆破|暴力',reason) and not strong:
        return False,'unsupported_frequency_in_single_request'
    if re.search(r'凭证|明文|密码|口令|账号|认证探测',reason) and not strong:
        return False,'credentials_alone_not_exploit'
    if re.search(r'clickhouse|x-clickhouse|\bformat\s+(?:csv|json|tabseparated|rowbinary)',text+'\n'+'\n'.join(data['headers'])):
        return False,'ordinary_database_client'
    if re.search(r'"(?:jobid|executorhandler|gluetype)"\s*:',body):return False,'scheduled_job_context'
    if not body and '?' not in target and '=' not in target and not sensitive:
        return False,'bare_endpoint_without_attack_structure'
    if re.search(r'(?:base64url|data:image/)',target) and not strong and re.search(r'编码|随机|长字符串|异常字符',reason):
        return False,'opaque_encoding_not_proof'
    # Direct business SQL APIs legitimately carry complete queries.
    business_sql=bool(re.search(r'(?:[?&](?:query|sql)=\s*(?:select|insert)|"(?:content|sql)"\s*:\s*"\s*(?:select|insert))',text))
    sql_exploit=bool(re.search(r'\bunion\s+(?:all\s+)?select\b|\b(?:sleep|extractvalue|updatexml|hashbytes)\s*\(|\binto\s+outfile\b|[\'\"]\s*(?:or|and)\s+[\'\"\d]',text))
    if business_sql and not sql_exploit and 'sql' in reason.lower():return False,'business_query_without_injection_evidence'
    if result.get('label')=='malicious' and re.search(r'扫描|枚举|弱口令|默认凭证|端点探测',reason) and not strong:
        return False,'probe_does_not_justify_malicious'
    if result.get('confidence')=='high':return True,'anchored_high_confidence_semantics'
    if result.get('label')=='malicious' and result.get('confidence')=='medium' and strong:
        return True,'anchored_medium_with_structural_corroboration'
    return False,'insufficient_confidence'


def proposal_label(message,result):
    # An executable extension disguised as an image is a concrete upload probe,
    # but without executable content we retain the weaker suspicious class.
    if (result.get('label')=='malicious' and result.get('confidence')=='high'
            and result.get('evidence_anchor_verified')):
        data,_=regions(message)
        if data is not None:
            text=data['target']+'\n'+data['body']
            executable_name=re.search(r'filename\s*=\s*[\'\"][^\'\"]{0,180}\.(?:php\d?|phtml|jspx?|aspx?)\.?[\'\"]',text,re.I)
            disguised_image=re.search(r'content-type\s*:\s*image/',text,re.I)
            executable_content=re.search(r'<\?(?:php|=)|<%|<script[^>]{0,100}runat|\b(?:eval|system|exec)\s*\(',text,re.I)
            if executable_name and disguised_image and not executable_content:
                adjusted=dict(result,label='suspicious')
                accepted,why=eligible(message,adjusted)
                return ('suspicious','executable_image_upload_probe') if accepted else (None,why)
    accepted,why=eligible(message,result)
    return (result['label'] if accepted else None),why
