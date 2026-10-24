"""Evidence-based extension for residual payloads; no IDs, fitting or labels."""
from dataclasses import dataclass
import base64
import re
from urllib.parse import parse_qsl

from payload_policy_v3 import normalized,FRAME,EMBEDDED
from request_context import make_regions

VERSION='residual_payload_v4'

@dataclass(frozen=True)
class Decision:
    label: str | None
    reason: str
    context: str
    evidence: str=''

REQUEST=re.compile(r'(get|post|put|patch|delete|head|options)\s+(/[^\n]{0,16000}?)\s+http/\d(?:\.\d)?',re.I)
TRUNCATED_REQUEST=re.compile(r'^(get|post|put|patch|delete|head|options)\s+(/[^\n]{1,5000})$',re.I)

def regions(message):
    text=normalized(message)
    text=re.split(r'\n\s*response_(?:code|message)\s*:',text,maxsplit=1)[0]
    framed=bool(FRAME.match(text))
    text=FRAME.sub('',text,count=1).strip()
    if EMBEDDED.search(text) or re.search(r'"\s*,\s*"(?:get|post|put|\d+,)',text):return None,'excluded'
    request=REQUEST.search(text)
    if request and request.start()<512:
        prefix=text[:request.start()]
        if re.search(r'[{}]|"role"\s*:|\[tool:',prefix):return None,'excluded'
        text=text[request.start():]
        target=request.group(2)
        result=make_regions(text,target)
        result['method']=request.group(1)
        if re.match(r'^/(?:api/array2singlemsg|gateway/api/|v1/chat/completions|v1/embeddings)',target):return None,'excluded'
        return result,'http_request'
    request=TRUNCATED_REQUEST.match(text.split('\n',1)[0])
    if request:
        result=make_regions(text,request.group(2));result['method']=request.group(1)
        return result,'truncated_http_request'
    if (framed or re.match(r'^(?:[\w.\[\]-]{1,100}\s*=|/|<\?xml|<!doctype|\{\s*[\'\"]|content-disposition:)',text)
            or re.search(r'content-disposition:.{0,200}filename=',text,re.S)):
        if re.search(r'\[root@|root,\s*cmd=| by root from |login_type=',text):return None,'excluded'
        # Keep all fragment text for strong patterns without inventing an HTTP wrapper.
        return dict(target=text.split('\n',1)[0],body=text,headers=[],header_items=[],values=[text],names=[],method=''),'fragment'
    return None,'unstructured'


MALICIOUS=[
    ('sql_time_comparison',r'\b(?:and|or)\s+(?:\d+\s*=\s*)?(?:sleep|pg_sleep|benchmark)\s*\(\s*\d+'),
    ('sql_identifier_version_expression',r'(?:^|[?&\n])\w*(?:id|no)\s*=\s*@@version(?:[&\s]|$)'),
    ('sql_path_grammar_injection',r'/(?:getdictitemsbytable|querytabledata)/[\'\"]\s+from\s+(?:sys_user|\w{1,60})\s*(?:/\*|--)'),
    ('java_class_lookup_expression',r'(?:#this|#request|#context|\$\{|#\{).{0,300}(?:getclass\s*\(\s*\)\s*\.\s*forname\s*\(|class\.forname|loadclass\s*\()'),
    ('fastjson_c3p0_jndi_gadget',r'(?:@type|java\.lang\.class).{0,1200}(?:com\.mchange\.v2\.c3p0\.(?:jndirefconnectionpooldatasource|wrapperconnectionpooldatasource)).{0,1500}(?:jndi|useroverridesasstring|ldap|rmi|hexascii)'),
    ('multipart_php_execution_marker',r'filename\s*=\s*[\'\"][^\'\"]{0,180}\.(?:php\d?|phtml)[\'\"].{0,1800}<\?php.{0,300}(?:echo\s+md5\s*\(|unlink\s*\(\s*__file__|(?:eval|system|assert)\s*\()'),
    ('traversal_sensitive_config',r'(?:\.\.[/\\]+){2,}[^\n&]{0,250}(?:winnt[/\\]+win\.ini|wp-config\.php|web\.config|application\.(?:ya?ml|properties)|appsettings\.json|settings\.js|fileserver\.sh)(?:[&\s\x00]|$)'),
    ('direct_sensitive_credential_or_dump',r'(?:^|/)(?:\.htpasswd|(?:db|database|dump|backup)\.sql)(?:[?&#\s]|$)'),
    ('apisix_full_config_export',r'^/apisix/admin/migrate/export(?:[?&#\s]|$)'),
]
COMPILED=[(name,re.compile(pattern,re.I|re.S)) for name,pattern in MALICIOUS]


def byte_signatures(phrases,min_length=12):
    result=[]
    for phrase in phrases:
        for offset in range(3):
            data=b'A'*offset+phrase.encode()
            value=base64.b64encode(data).decode()[4 if offset else 0:len(data)//3*4].lower()
            if len(value)>=min_length:result.append(value)
    return result

SQL_ENCODED=byte_signatures(['select sleep(', 'SELECT SLEEP(', 'select SLEEP(', 'waitfor delay', 'WAITFOR DELAY',
                           'sys.fn_varbintohexstr','sys.fn_sqlvarbasetostr','hashbytes(\'md5\''])
PHP_FILTER_ENCODED=byte_signatures(['php://filter','convert.base64-encode/resource='])
XSS_ENCODED=byte_signatures(['<script>alert(', '<script>confirm(', 'alert(document.domain)', 'alert(document.cookie)'])
SHELL_PREFIXES=['`echo ', '`whoami', '`ipconfig', '`cat /etc/', '`expr ',
                ' || echo ', ' || ipconfig', ' || whoami', '" || echo ', '" || ipconfig', '" || whoami']
SHELL_ENCODED_PREFIXES=[base64.b64encode(value.encode()).decode()[:len(value)//3*4].lower() for value in SHELL_PREFIXES if len(value)//3*4>=8]


def classify(message):
    result,context=regions(message)
    if result is None:return Decision(None,'excluded_or_unstructured',context)
    target=result['target'];body=result['body']
    text=target+'\n'+body
    sql_client=bool(re.search(r'clickhouse|x-clickhouse|\bformat\s+(?:rowbinary|tabseparated|csv|json)\b',text+'\n'+'\n'.join(result['headers'])))
    for reason,pattern in COMPILED:
        if reason.startswith('sql_') and sql_client:continue
        candidate=text if not reason.startswith(('direct_sensitive_','apisix_','sql_path_')) else target
        hit=pattern.search(candidate)
        if hit:return Decision('malicious',reason,context,hit[0])
    # A barcode output path with a server-executable extension is stronger than
    # an ordinary barcode request or a plugin path by itself.
    if re.search(r'/(?:barcode|qrcode)\.php(?:\?|$)',target):
        args=dict(parse_qsl(target.partition('?')[2],keep_blank_values=True))
        if (re.fullmatch(r'[1x01]{128,20000}',args.get('text','')) and
                re.search(r'\.(?:php\d?|phtml|jsp|aspx?)(?:$|[.;])',args.get('filepath',''))):
            return Decision('malicious','barcode_executable_file_write',context,'barcode bit pattern and executable output file')
    data_html=re.search(r'data:text/html;base64,([a-z0-9+/=]{12,20000})',target)
    if data_html and any(signature in data_html[1] for signature in XSS_ENCODED):
        return Decision('malicious','encoded_html_script_injection',context,'HTML data URI with encoded script execution signature')
    for token in re.findall(r'(?<![a-z0-9+/])[a-z0-9+/]{16,20000}={0,2}',text):
        if not sql_client and re.search(r'(?:^|[?&])(?:sql|querystring|query|data_s)=',target) and any(s in token for s in SQL_ENCODED):
            return Decision('malicious','encoded_sql_diagnostic_or_delay',context,'encoded database delay/diagnostic byte signature in query field')
        if any(s in token for s in PHP_FILTER_ENCODED) and re.search(r'(?:popup_shortcode_attributes|pagepath|file|path|url)',text):
            return Decision('malicious','encoded_php_stream_filter',context,'encoded PHP stream/filter in client-controlled file arguments')
    # Prefix matches are intentionally limited to a URL-conversion argument.
    # A backtick or command-chain prefix is not an ordinary encoded URL.
    for match in re.finditer(r'(?:^|[?&\n])(?:base64url|url)=([a-z0-9+/=]{16,20000})',text):
        token=match[1]
        if token.startswith(tuple(SHELL_ENCODED_PREFIXES)) and re.search(r'(?:getimage|getspiritsfromvideo|pdf_maker|imagehandler)',target):
            return Decision('malicious','encoded_shell_in_media_url',context,'encoded shell prefix in a media URL argument')
    # Structural probes need more than an admin-looking name or login fields.
    if context in ('http_request','truncated_http_request'):
        if re.search(r'/(?:wwwroot|www|webroot|backup|site|htdocs)\.(?:zip|tar(?:\.gz)?|tgz)(?:[?&#\s]|$)',target):
            return Decision('suspicious','website_source_archive_probe',context,'website source backup archive')
        if re.search(r'(?:\.\.(?:[/\\]+)|\.\\t\.[/\\]|\.[\t ]\.[/\\])',target) and re.search(r'/(?:supervisor/info|supervisor/token|supervisor/snapshot|config/)',target):
            return Decision('suspicious','obfuscated_management_traversal',context,'dot-segment bypass toward privileged management resource')
        if re.search(r'(?:^|/)(?:jmx-console/(?:htmladaptor)?|cgi-bin/exportallsettings\.sh)(?:[?&#\s]|$)',target):
            return Decision('suspicious','sensitive_admin_or_config_probe',context,'management interface or complete configuration export')
        if result['method']=='post' and re.search(r'/(?:upload|files?)\.cgi(?:\?|$)',target) and re.search(r'(?:^|[&\n])path=(?:\.\./){2,}',body):
            return Decision('suspicious','file_interface_traversal_probe',context,'parent-directory path through a file interface')
        if any(name in ('x-scanner','x-scan-device-flag') and value.strip() for name,value in result['header_items']):
            return Decision('suspicious','explicit_scanner_fragment',context,'explicit scanner/device marker on parsed request')
    return Decision(None,'no_additional_evidence',context)


def apply(frame,baseline):
    labels=list(baseline);audit=[]
    for position,(pipeline,message) in enumerate(zip(frame.pipeline,frame.message_sanitized)):
        if pipeline!='payload' or labels[position]=='malicious':continue
        decision=classify(message)
        if decision.label=='malicious' or (decision.label=='suspicious' and labels[position]=='benign'):
            labels[position]=decision.label
        audit.append((position,decision))
    return labels,audit
