"""Inspect missed request fragments and encoded evidence, never execute input."""
from dataclasses import dataclass
import base64
import html
import re
from urllib.parse import unquote_plus

VERSION='payload_fragment_v3'

@dataclass(frozen=True)
class Decision:
    label: str | None
    reason: str
    context: str
    evidence: str=''


def normalized(message):
    text=str(message or '').replace('\r\n','\n').replace('\r','\n')
    for _ in range(2):
        text=re.sub(r'\\+u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),text)
        text=re.sub(r'\\+r\\+n|\\+n|\\+r','\n',text)
        text=html.unescape(unquote_plus(text))
        text=re.sub(r'\\+(["\'])',r'\1',text)
    text=re.sub(r'(?:~[0-9a-fA-F]{2}){3,}',lambda m:bytes.fromhex(m[0].replace('~','')).decode('latin1'),text)
    return text.lower()


EMBEDDED=re.compile(r'"messages"\s*:|"payloads"\s*:|classify\s+(?:the\s+)?request|plaintext password|'
                    r'normal image file|you are\s+(?:a|an)|\\u4f60\\u662f|【补充判定规则】|'
                    r'rs_operation_load_log|rs_application_\w+log|ponshine_datatype|safety-middleground_log|'
                    r'"(?:operationcontent|operation_log|interceptcommand|networkcloud_type|kpis)"\s*:|'
                    r'snc\.script\.cmd\.|"request"\s*:\s*"agent data"|'
                    r'protection\(\d+\)=|hitdir\(\d+\)=|disposal_suggestion\s*=|data_auth_id\s*=|'
                    r'lookbehind\s*:|greedy\s*:|inside\s*:\s*\{|(?:apt-cache\|apt-get|groupadd\|groupdel)',re.I)
FRAME=re.compile(r'^\s*\d+(?:,\d+){3,},')
HTTP=re.compile(r'(?:^|\n|[^a-z])(?:get|post|put|patch|delete|head|options|connect|trace)\s+([^\n]{1,16000}?)\s+http/\d(?:\.\d)?',re.I)

PATTERNS=[
    ('sql_false_boolean_probe',r'(?:[\'\"]|\b\d+)\s+(?:or\s+not|and\s+not)\s+(\d{3,})\s*=\s*\1\s*--'),
    ('sql_string_boolean_probe',r'[\'\"]\s*(?:or|and)\s*[\'\"](\w{1,12})[\'\"]\s*=\s*[\'\"]\1(?:[\'\"&#\s]|$)'),
    ('sql_hash_function_probe',r'(?:^|[?&\n]|<\w+>)\w{1,50}[^=\n]{0,10}=.{0,120}(?:sys\.fn_(?:varbintohexstr|sqlvarbasetostr)\s*\(\s*hashbytes\s*\(\s*[\'\"]md5)'),
    ('sql_delay_function_parameter',r'(?:^|[?&\n])\w{1,60}=\s*(?:pg_sleep|sleep|benchmark)\s*\(\s*\d+(?:\s*,|\s*\))'),
    ('sql_diagnostic_function',r'(?:select|\band\b|\bor\b).{0,200}(?:sys\.fn_(?:varbintohexstr|sqlvarbasetostr)\s*\(\s*hashbytes|dbms_pipe\.receive_message\s*\(|(?:extractvalue|updatexml)\s*\()'),
    ('sql_file_write',r'\b(?:select|union)\b.{0,2500}\binto\s+(?:out|dump)file\s*[\'\"][^\n]{0,300}\.(?:php\d?|jsp|aspx?)'),
    ('sql_hash_probe',r'(?:^|[?&])(?:query|sql)\s*=\s*select\s+(?:lower\s*\(\s*hex\s*\(\s*)?md5\s*\(\s*[\'\"]\d{5,}[\'\"]\s*\)'),
    ('sql_error_based_count',r'\bselect\b.{0,800}\bconcat\s*\(.{0,400}\bfloor\s*\(\s*rand\s*\(\s*0\s*\)\s*\*\s*2'),
    ('sql_union_obfuscated',r'\bunion\s+(?:all\s+)?select\b.{0,250}(?:@@version|information_schema|md5\s*\(|\bnull\b|\d\s*,)'),
    ('ognl_context_execution',r'(?:ognl|struts2\.context|memberaccess).{0,600}(?:findvalue\s*\(|getruntime|allowstaticmethodaccess|excludedclasses)'),
    ('java_expression_execution',r'(?:\$|#)\{.{0,1200}(?:classloader|\.forname\s*\(|getruntime|\.exec\s*\(|defineclass)'),
    ('java_xml_workcontext_gadget',r'(?:workcontext|oracle\.toplink\.internal\.sessions\.unitofworkchangeset|keystoreresolver\$keystoreiterator).{0,2500}(?:array class=[\'\"]byte|lazysearchenumerationimpl|jdbcrowset|jndi)'),
    ('java_serialized_dns_gadget',r'java\.util\.hashmap.{0,1000}java\.net\.url.{0,1200}(?:authority|protocol|host)'),
    ('java_serialized_exec_gadget',r'(?:invokertransformer|templatesimpl|jdbcrowsetimpl|badattributevalueexpexception|unicastref).{0,2000}(?:getruntime|\.exec|jndi|ldap|rmi|java\.lang|traxfilter)'),
    ('xxe_external_entity',r'<!entity\s+%?\s*\w+\s+(?:system|public)\s+[\'\"](?:https?://|file:/|ftp://)'),
    ('php_upload_self_delete',r'<\?(?:php|=).{0,1400}(?:unlink\s*\(\s*__file__|file_put_contents\s*\(|(?:system|shell_exec|eval|assert)\s*\()'),
    ('jsp_executable_upload',r'(?:filename|filepath|<filename>|file_path|file_name).{0,220}\.(?:jsp[x]?|aspx?).{0,2000}(?:<%@\s*page|<%\s*(?:out\.|response\.|java\.)|<script[^>]{0,100}runat)'),
    ('jsp_marker_execution',r'<%\s*(?:out\.print|response\.write|new\s+java\.io\.file|@\s*page\s+language\s*=).{0,900}(?:delete\s*\(|getparameter|out\.print|response\.write|[\'\"][a-f0-9]{20,})'),
    ('postscript_pipe_execution',r'%!ps.{0,1500}%pipe%\s*(?:id|whoami|cat|curl|wget|/bin/)'),
    ('shell_command_separator',r'(?:[;|`]|\$\()\s*(?:/bin/(?:busybox\s+)?|busybox\s+)?(?:ping\s+[-\w.]{3,}|touch\s+[/\w.\-]+|expr\s+\d+\s+[-+*/]|sleep\s+\d+|whoami\b|id\b|cat\s+(?:<+)?/(?:etc|proc)/)'),
    ('shell_download_and_execute',r'\b(?:wget|curl)\b.{0,500}\bchmod\s+.{0,50}(?:\+x|777).{0,250}(?:setsid|\./|/bin/(?:ba)?sh)'),
    ('phpinfo_function_call',r'(?:^|[?&])(?:func|function|functionname|call|callback|f|c|a|cmd|command)\s*=\s*phpinfo(?:\s*\(\s*\))?(?:[&;\s]|$)'),
    ('sensitive_file_argument',r'(?:^|[?&\n])(?:db|database|download_file|filename|filepath|fullpath|path|file|realpath|urlpath|dir)\s*=\s*(?:[a-z]:[/\\]+(?:windows|winnt)[/\\]+win\.ini|/(?:windows/win\.ini|etc/(?:passwd|shadow|hosts)))(?:[&\s\x00]|\\?u0000|$)'),
    ('executable_traversal_write',r'(?:filename|filepath|file_name|file_path)\s*=\s*(?:\.{2}[/\\]+){2,}[^&\n]{0,160}\.(?:jsp|aspx?|php)(?:[&\s]|$)'),
    ('couchdb_duplicate_roles',r'"roles"\s*:\s*\[\s*"_admin"\s*\].{0,80}"roles"\s*:\s*\[\s*\]'),
    ('preload_elf_execution',r'ld_preload\s*=\s*/proc/self/fd/\d+.{0,1500}(?:elf|u007felf)'),
    ('exchange_proxy_resource_chain',r'x-anonresource-backend\s*=.{0,200}/ecp/.{0,150}x-beresource\s*=.{0,200}/owa/'),
    ('explicit_shell_command_argument',r'(?:^|[?&\n])(?:cmd|cmdline|shellcmd|command|commandtext)=\s*(?:expr\s+\d+\s+[-+*/ ]\s*\d+|set\s+/a\s+\d+\s*[-+*/]|type\s+\d+\s+\d+)'),
]
COMPILED=[(reason,re.compile(pattern,re.I|re.S)) for reason,pattern in PATTERNS]

# A case-folded log may have irreversibly altered base64's letter case. Match
# bounded encoded byte signatures instead of claiming that damaged text decoded.
ENCODED_PHRASES={
    'sql_file_write':['into outfile','INTO OUTFILE','into dumpfile','INTO DUMPFILE'],
    'sql_union':['union select','UNION SELECT','union all select','UNION ALL SELECT'],
    'sensitive_file':['/etc/passwd','/etc/shadow'],
    'execution':['java.lang.Runtime','getRuntime().exec','System.Diagnostics.Process','unlink(__FILE__)','file_put_contents',
                 'Response.Write(', 'Response.Write("','response.write(', 'System.IO.File.Delete','defineClass'],
}


def encoded_signatures():
    result=[]
    for family,phrases in ENCODED_PHRASES.items():
        for phrase in phrases:
            for offset in range(3):
                data=b'A'*offset+phrase.encode()
                encoded=base64.b64encode(data).decode()
                encoded=encoded[4 if offset else 0:len(data)//3*4]
                if len(encoded)>=12:result.append((family,encoded.lower()))
    return result

ENCODED_SIGNATURES=encoded_signatures()


def classify(message):
    text=normalized(message)
    text=re.split(r'\n\s*response_(?:code|message)\s*:',text,maxsplit=1)[0]
    framed=bool(FRAME.match(text))
    text=FRAME.sub('',text,count=1).strip()
    if EMBEDDED.search(text):return Decision(None,'excluded_nested_or_operational_context','excluded')
    if re.search(r'"\s*,\s*"(?:get|post|put|\d+,)',text):
        return Decision(None,'quoted_request_array_fragment','excluded')
    request=HTTP.search(text)
    context='http_request' if request and request.start()<512 else 'structured_fragment'
    if context=='http_request':
        target=request.group(1)
        if re.match(r'^/(?:api/array2singlemsg|gateway/api/|v1/chat/completions|v1/embeddings)',target):
            return Decision(None,'transport_endpoint','excluded')
        # Headers such as Accept: */* are not query or command evidence.
        suffix=text[request.end():]
        lines=suffix.split('\n')
        last_header=0
        for index,line in enumerate(lines):
            if re.match(r'^[a-z][a-z0-9_-]{0,60}\s*:',line):last_header=index
            elif last_header and not line.strip():break
        body='\n'.join(lines[last_header+1:])
        evidence_text=target+'\n'+body
        if re.search(r'clickhouse|x-clickhouse|format\s+(?:csv|rowbinary|tabseparated)',text):
            sql_client=True
        else:sql_client=False
    else:
        evidence_text=text
        sql_client=False
    for reason,pattern in COMPILED:
        if sql_client and reason.startswith('sql_'):continue
        if reason.startswith('shell_') and context!='http_request' and not framed and not (
                re.match(r'^[\w.\[\]-]{1,80}\s*=',text) or re.search(r'\b(?:username|userpassword)\s*=',text)):
            continue
        hit=pattern.search(evidence_text)
        if hit:return Decision('malicious',reason,context,hit[0])
    # Strong syntax in truncated protocol bodies, without fabricating HTTP context.
    if context=='structured_fragment':
        import payload_policy_v2 as older
        for reason,pattern in older.MALICIOUS:
            if reason in ('jsp_embedded_script','shell_marker_write','shell_marker_tee','command_execution_parameter') and not framed:
                continue
            if reason.startswith('sql_') and sql_client:continue
            hit=re.search(pattern,evidence_text,re.I|re.S)
            if hit:return Decision('malicious','fragment_'+reason,context,hit[0])
    raw_request=re.split(r'(?:\r?\n|\\r\\n|\\n)\s*response_(?:code|message)\s*:',str(message),maxsplit=1,flags=re.I)[0].lower()
    for token in re.findall(r'(?<![a-z0-9+/])[a-z0-9+/]{40,16000}={0,2}',evidence_text+'\n'+raw_request):
        families={family for family,signature in ENCODED_SIGNATURES if signature in token}
        if not families:continue
        if 'sql_file_write' in families or ('sql_union' in families and re.search(r'(?:[?&]|^)\w*(?:sql|par|data)\w*=',evidence_text)):
            return Decision('malicious','casefolded_base64_sql_signature',context,'encoded SQL exploitation byte signature')
        if 'execution' in families and re.search(r'(?:upload|filename|bufvalue|\.jsp|\.aspx|\.php)',evidence_text):
            return Decision('malicious','casefolded_base64_execution_signature',context,'encoded execution byte signature in file-upload context')
        if 'sensitive_file' in families and re.search(r'(?:[?&]|^)(?:path|file|url|dl)=',evidence_text):
            return Decision('malicious','casefolded_base64_sensitive_file_signature',context,'encoded sensitive file byte signature in file argument')
    # Structural traversal in URL parameters bypasses ordinary route handling.
    if context=='http_request':
        if re.search(r'/\.\.;/',target):
            return Decision('suspicious','semicolon_path_traversal',context,'semicolon traversal syntax')
        if re.search(r'/(?:phpinfo\.php|(?:owncloud/)?apps/graphapi/vendor/microsoft/microsoft-graph/tests/getphpinfo\.php)(?:\?|$)',target):
            return Decision('suspicious','phpinfo_information_probe',context,'phpinfo endpoint')
        if re.search(r'(?:^|[?&\n])\w+=\s*phpinfo\s*\(\s*\)',evidence_text) or re.search(r'(?:^|[?&\n])(?:function|callback|call|func)=phpinfo(?:[&\s]|$)',evidence_text):
            return Decision('suspicious','phpinfo_callback_probe',context,'phpinfo requested as callback/function')
        if re.search(r'(?:[?&])(?:file|filename|path|aam-media|adjunctfile)=[^&]{0,100}(?:web\.config|wp-config\.php|/etc/group)(?:[?&\s]|$)',target):
            return Decision('suspicious','configuration_file_argument_probe',context,'sensitive configuration in file parameter')
        if re.search(r'(?:\.gitlab-ci\.bak|settings\.php\.bak|/api/jolokia/list|/@fs/etc/group|/cgi-bin/admin\.cgi\?command=getusernamepassword)',target):
            return Decision('suspicious','specific_sensitive_resource_probe',context,'sensitive resource query')
        if re.search(r'(?:[?&]|^)(?:ld_debug|ld_preload)=',target):
            return Decision('suspicious','dynamic_loader_environment_probe',context,'client supplied dynamic-loader environment')
    return Decision(None,'no_additional_evidence',context)


def apply(frame,baseline):
    labels=list(baseline)
    audit=[]
    for position,(pipeline,message) in enumerate(zip(frame.pipeline,frame.message_sanitized)):
        if pipeline!='payload' or labels[position]!='benign':continue
        decision=classify(message)
        if decision.label:labels[position]=decision.label
        audit.append((position,decision))
    return labels,audit
