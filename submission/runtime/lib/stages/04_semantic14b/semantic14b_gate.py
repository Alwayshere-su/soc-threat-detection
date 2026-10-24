"""Require corroboration for the larger model's proposals; no ID-based decisions."""
import re
from payload_policy_v5 import recover,OPERATIONS

VERSION='recovered_context_semantic_gate_v13'
STRONG=re.compile(r'(?:<\?(?:php|=)|<%|<!entity|\bunion\s+(?:all\s+)?select\b|\bwaitfor\s+delay|'
    r'\b(?:updatexml|extractvalue|sleep|system|eval|exec|file_get_contents)\s*\(|'
    r'class\.forname|defineclass|getclassloader\s*\(|jdbcrowsetimpl|getruntime\s*\(|'
    r'java[/\.]lang[/\.](?:runtime|processbuilder)|new\s+processbuilder|'
    r'\$\{jndi:|\#\{t\(|\b(?:information_schema|fn_sqlvarbasetostr|hashbytes)\b|'
    r'(?:[;|`]\s*(?:echo|cat|wget|curl)\b)|onerror\s*=|<script\b)',re.I)
SENSITIVE=re.compile(r'/etc/(?:passwd|shadow)|(?:windows|winnt)[/\\]*win\.ini|\.git/(?:config|index)|'
    r'(?:\.\.[/\\]){2,}.{0,160}(?:password|config|application|database|web-inf|thin[vw]nc)|php://filter|'
    r'/\.aws/credentials|/\.ssh/config(?:[?\s]|$)|/@fs/etc/(?:group|hosts)|/_profiler/open\?file=[^&\s]*config/parameters\.ya?ml|'
    r'[?&](?:file|filename|filepath)=web\.config(?:[&\s]|$)',re.I|re.S)
PUBLIC_PROBE=re.compile(r'\.\.[/\\]|\.idea/|\.ds_store|\.git/|\.svn/|/actuator|/jmx-console|/jolokia|'
    r'/cfide/adminapi/|/manager/(?:html|text/list)|/jkstatus;|/solr/admin/cores|/v1/agent/self|'
    r'/api/v1/clusters/kubeconfig|/yyoa/ext/https/getsessionlist|/cgi-bin/(?:exportcfg|export-cgi|exportlogs)|'
    r'/form/exportconfig|/level/15/exec/show/config|/data/pbootcms\.db|\.config\.i18n\.ashx|'
    r'/mgmt/tm/util/bash|/application/runtime/logs/home/[^\s?]+\.log|/\.well-known/.*openapi|mstshash=nmap|'
    r'/(?:webshell\.(?:php|jsp)|shell\.aspx)(?:[?\s]|$)|/_profiler/phpinfo(?:[?\s]|$)',re.I)

def proposal(message,result):
    label=result.get('label')
    if label not in ['malicious','suspicious']:return None,'no_threat_proposal'
    if not result.get('evidence_anchor_verified'):return None,'unverified_evidence'
    data,context=recover(message)
    if data is None:return None,'protected_context'
    target=data['target'];body=data['body'];text=target+'\n'+body+'\n'+'\n'.join(name+': '+value for name,value in data['headers'])
    text=re.sub(r'~([0-9a-f]{2})',lambda match:chr(int(match[1],16)),text,flags=re.I)
    if context=='direct_fragment' and re.match(r'http/\d(?:\.\d)?\s+\d{3}\b',target):
        return None,'response_only_without_request'
    if (data['method']=='post' and re.match(r'^/\d{1,3}(?:\.\d{1,3}){3}/[^?\s]+\.\d{14}$',target)
            and 'filename="/unios/pxm/unios-pxm-dfs/bin/../../data/' in body
            and re.search(r'# timos-c-|!software version v\d',body)):
        return None,'network_device_configuration_backup'
    if (target.endswith('.pdf') and 'filename="/unios/pxm/unios-pxm-dfs/bin/../../data/' in body
            and re.search(r'%pdf-1\.\d',body) and not re.search(r'/(?:javascript|launch|openaction|embeddedfile)\b',body)):
        return None,'ordinary_opaque_pdf_document_upload'
    if re.search(r'\bformat\s+(?:rowbinary|tabseparated|tsv|csv|json)|clickhouse|x-clickhouse',text):return None,'business_database_client'
    if re.search(r'"(?:jobid|executorhandler|gluetype)"\s*:',body):return None,'scheduled_job'
    if re.search(r'@rsyncd|--sender|--backup-dir|redis_version:|lookbehind:|greedy:',text):return None,'ordinary_protocol_or_code'
    if context=='direct_fragment' and re.search(r'(?:\b[a-z][a-z0-9_-]{1,25}\|){6,}',text):return None,'command_name_wordlist'
    confidence=result.get('confidence')
    if confidence not in ['high','medium']:return None,'insufficient_confidence'
    strong=bool(STRONG.search(text))
    # Code fragments must contain more than an opening tag or isolated filename.
    if context=='direct_fragment' and len(text.strip())<50 and not re.search(r'\$\{jndi:|<!entity|union\s+select|\bsleep\s*\(',text):strong=False
    java_graph=bool(re.search(r'abstracttranslet|java[/\.]lang[/\.]processbuilder|templatesimpl',text) and re.search(r'tomcatecho|setaccessible|defineclass|cmd\.exe|/bin/sh|bytecode|java[/\.]util[/\.]scanner',text))
    java_graph=java_graph or bool(re.search(r'ysoserial[/\.]payloads[/\.]util[/\.]gadgets',text)
        and re.search(r'_bytecodes|stubtransletpayload|_transletindex',text))
    php_object_graph=bool(re.search(r'yii[\\\s]+(?:r?est|base)[\\\s]+(?:createaction|component)',text)
        and re.search(r'checkaccess.{0,35}assert|file_put_contents\s*\(',text,re.S))
    xml_script_execution=bool(re.search(r'<void\s+class="bsh\.interpreter"',text)
        and re.search(r'<void\s+method="eval"',text))
    code_injection=bool(re.search(r'(?:&&|\|\||;|`)\s*(?:whoami|id)\b|(?:\$|#)\{.{0,160}(?:getclass|forname|runtime|processbuilder|java\.lang)|'
        r'\b(?:utilcmdargs|oscommand|execcommand)[\"\s:=]+.{0,80}(?:-c\s+id\b|whoami)|'
        r'\$\{ifs\}.{0,150}(?:wget|curl|/bin/sh)|(?:wget|curl).{0,150}\$\{ifs\}|'
        r'\{\.exec\||[\'\"]\s*(?:and|or)\s+(?:gtid_subset|json_keys)\s*\(',text,re.I|re.S))
    template_injection=bool(re.search(r'"_template"\s*:\s*"(?:\.\./)+[^"\n]{0,120}(?:web\.xml|web-inf/)',text)
        and re.search(r'"(?:macro|name)"\s*:\s*(?:\{|"widget")',text))
    template_injection=template_injection or bool(re.search(r'\$\\+c\s*\{\s*\d{4,}\s*[*+/-]\s*\d{4,}\s*\}',text)
        and re.search(r'/rest/(?:beta|v1)/repositories|"membernames"',text))
    php_cgi_injection=bool(re.search(r'-d\s+allow_url_include\s*=\s*(?:on|1)',text)
        and re.search(r'-d\s+auto_prepend_file\s*=\s*php://input',text))
    sql_error_probe=bool(re.search(r"[?&][^=&\s]+=[^\n]{0,350}'\s*(?:and|or)\s+\d+\s*=\s*user::integer\s*--",text))
    sql_error_probe=sql_error_probe or bool(re.search(r'/geoserver/ows\?',target)
        and re.search(r'cql_filter=.*\bselect\s+cast\s*\(\s*\(select\s+md5\s*\(',text,re.S))
    sql_error_probe=sql_error_probe or bool(re.search(r"'\)?\s+and\s+convert\s*\(\s*varchar\(max\),\s*0x[0-9a-f]{8,},\s*0\)\s*>\s*\d+\s*--",text))
    shell_arithmetic_probe=bool(re.search(r'[|`]\s*(?:set\s+/a|expr)\s+\d{5,}\s*[+ -]\s*\d{4,}',text))
    report_expression_probe=bool(re.search(r'/webroot/decision/[^?]+\?',target)
        and re.search(r'[?&]sessionid=\$\{sum\(\d{4,},\d{4,}\)\}',text))
    file_write=bool(re.search(r'"methodname"\s*:\s*"savexstreamconfig"',text)
        and re.search(r'webapps/[^"\n]{1,180}\.(?:jspx?|php)',text))
    callback_domain=bool(re.search(r'(?:https?|ftp|ldaps?)://[^/\s&<"}]*\.(?:jorm0\.surf|oast\.(?:fun|site|online)|ceye\.io|interact\.sh)(?:/|<|["}\s]|$)',text))
    callback_fetch=bool(callback_domain and re.search(r'(?:url|uri|src|source|mla_stream_file|meta|dsname)\s*=|include:\s*\n\s*remote:|<url>\s*https?://',text))
    callback_fetch=callback_fetch or bool(callback_domain and re.search(r'/partymgr/control/getjsonuilabel(?:array)?(?:\s|$)',target)
        and re.search(r'requiredlabel=\s*\{\s*"https?://',body))
    business_sql=bool(re.search(r'"(?:content|query|sql)"\s*:\s*"\s*(?:select|insert)|[?&](?:sql|query)=\s*(?:select|insert)',text))
    inj=bool(re.search(r"\bunion\s+(?:all\s+)?select|['\"]\s*(?:or|and)\b|\b(?:sleep|updatexml|extractvalue)\s*\(|\binto\s+outfile",text))
    if business_sql and not inj and not code_injection:return None,'business_sql_without_injection'
    if (context=='direct_fragment' and re.match(r'\s*(?:delete\s+from|update\s+\w+\s+set|insert\s+into|select\s+|with\s+\w+\s+as)',target)
            and not re.search(r'xp_cmdshell|into\s+outfile|load_file\s*\(|openrowset|\bsleep\s*\(|\bwaitfor\s+delay|(?:/etc/|win\.ini)',text)):
        return None,'standalone_business_sql_statement'
    primitive=strong or java_graph or php_object_graph or xml_script_execution or code_injection or template_injection or php_cgi_injection or file_write or callback_fetch or sql_error_probe or shell_arithmetic_probe or report_expression_probe or bool(SENSITIVE.search(text))
    if context=='direct_fragment' and re.match(r'retr\s+',target) and not primitive:
        return None,'ftp_relative_file_read_without_sensitive_target'
    if (not strong and re.search(r'/(?:images?\.php|include/thumb\.php)\?',target)
            and re.search(r'\.(?:png|jpe?g|gif|webp)(?:[&\s]|$)',target)):
        return None,'ordinary_relative_image_path'
    plain_path=target.partition('?')[0]
    if (not primitive and data['method'] in ['get','head'] and plain_path.count('../')==1
            and '\\' not in plain_path and ';' not in plain_path
            and re.search(r'\.(?:html?|css|js|png|jpe?g|gif|webp)$',plain_path)):
        return None,'ordinary_static_path_normalization'
    reason=result.get('reason','')
    if re.search(r'频繁|多次|批量|爆破|暴力',reason) and not primitive:return None,'unsupported_frequency_claim'
    if (confidence=='high' and context=='direct_fragment' and body.strip()==target.strip()
            and len(target)<90 and SENSITIVE.search(target) and not (strong or java_graph or code_injection or template_injection)):
        return 'suspicious','sensitive_file_fragment_without_action'
    if label=='malicious' and primitive:
        return 'malicious',('anchored_high_with_exploit' if confidence=='high' else 'anchored_medium_with_exploit')
    if confidence=='high' and (java_graph or template_injection or php_cgi_injection or file_write or callback_fetch):return 'malicious','explicit_structural_exploit_with_model_support'
    if confidence=='high' and PUBLIC_PROBE.search(target+'\n'+body):
        return 'suspicious','anchored_sensitive_probe_without_execution'
    return None,'no_corroborating_exploit_or_probe'
