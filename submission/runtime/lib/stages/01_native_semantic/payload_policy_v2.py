"""Bounded contextual attack signatures, informed by local CRS reference review.

No runtime CRS approximation, external API, row-ID rule, fitting or test labels.
"""
import re
import base64
import binascii
from request_context import extract, v1

VERSION = 'payload_request_v2'
Decision = v1.Decision
FLAGS = re.I | re.S

MALICIOUS = [
    ('fastjson_network_autotype', r'[\'\"]@type[\'\"]\s*:\s*[\'\"](?:java\.net\.(?:inet\w*address|url)|javax\.naming\.|com\.sun\.rowset\.|jar:|[a-z.]*jdbcrowsetimpl)'),
    ('fastjson_gadget', r'[\'\"]@type[\'\"].{0,600}(?:jdbcrowsetimpl|org\.apache\.ibatis|jndiconverter|badattributevalueexpexception)'),
    ('xstream_ldap_graph', r'(?:java\.util\.priorityqueue|object-stream|sorted-set|java\.beans\.xmldecoder).{0,2500}(?:javax\.naming\.ldap|com\.sun\.xml\.internal\.ws|java\.beans\.eventhandler|jdbcrowset|templatesimpl|unicastref)'),
    ('xml_decoder_execution', r'java\.beans\.xmldecoder.{0,1000}(?:processbuilder|runtime|method\s*=\s*[\'\"]exec|java\.lang\.process)'),
    ('java_ognl_execution', r'@java\.lang\.runtime@getruntime\s*\(|ognl\.ognlcontext@default_member_access|freemarker\.template\.utility\.execute'),
    ('server_side_include', r'<!--\s*#\s*exec\s+(?:cmd|cgi)\s*='),
    ('shell_marker_write', r'(?:^|[=;|`])\s*(?:echo|printf)\s+[^\n]{1,180}>>?\s*[/\w.\-]'),
    ('shell_marker_tee', r'(?:^|[=;|`])\s*echo\s+.{1,150}\|\s*tee\s+[/\w.]'),
    ('windows_type_command', r'(?:^|[?&;\n])\s*(?:cmd|command)\s*=\s*type\s+[a-z]:\\+(?:windows|winnt)\\+win\.ini'),
    ('shellshock_function', r'\(\s*\)\s*\{\s*:;\s*\};.{0,120}(?:/bin/(?:ba)?sh|\b(?:cat|echo|wget|curl)\b)'),
    ('command_execution_parameter', r'(?:^|[?&;\n])\s*(?:cmd|command|cmdtext|exec|run|execcommand)\s*=\s*(?:[\'\"])?(?:expr\s+\d+\s*[-+*/]|(?:whoami|id)\b|echo\s+[a-z0-9_%]{4,}|ping\s+(?:[-\w]+\s+){0,3}(?:\d{1,3}\.){3}\d{1,3})'),
    ('sql_boolean_unquoted', r'\b(?:or|and)\s+\(?\s*(\d{2,8})\s*=\s*\1(?:\D|$)'),
    ('sql_waitfor_compact', r'\bwaitfor\s+delay\s*[\'\"]\d+:\d+:\d+'),
    ('sql_file_write', r'[\'\";].{0,60}(?:create\s+table|insert\s+into|copy\s+\w+|into\s+outfile).{0,250}(?:<\?php|\.php|program|xp_cmdshell)'),
    ('php_short_tag_code', r'<\?=.{0,500}(?:file_put_contents|system|eval|assert|shell_exec|include|require)\s*\('),
    ('php_function_expression', r'(?:^|[?&])\w{1,40}\s*=\s*(?:echo|print)\s+(?:md5|sha1)\s*\(.{1,100}\)\s*;\s*(?:exit|die)\s*\('),
    ('jsp_asp_execution_upload', r'(?:filename|filepath|realfiletype|location).{0,140}\.(?:jspx?|aspx?|shtml).{0,1200}(?:<%\s*(?:out\.|response\.|=|@)|<script\s+runat|<!--\s*#exec)'),
    ('jsp_embedded_script', r'<%\s*(?:out\.print|response\.write|=\s*request\.getparameter|java\.lang\.runtime)'),
    ('absolute_sensitive_file_parameter', r'(?:^|[?&;\n\s])(?:filename|filepath|fullpath|file|path|urlpath|url|realpath|dir)\s*[=:]\s*[\'\"]?(?:[a-z]:[/\\](?:windows|winnt)[/\\]win\.ini|/etc/(?:passwd|shadow|hosts))'),
    ('xxe_file_entity', r'<!entity\s+\w+\s+system\s+[\'\"]file:/+(?:etc|[a-z]:)'),
    ('xxe_remote_parameter_entity', r'<!entity\s+%\s*\w+\s+system\s+[\'\"]https?://'),
    ('jdbc_deserialization_config', r'(?:autodeserialize[\'\"]?\s*[:=]\s*[\'\"]?true|statementinterceptors.{0,120}serverstatusdiffinterceptor)'),
    ('template_arithmetic_probe', r'(?:\$\{|\{\{)\s*\d{1,8}\s*\*\s*\d{1,8}\s*(?:\}|\}\})'),
    ('hostname_shell_injection', r'[\'\"]hostname[\'\"]\s*:\s*[\'\"][^\'\"]{0,130}(?:>>\s*[/\w.]|;\s*(?:echo|wget|curl|sh)\b|\$\()'),
]

SENSITIVE_PATH = re.compile(
    r'(?:^|/)(?:\.ds_store|\.vscode(?:/|$)|\.ssh/|\.aws/|\.npmrc|\.htpasswd|\.git(?:/|ignore\b)|\.svn/|'
    r'(?:wp-)?config\.(?:php\.(?:bak|old|txt)|ya?ml|properties)|application\.(?:ya?ml|properties)|bootstrap\.ya?ml|'
    r'(?:database|backup|dump|db)\.sql|phpunit/src/util/php/eval-stdin\.php|cgi-bin/exportsettings\.sh|'
    r'apisix/admin/migrate/export|debug/pprof|actuator/(?:env|heapdump|gateway/routes)|'
    r'web/cgi-bin/[^/]+/backup\.cgi|jolokia/(?:read|exec)|actuator/jolokia/(?:read|exec))', re.I)


def decoded_views(text):
    """Decode bounded data in memory for inspection; never execute or persist it."""
    result = []
    for match in list(re.finditer(r'(?<![a-f0-9])(?:cafebabe|aced0005)[a-f0-9]{100,20000}', text, re.I))[:3]:
        value = match.group(0)
        try:
            data = bytes.fromhex(value[:len(value)//2*2])
            result.append(data.decode('latin1', errors='replace').replace('\x00', ' ').lower())
        except ValueError:
            pass
    for match in list(re.finditer(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{64,12000}={0,2}', text))[:4]:
        value = match.group(0)
        try:
            data = base64.b64decode(value + '=' * (-len(value) % 4), validate=True)
            if not data:
                continue
            printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data) / len(data)
            if printable > .8 or data.startswith((b'\xca\xfe\xba\xbe', b'\xac\xed\x00\x05')):
                result.append(data.decode('latin1', errors='replace').replace('\x00', ' ').lower())
        except (ValueError, binascii.Error):
            pass
    return result


def classify(message):
    existing = v1.classify(message)
    if existing.label == 'malicious':
        return existing
    regions, context = extract(message)
    if regions is None:
        return existing
    body = regions['body']
    text = '\n'.join([regions['target'], *regions['headers'], *regions['values'], body])
    # Benign SQL clients legitimately submit queries; this suppresses only SQL
    # signatures on direct SQL bodies, not malicious expressions in URL fields.
    sql_client = bool(re.search(r'clickhouse|x-clickhouse', '\n'.join(regions['headers'])))
    for reason, pattern in MALICIOUS:
        if sql_client and reason.startswith('sql_'):
            continue
        match = re.search(pattern, text, FLAGS)
        if match:
            evidence = text[max(0, match.start()-30):match.end()+70]
            return Decision('malicious', 'v2_' + reason, context, evidence)
    decode_source = text if context == 'outer_request_body_excluded' else str(message or '')
    for decoded in decoded_views(decode_source):
        if re.search(r'(?:getruntime|defineclass|templatesimpl|processbuilder|invokertransformer|unsafe)', decoded) and re.search(r'java[/\.](?:lang|io)|javax[/\.]', decoded):
            return Decision('malicious', 'v2_encoded_java_execution', context, 'decoded Java execution/class-loading indicators')
        if re.search(r'\binto\s+outfile\b|<\?php.{0,300}(?:eval|system|file_put_contents)', decoded, FLAGS):
            return Decision('malicious', 'v2_encoded_sql_or_php', context, 'decoded file-write or PHP execution indicators')
    if existing.label:
        return existing
    match = SENSITIVE_PATH.search(regions['target'])
    if match:
        return Decision('suspicious', 'v2_sensitive_endpoint_probe', context, match.group(0))
    image_thumbnail = bool(re.search(r'/(?:images\.php|include/thumb\.php)\?', regions['target'])
                           and re.search(r'\.(?:jpg|jpeg|png|gif|webp)(?:&|$)', regions['target']))
    if not image_thumbnail:
        match = re.search(r'(?:\.\.[/\\]){2,}', regions['target'])
        if match:
            return Decision('suspicious', 'v2_short_traversal_probe', context, match.group(0))
    match = re.search(r'(?:^|[?&])\w*id=\d+[\'\"](?:&|$)', regions['target'])
    if match:
        return Decision('suspicious', 'v2_numeric_identifier_quote_probe', context, match.group(0))
    match = re.search(r'(?:^|[?&])(?:url|uri|src|dest|target|host|server)\s*=\s*https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)(?::\d+)?(?:/|&|$)', regions['target'])
    if match:
        return Decision('suspicious', 'v2_loopback_ssrf_probe', context, match.group(0))
    for name, value in regions['header_items']:
        if (name in ('x-scanner', 'x-scan-device-flag') and value.strip()) or (
                name == 'user-agent' and re.search(r'\b(?:topvas|topsec|nessus|nuclei|sqlmap|nikto|acunetix|libredtail-http)\b', value)):
            return Decision('suspicious', 'v2_explicit_scanner', context, name + ':' + value)
    # A login using a known default username/password pair is a weak-credential
    # probe hypothesis, not proof of intrusion. Keep its class suspicious.
    if re.search(r'(?:login|auth|signin)', regions['target']):
        username = re.search(r'(?:^|[&?\n{,])\s*[\'\"]?(?:username|uname|user|account)[\'\"]?\s*[:=]\s*[\'\"]?(admin|root|nacos)\b', text)
        password = re.search(r'(?:^|[&?\n{,])\s*[\'\"]?(?:password|passwd|pwd)[\'\"]?\s*[:=]\s*[\'\"]?(admin|admin123|123456|root|nacos)(?:[\'\"&\s},]|$)', text)
        if username and password:
            return Decision('suspicious', 'v2_default_credential_probe', context, 'default administrative credential pair')
    return existing


def apply(frame, baseline):
    labels = list(baseline)
    decisions = []
    for position, (pipeline, message) in enumerate(zip(frame.pipeline, frame.message_sanitized)):
        if pipeline != 'payload':
            continue
        decision = classify(message)
        if decision.label and (labels[position] != 'malicious' or decision.label == 'malicious'):
            labels[position] = decision.label
        decisions.append((position, decision))
    return labels, decisions
