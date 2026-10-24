"""Local, deterministic payload triage. Strings are parsed, never executed.

Labels are a semantic policy, not official B truth: exploitation -> malicious;
reconnaissance -> suspicious. Embedded quotations and response bodies are excluded.
"""
from dataclasses import dataclass
import html
import re
from urllib.parse import unquote_plus

VERSION = 'payload_request_v1'
FLAGS = re.I | re.S
HTTP = re.compile(r'\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+([^\n]{1,5000}?)\s+HTTP/\d(?:\.\d)?', re.I)
FRAME = re.compile(r'^\s*\d+(?:,\d+){3,},')
RESPONSE = re.compile(r'\n\s*response_(?:code|message)\s*:', re.I)
PROMPT = re.compile(r'\b(?:classify\s+(?:the\s+)?request|you are\s+(?:a|an)|system prompt|normal image file|plaintext password)\b|"messages"\s*:\s*\[|\\u4f60\\u662f', re.I)
NESTED_LOG = re.compile(r'"(?:payloads|relationships|ponshine_datatype)"\s*:|safety-middleground_log|rs_operation_load_log', re.I)


@dataclass(frozen=True)
class Decision:
    label: str | None
    reason: str
    context: str
    evidence: str = ''


def normalize(message):
    text = str(message or '').replace('\r\n', '\n').replace('\r', '\n')
    text = re.sub(r'\\+r\\+n|\\+n|\\+r', '\n', text)
    for _ in range(2):
        text = html.unescape(unquote_plus(text))
    # MySQL executable comments and separator comments are common obfuscations.
    text = re.sub(r'/\*!\d{0,6}\s*(.*?)\*/', r' \1 ', text, flags=re.S)
    text = re.sub(r'/\*[^*]*\*/', ' ', text)
    return text.lower()


def _hit(pattern, text):
    match = re.search(pattern, text, FLAGS)
    if not match:
        return None
    return text[max(0, match.start()-50):min(len(text), match.end()+90)].replace('\n', ' ')


def classify(message):
    original = str(message or '')
    text = normalize(original)
    if not text.strip():
        return Decision(None, 'empty', 'empty')
    unframed = FRAME.sub('', text, count=1).strip()
    framed = bool(FRAME.match(text))
    # Only treat an HTTP request near the start as the outer event. An HTTP
    # sample deep inside JSON, JavaScript, a prompt or a log is not the request.
    request = HTTP.search(unframed)
    outer = request is not None and request.start() <= 256
    if outer and (PROMPT.search(unframed[:request.start()]) or NESTED_LOG.search(unframed[:request.start()])):
        outer = False
    target = request.group(2) if outer else ''
    context = 'http_request' if outer else 'framed_fragment' if framed else 'fragment'
    if not outer and (PROMPT.search(unframed) or NESTED_LOG.search(unframed[:700])):
        return Decision(None, 'embedded_prompt_or_log', 'quoted_or_forwarded')
    if outer:
        text = unframed[request.start():]
        text = RESPONSE.split(text, maxsplit=1)[0]
        # A blank line immediately after the request line occurs in this data;
        # identify body after the last actual header, rather than blindly using
        # the first double newline.
        header_lines = text.split('\n')
        last_header = 0
        for i, line in enumerate(header_lines[1:], 1):
            if re.match(r'^[a-z][a-z0-9_-]{0,60}\s*:', line):
                last_header = i
            elif last_header and not line.strip():
                break
        headers = '\n'.join(header_lines[:last_header+1])
        body = '\n'.join(header_lines[last_header+1:]).lstrip()
        is_transport = (re.search(r'^/(?:api/array2singlemsg|gateway/api/|v1/chat/completions|v1/embeddings)', target)
                        or PROMPT.search(body) or NESTED_LOG.search(body[:1500]))
        if is_transport:
            text = headers
            context = 'outer_request_nested_content_excluded'
    else:
        text = RESPONSE.split(unframed, maxsplit=1)[0]
        # Unframed source-code, prose and admin syslog are not raw attack inputs.
        direct_fragment = bool(re.match(r'^(?:[\w.\[\]-]{1,80}\s*=|/|\$\{|<\s*(?:img|svg|script)\b|union\s+(?:all\s+)?select\b|updatexml\s*\(|extractvalue\s*\()', text))
        if not framed and not direct_fragment:
            return Decision(None, 'not_a_request_or_attack_fragment', context)
        if framed and PROMPT.search(text):
            return Decision(None, 'embedded_prompt', 'quoted_or_forwarded')
        if not target:
            target = text.split('\n', 1)[0].split(' http/', 1)[0]

    executable_upload = re.search(r'filename\s*=\s*[\'\"][^\'\"]*\.(?:php\d?|phtml|jspx?|aspx?)(?:[\'\";\s])', text)
    server_code = re.search(r'<\?php|<%@\s*page|<script\s+runat\s*=\s*[\'\"]server', text)
    upload_context = re.search(r'content-type\s*:\s*image/|gif89a|unlink\s*\(\s*__file__|file\.delete|upload', text)
    if executable_upload and server_code and upload_context:
        evidence = text[max(0, executable_upload.start()-20):executable_upload.end()+100]
        return Decision('malicious', 'executable_file_upload', context, evidence.replace('\n', ' '))

    malicious = [
        ('sql_union', r'\bunion\s+(?:all\s+)?select\b.{0,200}(?:\bnull\b|\bmd5\s*\(|\d\s*,|\bfrom\b)'),
        ('sql_error_or_time', r'\b(?:updatexml|extractvalue|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\s+[\'\"]|\bselect\s*\(?\s*sleep\s*\(|\b(?:and|or)\s+sleep\s*\('),
        ('sql_boolean', r'[\'\"]\s*(?:\)|\s)*\s*(?:or|and)\s+(\d{1,8})\s*=\s*\1(?:\D|$)'),
        ('sql_identifier_expression', r'\b(?:table|tablename|strtbname|orderby|column)\s*=\s*\(\s*select\s+\d+(?:\s*,\s*\d+){3,}'),
        ('xss_event_handler', r'<\s*(?:img|svg|body|iframe|input|details|video|marquee|a)\b[^>]{0,500}\bon[a-z]+\s*=.{0,100}(?:alert\s*\(|prompt\s*\(|confirm\s*\(|document\.|javascript:|&#)'),
        ('xss_script', r'<\s*script\b[^>]*>\s*(?:alert\s*\(|prompt\s*\(|confirm\s*\(|document\.|fetch\s*\(|window\.)'),
        ('xss_javascript_uri', r'javascript\s*:\s*(?:alert|prompt|confirm)\s*\('),
        ('xss_attribute_breakout', r'[\'\"]\s+on[a-z]+\s*=\s*[\'\"]?\s*(?:alert|prompt|confirm)\s*\('),
        ('jndi_lookup', r'\$\{\s*jndi\s*:\s*(?:ldap|rmi|dns|iiop|ldaps)\s*:'),
        ('java_runtime_exec', r'(?:java\.lang\.)?runtime\s*\.\s*getruntime\s*\(\s*\)\s*\.\s*exec\s*\(|java\.lang\.processbuilder\b'),
        ('java_reflective_loader', r'classloader.{0,600}(?:defineclass|setaccessible)|defineclass.{0,600}setaccessible'),
        ('template_execution', r'\{\{.{0,500}(?:__globals__|__mro__|__subclasses__|popen\s*\().{0,300}\}\}'),
        ('php_code_execution', r'<\?php.{0,500}(?:eval\s*\(|assert\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|echo\s+md5\s*\()'),
        ('php_eval_chain', r'\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\('),
        ('php_expression_injection', r'(?:^|[?&])\w{1,40}\s*=\s*(?:echo|print)\s+(?:md5|sha1)\s*\(.{1,100}\)\s*;\s*(?:exit|die)\s*\('),
        ('php_system_command', r'\b(?:system|shell_exec|passthru)\s*\(\s*[\'\"]\s*(?:whoami\b|id\b|cat\s+/etc/passwd)'),
        ('shell_command_parameter', r'(?:^|[?&;\n])\s*(?:cmd|command|exec|code)\s*=.{0,80}(?:\b(?:cat|head|tail)\s+/etc/(?:passwd|shadow)|\b(?:wget|curl)\s+https?://|\b(?:whoami|id)\s*(?:[;&|]|$))'),
        ('shell_injection', r'(?:[;|`]|\$\()\s*(?:cat\s+/etc/(?:passwd|shadow)|whoami\b|(?:wget|curl)\s+https?://)'),
        ('download_and_execute', r'\b(?:wget|curl)\s+https?://.{0,200}[;&|].{0,120}\bchmod\s+[0-7]{3,4}'),
        ('download_pipe_shell', r'\b(?:wget|curl)(?:\s+[-\w]+){0,6}\s+https?://.{0,200}\|\s*(?:ba)?sh\b'),
        ('traversal_to_shell', r'(?:\.\.[/\\]){2,}bin[/\\](?:ba)?sh\b'),
        ('file_inclusion', r'(?:javax\.servlet\.include\.servlet_path|php://filter|file:///(?:etc|c:)|\bexpect://)'),
        ('sensitive_traversal', r'(?:\.\.[/\\]){2,}.{0,250}(?:etc[/\\](?:passwd|shadow)|windows[/\\]win\.ini|boot\.ini|web-inf[/\\]web\.xml)'),
        ('java_deserialization_gadget', r'(?:invokertransformer|templatesimpl|ysoserial|org\.apache\.commons\.collections).{0,1500}(?:runtime|processbuilder|exec|transformer)'),
        ('uploaded_exploit', r'filename\s*=\s*[\'\"][^\'\"]*(?:rce|exploit)[^\'\"]*\.(?:jar|jsp|php|aspx?)\b'),
        ('ssrf_metadata', r'(?:url|uri|dest|target|host)\s*=\s*https?://169\.254\.169\.254/(?:latest/|metadata)'),
    ]
    for reason, pattern in malicious:
        evidence = _hit(pattern, text)
        if evidence:
            return Decision('malicious', reason, context, evidence)

    suspicious = [
        ('sensitive_file_probe', r'(?:^|/)(?:\.bash_history|\.env(?:\.[a-z]+)?|\.git/(?:head|config|index)|\.svn/(?:entries|wc\.db)|web-inf/web\.xml|etc/passwd|windows/win\.ini|phpinfo\.php|webshell\.php|shell\.php)(?:[?&#\s]|$)'),
        ('traversal_probe', r'(?:\.\.[/\\]){3,}'),
        ('management_data_probe', r'(?:^|/)(?:actuator/(?:env|heapdump|configprops)|jolokia/read|server-status)(?:[?&#\s]|$)'),
    ]
    for reason, pattern in suspicious:
        evidence = _hit(pattern, target)
        if evidence:
            return Decision('suspicious', reason, context, evidence)
    evidence = _hit(r'user-agent\s*:.{0,120}\b(?:sqlmap|nikto|nuclei|acunetix|nessus)\b', text)
    if evidence:
        return Decision('suspicious', 'scanner_user_agent', context, evidence)
    return Decision(None, 'no_explicit_attack_evidence', context)


def apply(frame, baseline):
    """Return labels and audit decisions; event IDs never enter classify()."""
    labels = list(baseline)
    decisions = []
    for position, (pipeline, message) in enumerate(zip(frame.pipeline, frame.message_sanitized)):
        if pipeline != 'payload':
            continue
        decision = classify(message)
        if decision.label:
            # A clear exploit may upgrade an existing suspicious prediction;
            # a probe never downgrades a model's malicious decision.
            if labels[position] != 'malicious' or decision.label == 'malicious':
                labels[position] = decision.label
        decisions.append((position, decision))
    return labels, decisions
