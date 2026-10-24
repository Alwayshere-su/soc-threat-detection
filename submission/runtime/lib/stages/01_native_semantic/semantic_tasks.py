"""Build semantic inputs while retaining request target/body and attack-bearing headers."""
import hashlib
import json
import re
from request_context import extract

VERSION = 'semantic_request_view_v1'


def view(message):
    regions, context = extract(message)
    if regions is None or context == 'outer_request_body_excluded':
        return None
    headers = {}
    for name, value in regions['header_items']:
        if name in ('host', 'content-length', 'accept', 'accept-encoding', 'accept-language',
                    'connection', 'cache-control', 'pragma', 'date'):
            if name == 'host' and re.search(r'[${}<>\'\"]', value):
                headers[name] = value
            continue
        if name in ('x-real-ip', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port',
                    'x-forwarded-proto', 'x-scheme') and re.fullmatch(r'[\w. :,\-]+', value):
            continue
        if name in ('authorization', 'authorization-gateway', 'x-key', 'accesstoken', 'sign',
                    'subscribeid', 'traceid', 'kaas-trace-id', 'requestid') and re.fullmatch(r'[\w+/. :=\-]+', value):
            continue
        if name == 'user-agent':
            value = 'mozilla-browser' if 'mozilla/' in value else re.sub(r'/[\d.]+', '', value)
        if name == 'cookie':
            value = re.sub(r'(?i)\b(phpsessid|jsessionid|sessionid|csrf|csrftoken|serverid)=([\w.\-]{10,})', r'\1=<session>', value)
        if name == 'content-type':
            value = re.sub(r'(?i)boundary=[^;\s]+', 'boundary=<boundary>', value)
        headers[name] = value
    body = re.sub(r'(?m)^--[-A-Za-z0-9_.]{10,}(?:--)?\s*$', '--BOUNDARY', regions['body'])
    text = json.dumps({'request_target': regions['target'], 'headers': headers, 'body': body},
                      ensure_ascii=False, sort_keys=True)
    return text


def key(message):
    text = view(message)
    return hashlib.sha256(text.encode()).hexdigest() if text is not None else None
