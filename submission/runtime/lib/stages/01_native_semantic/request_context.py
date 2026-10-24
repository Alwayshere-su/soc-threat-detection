"""Extract request regions for local reference checks; no embedded instructions run."""
from pathlib import Path
import importlib.util
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
previous = Path(__file__).resolve().parent / 'previous_payload_policy.py'
if not previous.exists():
    previous = ROOT / 'exp/submissions/20261016_B_payload_v1/payload_policy.py'
spec = importlib.util.spec_from_file_location('previous_payload_request_rules', previous)
v1 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = v1
spec.loader.exec_module(v1)


def make_regions(text, target):
    lines = text.split('\n')
    last_header = 0
    headers = []
    for index, line in enumerate(lines[1:], 1):
        match = re.match(r'^([a-z][a-z0-9_-]{0,60})\s*:\s*(.*)$', line)
        if match:
            last_header = index
            headers.append((match.group(1), match.group(2)))
        elif last_header and not line.strip():
            break
    body = '\n'.join(lines[last_header+1:]).lstrip() if last_header else ''
    values, names = [], []
    for data in [target.partition('?')[2], body]:
        for field in data.split('&'):
            name, separator, value = field.partition('=')
            if separator:
                names.append(name)
                values.append(value)
    if body:
        values.append(body)
    return {'target': target, 'body': body, 'values': values, 'names': names,
            'headers': [value for _, value in headers], 'header_items': headers,
            'cookies': '\n'.join(value for name, value in headers if name == 'cookie'),
            'user_agent': '\n'.join(value for name, value in headers if name == 'user-agent'),
            'files': re.findall(r'filename\s*=\s*[\'\"]([^\'\"]+)', body)}


def extract(message):
    text = v1.FRAME.sub('', v1.normalize(message), count=1).strip()
    framed = bool(v1.FRAME.match(v1.normalize(message)))
    text = v1.RESPONSE.split(text, maxsplit=1)[0]
    request = v1.HTTP.search(text)
    outer = request is not None and request.start() <= 256
    if outer and (v1.PROMPT.search(text[:request.start()]) or v1.NESTED_LOG.search(text[:request.start()])):
        outer = False
    operational_log = re.search(r'"(?:networkcloud_type|operation_log|operationcontent|interceptcommand)"\s*:', text)
    if not outer and (v1.PROMPT.search(text) or v1.NESTED_LOG.search(text[:700]) or operational_log):
        return None, 'embedded_or_forwarded'
    if outer:
        text = text[request.start():]
        target = request.group(2)
        regions = make_regions(text, target)
        if (re.search(r'^/(?:api/array2singlemsg|gateway/api/|v1/chat/completions|v1/embeddings)', target)
                or v1.PROMPT.search(regions['body']) or v1.NESTED_LOG.search(regions['body'][:1500])
                or operational_log):
            regions['body'] = ''
            regions['files'] = []
            regions['values'] = [part.partition('=')[2] for part in target.partition('?')[2].split('&') if '=' in part]
            return regions, 'outer_request_body_excluded'
        return regions, 'http_request'
    direct = re.match(r'^(?:[\w.\[\]-]{1,80}\s*=|/|\$\{|union\s+(?:all\s+)?select\b|updatexml\s*\(|extractvalue\s*\()', text)
    header_fragment = re.search(r'\n(?:host|user-agent|content-type):', text)
    if not direct and not (framed and header_fragment):
        return None, 'unstructured_or_code'
    target = text.split('\n', 1)[0].split(' http/', 1)[0]
    regions = make_regions(text, target)
    if '?' not in target:
        for field in target.split('&'):
            name, separator, value = field.partition('=')
            if separator:
                regions['names'].append(name)
                regions['values'].append(value)
    if not regions['values']:
        regions['values'].append(target)
    return regions, 'request_fragment'
