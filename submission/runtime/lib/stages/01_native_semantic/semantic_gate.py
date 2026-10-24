"""Guard semantic proposals using request evidence, not model confidence alone."""
import re
from urllib.parse import parse_qsl
from request_context import extract

VERSION = 'semantic_evidence_gate_v2'
STRONG = re.compile(
    r'(?:<\?php|<%|<!entity|\bunion\s+(?:all\s+)?select\b|\bwaitfor\s+delay|'
    r'\b(?:updatexml|extractvalue|sleep|system|eval|exec|file_get_contents)\s*\(|'
    r'class\.forname|defineclass|classloader|jdbcrowsetimpl|\b(?:runtime|processbuilder)\b|'
    r'\$\{jndi:|\#\{t\(|\b(?:information_schema|fn_sqlvarbasetostr|hashbytes)\b|'
    r'(?:[;|`]\s*(?:echo|cat|wget|curl)\b)|onerror\s*=|<script\b)', re.I)


def eligible_proposal(message, result):
    if result.get('label') not in ('malicious', 'suspicious'):
        return False, 'no_threat_proposal'
    if not result.get('evidence_anchor_verified'):
        return False, 'unverified_evidence_quote'
    regions, context = extract(message)
    if regions is None or context == 'outer_request_body_excluded':
        return False, 'excluded_context'
    target = regions['target']
    body = regions['body'].strip().strip('|').strip()
    text = '\n'.join([target, *regions['headers'], *regions['values'], body])
    strong = bool(STRONG.search(text))
    # Authentication fields and complete business queries need exploit evidence.
    # This also rejects an erroneous SQL allegation when the input is just a password.
    query = target.split('?',1)[1] if '?' in target else (target if re.match(r'^\w+=',target) else '')
    pairs = parse_qsl(query.strip('|')+'&'+body.strip('|'),keep_blank_values=True)
    names = {name.strip() for name,value in pairs}
    credential_fields = {'id','user','username','userid','account','login','password','pwd','pass','passwd','remember','rememberme'}
    exploit = re.search(r"(?:['\"]\s*(?:or|and)\b|\bselect\b|[;|`<>]|\$\{|\.\./)", '\n'.join(value for name,value in pairs))
    if not strong and names and names <= credential_fields and names & {'password','pwd','pass','passwd'} and not exploit:
        return False, 'authentication_fields_without_exploit'
    business_query = re.search(r'(?:^|[?&])(?:where|args)=[^&]*\bselect\b',target+'\n'+body,re.M)
    bypass = re.search(r'\b(?:union|sleep|benchmark)\b|--|/\*|\b(?:or|and)\s+\d+\s*=',target+'\n'+body)
    if not strong and business_query and not bypass:
        return False, 'business_query_without_exploit'
    if not strong and re.search(r'@rsyncd|--sender|--backup-dir|giop|lookbehind:|greedy:', text):
        return False, 'protocol_or_code_fragment'
    if not strong and re.search(r'(?:clickhouse|format\s+(?:rowbinary|tabseparated|csv)|select\s+1\s+format)', text):
        return False, 'ordinary_database_client'
    reason = result.get('reason', '')
    if not strong and re.search(r'凭证|明文|密码|账号|口令', reason):
        return False, 'credential_presence_not_attack_proof'
    if not strong and re.search(r'(?:base64url|data:image/)', target) and re.search(r'(?:image|thumb|format=png|format=jpg)', target):
        return False, 'opaque_image_data'
    if not strong and re.search(r'^(?:[\w.]+)=\s*(?:https?|ftp)://', target) and not body:
        return False, 'external_url_only_fragment'
    no_header_payload = not any(re.search(r'[${}<>]|\b(?:eval|exec|system)\s*\(', value) for value in regions['headers'])
    sensitive_path = re.search(r'\.env\b|\.git/|\.svn/|\.bash_history|\.htpasswd|web\.config|wp-config|/etc/|win\.ini|'
                               r'/(?:actuator|jolokia|debug/pprof)|\.{2}/|\.(?:sql|bak|ya?ml|properties)(?:$|\?)', target)
    if (not strong and '?' not in target and '=' not in target and not body and no_header_payload
            and not sensitive_path):
        return False, 'ordinary_endpoint_without_exploit_evidence'
    if result.get('confidence') == 'high':
        return True, 'high_confidence_anchored_semantics'
    if result.get('confidence') == 'medium' and result.get('label') == 'malicious' and strong:
        return True, 'medium_confidence_with_structural_corroboration'
    return False, 'insufficient_confidence_or_corroboration'
