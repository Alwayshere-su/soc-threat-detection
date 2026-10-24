"""Additional static request view; preserve case/+ and explicitly record framing.

The older parser is used only as a conservative outer-context gate. Values below
are re-read from original text. No dynamic deserialization or payload execution.
"""
import html,re
from urllib.parse import unquote
from request_recovery import recover as context_gate

FRAME=re.compile(r'^\s*\d+(?:,\d+){3,},')
HTTP=re.compile(r'\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+([^\r\n]{1,25000}?)\s+HTTP/\d(?:\.\d)?',re.I)


def preserve(message):
    text=str(message).replace('\r\n','\n').replace('\r','\n')
    for _ in range(2):
        text=re.sub(r'\\+u([a-fA-F0-9]{4})',lambda m:chr(int(m[1],16)),text)
        text=re.sub(r'\\+r\\+n|\\+n|\\+r','\n',text)
        text=re.sub(r'&(?:#[xX][0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);',lambda m:html.unescape(m[0]),text)
        text=re.sub(r'\\+(["\'])',r'\1',text)
    return text


def decode(value):
    for _ in range(3):
        new=unquote(value)
        if new==value:break
        value=new
    return value


def parameters(value):
    # Preserve literal '+' in encoded byte strings instead of globally treating it as space.
    result={}
    for part in value.split('&'):
        name,sep,item=part.partition('=')
        if sep:
            key=unquote(name).casefold()
            if key in result:return None # No interpretation of conflicting duplicate parameters.
            result[key]=unquote(item)
    return result


def parse(message):
    _,context=context_gate(message)
    if context not in ['recovered_http','recovered_http_fragment']:return None
    text=FRAME.sub('',preserve(message),count=1).strip()
    text=re.split(r'\n\s*response_(?:code|message)\s*:',text,flags=re.I,maxsplit=1)[0]
    text=re.split(r'\|{4,}',text,maxsplit=1)[0]
    hit=HTTP.search(text)
    if hit and hit.start()<700:
        method,target=hit[1].upper(),hit[2];suffix=text[hit.end():]
    else:
        first,_,suffix=text.partition('\n')
        fragment=re.fullmatch(r'(/[^\n]+?)\s+HTTP/\d(?:\.\d)?',first,flags=re.I)
        if not fragment:return None
        method,target='',fragment[1]
    headers={};body=[];in_body=False
    for line in suffix.splitlines():
        if not in_body:
            if not line.strip():
                if headers:in_body=True
                continue
            if not headers and re.fullmatch(r'\d\.\d',line.strip()):continue
            h=re.match(r'^([a-zA-Z][a-zA-Z0-9_-]{0,60})\s*:\s*(.*)$',line)
            if h:
                key=h[1].casefold()
                if key in headers:return None
                headers[key]=h[2];continue
            in_body=True
        body.append(line)
    return {'method':method,'target':target,'headers':headers,'body':'\n'.join(body).strip(),'context':context}
