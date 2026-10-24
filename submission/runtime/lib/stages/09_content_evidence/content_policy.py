"""Deeper review: withdraw ambiguous configuration-only changes; add scoped file probes."""
import base64
import re
from previous_policy import Finding,assess as previous_assess
def fingerprint(value,text,encoding):
    data=text.encode(encoding)
    for offset in range(3):
        part=data[offset:];part=part[:len(part)//3*3]
        if len(part)>=12 and base64.b64encode(part).decode().lower() in value.lower():return True
    return False
def assess(message,recover,decode_part):
    data,context=recover(message)
    if not data or context not in ['recovered_http','recovered_http_fragment']:return None
    target=decode_part(data['target']);body=decode_part(data['body']);method=data['method']
    if context=='recovered_http' and method=='get' and target.startswith('/jsoa/dl.jsp?@jiusi10@') and target.endswith('@jiusi13@'):
        value=target.split('@jiusi10@',1)[1].rsplit('@jiusi13@',1)[0]
        expected=base64.b64encode(b'&FileName=../../../dl.jsp&path=/aaa').decode().lower()
        if value==expected:
            return Finding('suspicious','jsoa_encoded_source_read_probe','特定下载接口的完整编码值匹配目录穿越读取脚本源码的折叠指纹；不声称无损解码',target,
                'https://update.nsfocusglobal.com/update/listNewipsDetail/v/rule5.6.10')
    if context=='recovered_http' and method=='post' and target=='/servlet/webchat/attachment/1':
        match=re.search(r'(?:^|&)attachpk=([^&\s]+)',body)
        if (match and match[1].startswith('/v8') and fingerprint(match[1],'/../../','utf-16-be')
            and fingerprint(match[1],'/WEB-INF/web.xml','utf-16-be')):
            return Finding('suspicious','utf16_encoded_attachment_config_probe','附件参数同时含UTF-16BE BOM、目录穿越及WEB-INF配置文件编码指纹，支持越界文件探测；不声称还原实际字节',target+'|UTF16BE-BOM|/../../|/WEB-INF/web.xml')
    previous=previous_assess(message,recover,decode_part)
    if previous and previous.category=='solr_remote_streaming_enable_probe':
        return None
    return previous
