"""Content-only follow-up on potential misses. Never execute or fetch log content."""
from dataclasses import dataclass
import base64
import binascii
import re
from urllib.parse import unquote

VERSION='scoped_potential_miss_review_v1'
REFERENCES={
    'thinkadmin':'https://nvd.nist.gov/vuln/detail/CVE-2020-25540',
    'confluence':'https://www.rapid7.com/blog/post/ra-cve-2023-22515-analysis/',
    'bitbucket':'https://bo0om.ru/just-enter-the-space-attacks-en',
    'dlink':'https://isc.sans.edu/diary/DLink%2BNAS%2BDevice%2BBackdoor%2BAbused/30878',
    'totolink':'https://github.com/4hsienyang/CVE-vulns/blob/main/TOTOLINK/EX200/Leak_getEasyWizardCfg/Leak.md',
}

@dataclass(frozen=True)
class Finding:
    label:str|None
    category:str
    reason:str
    evidence:str=''
    grade:str='held'
    reference:str=''

def static_base36(value):
    if len(value)%2 or not re.fullmatch(r'[0-9a-z]{6,1200}',value,re.I):return None
    try:
        values=[int(value[i:i+2],36) for i in range(0,len(value),2)]
        if any(v>255 for v in values):return None
        return bytes(values).decode('gb18030')
    except (ValueError,UnicodeError):return None

def exact_base64(value):
    try:
        value=unquote(value)
        if len(value)>18000 or len(value)%4==1 or not re.fullmatch(r'[a-zA-Z0-9+/]+={0,2}',value):return None
        raw=base64.b64decode(value+'='*((-len(value))%4),validate=True)
        text=raw.decode('utf-8')
        if not text or sum(c.isprintable() or c in '\r\n\t' for c in text)/len(text)<.96:return None
        return text
    except (ValueError,UnicodeError,binascii.Error):return None

def assess(message,recover,decode_part):
    data,context=recover(message)
    def f(label,category,reason,evidence='',grade='held',reference=''):
        return Finding(label,category,reason,evidence,grade,REFERENCES.get(reference,reference))
    if data is None:
        if '"role"' in str(message).lower() or '/api/array2singlemsg' in str(message).lower():
            return f(None,'hold_quoted_model_input','外层为模型/日志整理接口，内层攻击样本不能直接作为外层攻击')
        return f(None,'hold_nested_operations_context','日志上报/运维上下文中的引用攻击，需要明确分类主体，暂不提升')
    target=decode_part(data['target']);body=decode_part(data['body'])
    headers=decode_part('\n'.join(k+': '+v for k,v in data['headers']))
    active=target+'\n'+body+'\n'+headers
    # Do not reinterpret an escaped array of requests as a direct request.
    raw=str(message)
    if re.search(r'\\+"\s*,\s*\\+[rn]|\\+"(?:get|post)\s|"\s*,\s*"(?:get|post)\s',raw,re.I):
        return f(None,'hold_unframed_request_array','转义请求列表残片缺少可靠外层，不能继承其中任意攻击标签')
    if re.search(r'\b(?:fuzz faster u fool|nmap scripting engine|nmap nse|gobuster|nuclei/)',headers):
        return f('suspicious','explicit_scanner_user_agent','请求头明确标明扫描/模糊测试工具，不按普通浏览器访问处理',headers,'strong')
    # Base36 is case-insensitive; decoding byte pairs is lossless even for lowercased logs.
    match=re.search(r'(?:^|[?&])s=admin/api\.update/get/encode/([0-9a-z]+)',target,re.I)
    if match:
        decoded=static_base36(match[1])
        if decoded is not None and ('../' in decoded or '..\\' in decoded) and re.search(r'/etc/(?:passwd|shadow)|(?:^|[/\\])index\.php$|(?:web|config)\.(?:xml|php)',decoded,re.I):
            return f('malicious','decoded_thinkadmin_file_read','按Base36双字符字节规则无损解析后，文件参数指向越界系统文件/应用源码',decoded,'strong','thinkadmin')
    # Extract encoded values from original text, before any case normalization.
    for encoded in re.finditer(r'(?i)\b(path|url|urls|dl|filename|file|cid|sql|querystring|data_s|meeturl)=([a-zA-Z0-9+/%=_-]{8,})',raw):
        name=encoded[1].lower();decoded=exact_base64(encoded[2])
        if decoded is not None and name in ['path','url','dl','filename','file'] and re.search(r'/etc/(?:passwd|shadow)(?:\b|$)|(?:\.\.[/\\]){2,}.*web-inf',decoded,re.I):
            return f('malicious','case_preserved_base64_file_read','保留原文大小写后严格Base64解码，明确得到系统敏感文件读取目标',decoded,'strong')
    # A case-folded fingerprint is NOT claimed to be a decoded original value.
    known=base64.b64encode(b'/etc/passwd').decode().lower()
    if ((re.search(r'(?:[?&]|^|\n)path='+re.escape(known)+r'(?:[&\s]|$)',active) and re.search(r'(?:/|\.)fileservlet|^path=',active))
            or ('page=download_video' in target and re.search(r'[?&]dl='+re.escape(known)+r'(?:[&\s]|$)',target))):
        return f('suspicious','casefolded_encoded_file_probe','读取参数命中系统文件的大小写折叠编码指纹；不能无损解码，按探测而非确认读取处理',known,'specific_probe')
    if '/adminer?' in target and re.search(r'(?:[?&])elastic=[^&\s]*\.(?:jorm0\.surf|ceye\.io|oast\.[a-z]+)',target):
        return f('malicious','database_connection_callback','数据库管理连接参数指定专用回连域名，支持服务端连接/SSRF利用尝试',target,'strong')
    if target.startswith('/server-info.action?') and 'bootstrapstatusprovider.applicationconfig.setupcomplete=false' in target:
        return f('malicious','confluence_setup_state_bypass','公开信息接口被用于修改内部初始化完成状态，与CVE-2023-22515利用步骤一致',target,'strong','confluence')
    if re.match(r'^/admin[\x01-\x20]+/(?:avatars|db(?:/edit)?|license|logging|mail-server|server-settings)(?:[?\s]|$)',target):
        return f('malicious','bitbucket_whitespace_auth_bypass','管理路由添加空白控制字符规避鉴权，与原始研究中的受保护路由模式一致',target,'strong','bitbucket')
    if '/cgi-bin/nas_sharing.cgi?' in target and all(value in target for value in ['user=messagebus','passwd=','cmd=15','system=']):
        return f('malicious','dlink_backdoor_encoded_command','公开后门账户、空口令及命令参数组合符合D-Link NAS利用；不声称恢复了命令原文',target,'strong','dlink')
    if target=='/cgi-bin/cstecgi.cgi' and '"topicurl":"setting/geteasywizardcfg"' in re.sub(r'\s+','',body):
        return f('malicious','totolink_configuration_disclosure','具体配置读取动作对应公开未授权敏感信息读取漏洞，超出仅访问CGI入口',body,'strong','totolink')
    arithmetic=re.search(r'(?m)^(?:cmd|testcmd|if-modified-simple):\s*(?:expr\s+\d{5,}\s*[-+]\s*\d{4,}|set\s+/a\s+\d{5,}\s*[-+]\s*\d{4,}|echo\s+\d+\s*-\s*\d+\s*\|\s*bc)',headers)
    if arithmetic and len(body)>400:
        return f('suspicious','command_marker_with_opaque_payload','完整请求含随机数算术命令头及异常编码请求体，支持执行能力探测；未验证触发链，暂不判确证利用',arithmetic[0],'specific_probe')
    if target.startswith('/service/0/') and re.search(r'/(?:test\.)?oast\.[a-z]+|test\.oast\.me',target):
        return f('suspicious','callback_domain_route_probe','特殊服务路由中指定专用回连域名，支持回连/路由探测，但不能证明已发生服务端抓取',target,'specific_probe')
    if '/cve-2018-2628.jsp?' in target and 'tom=' in target:
        return f('suspicious','named_execution_probe_with_encoded_argument','漏洞命名脚本配合编码命令参数，支持执行入口探测；编码原文未可靠还原',target,'specific_probe')
    if re.search(r'^/(?:api/hassio(?:_ingress)?/app/\.\.?/supervisor/info|api/hassio/app/\.\./supervisor/info|x/\.\.//restapi/licensemgr)',target):
        return f('suspicious','management_route_traversal_probe','非规范路径穿越指向管理信息接口，支持路由/鉴权探测；未包含实际执行动作',target,'specific_probe')
    if '/dyxtzpje?jsp=/app/rest/users;.jsp' in target:
        return f('suspicious','jsp_user_route_probe','脚本后缀/分号伪装访问管理用户路由，支持路由解析探测',target,'specific_probe')
    if '/setup.cgi?todo=debug&x=currentsetting.htm' in target:
        return f('suspicious','device_debug_bypass_probe','调试操作配合特制设置页参数，符合设备调试/鉴权探测',target,'specific_probe')
    if data['method']=='put' and re.fullmatch(r'/fileserver/[a-z]{4,18}\.txt',target) and re.fullmatch(r'[a-z]{3,40}',body):
        return f('suspicious','unauthenticated_marker_put_probe','文件服务入口PUT随机标记文本，符合写入能力探测，未显示后续移动或执行',target,'specific_probe')
    if 'fileupload.php?' in target and 'uploaddir=upload' in target and re.search(r'[?&]name=[a-z0-9]+\.php(?:[&\s]|$)',target):
        return f('suspicious','script_upload_destination_probe','上传目的文件显式指定脚本扩展名，正文缺失时只判文件类型探测',target,'specific_probe')
    if target.endswith('senddocument_import.jsp;'):
        return f('suspicious','semicolon_script_route_probe','脚本路由尾附分号，符合服务器路由解析/权限探测',target,'specific_probe')
    if '/seeyonreport/reportserver?op=plugin&cmd=local_install' in target and 'application/zip' in body and re.search(r'\r?\n\r?\n[0-9a-f]{32}\r?\n',body):
        return f('suspicious','plugin_install_marker_probe','插件安装接口上传声明ZIP却为短标记文本的内容，支持安装能力探测，未显示可执行插件',target,'specific_probe')
    if re.search(r'^/servlet/org\.apache\.catalina\.servlets\.defaultservlet/default\.jsp',target):
        return f('suspicious','explicit_container_servlet_probe','以容器内部Servlet类路径访问测试JSP，偏向组件/映射探测',target,'specific_probe')
    if re.search(r'(?m)^get\s+/~log/client//\x27$',body):
        return f('suspicious','quote_in_log_path_probe','日志路径尾加入引号及重复分隔符，支持路径/输入探测',body,'specific_probe')
    if re.search(r'(?:path|url|dl|sql|cid|querystring|meeturl|attachpk)=',active):
        return f(None,'hold_opaque_value','未能可靠还原的编码/加密输入，不把疑似编码当作已验证利用')
    if context=='direct_fragment' or re.search(r'content-disposition:[^\n]*name=\s*$',body):
        return f(None,'hold_truncated_fragment','仅残缺协议或请求体，缺少完整动作及分类主体')
    if re.search(r'export|admin|config|upload|setup|wizard|user|rmiservlet',target):
        return f(None,'hold_authorization_context','管理/业务操作缺少足够利用结构或授权背景，保留正常预测')
    return f(None,'hold_no_specific_attack_evidence','未发现足以提升为威胁的具体证据，保留原预测')
