"""Specific request evidence only; no ID/model-label input and no payload execution."""
from dataclasses import dataclass
import base64
import re

@dataclass(frozen=True)
class Finding:
    label:str
    category:str
    reason:str
    evidence:str
    reference:str=''

REFS={
 'openam':'https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464',
 'fortinet':'https://github.com/horizon3ai/CVE-2022-40684',
 'kemp':'https://rhinosecuritylabs.com/research/cve-2024-1212unauthenticated-command-injection-in-progress-kemp-loadmaster/',
 'solr':'https://issues.apache.org/jira/browse/SOLR-14853',
 'mlflow':'https://kosokoking.com/index.php/security/vulnerable-framework-code-in-ml-applications/',
 'bitbucket':'https://bo0om.ru/just-enter-the-space-attacks-en',
 'ha':'https://github.com/elttam/publications/blob/master/writeups/home-assistant/supervisor-authentication-bypass-advisory.md',
}
def b64fold(text):return base64.b64encode(text.encode()).decode().lower()
def typed_fingerprint(value,name):
    # Compare whole aligned byte triplets of a known type name. Not a decoder.
    data=name.encode()
    for offset in range(3):
        part=data[offset:];part=part[:len(part)//3*3]
        if len(part)>=18 and base64.b64encode(part).decode().lower() in value.lower():return True
    return False
def assess(message,recover,decode_part):
    data,context=recover(message)
    if not data or context not in ['recovered_http','recovered_http_fragment']:return None
    method=data['method'];target=decode_part(data['target']);body=decode_part(data['body'])
    headers={k:decode_part(v) for k,v in data['headers']}
    def found(label,category,reason,evidence,reference=''):
        return Finding(label,category,reason,evidence,REFS.get(reference,reference))
    if (method=='put' and re.fullmatch(r'/api/v2/cmdb/system/admin/[^/?]+',target)
        and headers.get('user-agent')=='report runner'
        and all(x in headers.get('forwarded','') for x in ['for=[127.0.0.1]:8000','by=[127.0.0.1]:9000'])):
        return found('malicious','fortinet_loopback_auth_bypass','管理员修改路由同时带特制来源伪造头和Report Runner标记，符合公开鉴权绕过利用尝试；不声称修改成功',target+'|loopback-forwarded|report-runner','fortinet')
    if (method=='get' and target=='/access/set?param=enableapi&value=1'
        and re.fullmatch(r'basic\s+jz[a-z0-9+/=_-]{12,}',headers.get('authorization',''))):
        return found('suspicious','kemp_encoded_auth_probe','精确API设置路径配合异常Basic编码前缀，匹配公开命令注入探测结构；大小写丢失，不能声称已解码命令',target+'|basic-quote-prefix','kemp')
    comparator='org.apache.click.control.Column$ColumnComparator'
    template='com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl'
    if (method=='post' and re.search(r'/ccversion/version$',target) and body.startswith('jato.pagesession=')
        and typed_fingerprint(body,comparator) and typed_fingerprint(body,template)
        and re.fullmatch(r'(?:expr|set\s+/a)\s+\d{5,}\s*-\s*\d{4,}',headers.get('cmd',''))):
        return found('malicious','openam_typed_deserialization_attempt','已知反序列化入口同时含两个利用链类型的编码指纹和命令探测头，证据超出单纯不透明数据；未执行或恢复整个对象',target+'|ClickComparator+TemplatesImpl|'+headers['cmd'],'openam')
    if (method=='post' and target.startswith('/ajax/login.ashx?')
        and re.search(r'(?:^|&)username=admin\x27;\s*select\s+version\s*\(\s*\)',body)):
        return found('malicious','stacked_sql_login_escape','登录用户名含闭合引号、语句分隔符和额外SELECT表达式，是输入逃逸尝试',body.split('&password=',1)[0])
    if (method=='post' and target=='/ajax-api/2.0/mlflow/experiments/create'
        and re.search(r'"artifact_location"\s*:\s*"http:///\?/((?:\.\./){3,})etc/',body)):
        return found('malicious','mlflow_artifact_path_traversal','实验工件位置使用畸形HTTP查询路径并连续越界指向系统目录，符合文件读取利用链的构造步骤',target+'|artifact_location=http:///?/../.../etc/','mlflow')
    if method=='get' and target=='/api/hassio/app/../supervisor/info':
        return found('malicious','homeassistant_known_auth_traversal','公开鉴权绕过中的精确跨层API路径访问Supervisor信息，超出仅访问管理页',target,'ha')
    if method=='get' and target.startswith('/wp-admin/admin-post.php?page=download_video&dl='):
        value=target.split('&dl=',1)[1].split('&',1)[0]
        if value==b64fold('C:\\windows\\win.ini'):
            return found('suspicious','encoded_windows_file_probe','下载参数精确命中Windows系统文件的折叠编码指纹；不冒充无损解码',target)
    if method=='get' and target.startswith('/do/job.php?job=download&url='):
        value=target.split('&url=',1)[1].split('&',1)[0]
        if value==b64fold('/etc/passwd<'):
            return found('suspicious','encoded_unix_file_probe','下载参数命中系统口令文件探测值的折叠编码指纹，包含额外边界字符，保守按探测',target)
    if method=='get' and target.startswith('/jsoa/dl.jsp?@jiusi10@') and target.endswith('@jiusi13@'):
        value=target.split('@jiusi10@',1)[1].rsplit('@jiusi13@',1)[0]
        expected='&FileName=../../../dl.jsp&Path=/aaa'
        if value==b64fold(expected):
            return found('suspicious','encoded_application_source_probe','特定下载接口参数命中含目录穿越与脚本源码的编码指纹，不声称恢复实际字节',target)
    if (method=='get' and re.match(r'^/admin[\x01-\x20]+/authentication$',target)):
        return found('suspicious','whitespace_admin_auth_probe','鉴权设置路由中插入非标准空白分隔，符合鉴权路由解析探测，未按普通页面访问处理',target,'bitbucket')
    if (method=='get' and re.fullmatch(r'/tool/log/c\.php\?strip_slashes=md5&host=[a-z]{6,30}',target)):
        return found('suspicious','explicit_php_function_probe','过滤函数选择参数被设为MD5并搭配随机输入，支持用户可控函数调用探测，未见系统命令',target)
    if (method=='post' and target in ['/solr//config','/solr/gettingstarted_shard1_replica_n1/config']
        and re.fullmatch(r'\{\s*"set-property"\s*:\s*\{\s*"requestdispatcher\.requestparsers\.enableremotestreaming"\s*:\s*true\s*\}\s*\}',body.strip())):
        return found('suspicious','solr_remote_streaming_enable_probe','配置请求显式打开有安全风险的远程流读取开关，支持文件读取前置探测；不能证明未授权或已读文件',target+'|enableRemoteStreaming=true','solr')
    if (method=='post' and target=='/login' and re.search(r'(?:^|&)username=[a-z0-9]+\|pwd(?:&|$)',body)):
        return found('suspicious','login_shell_pipe_probe','用户名中插入管道符及工作目录命令，支持命令拼接探测而非普通用户名',target+'|username=*|pwd')
    if (method=='post' and target=='/sitecore_xaml.ashx/-/xaml/sitecore.xaml.tutorials.styles.index'
        and body=='__isevent=1&__source=&__parameters=parsecontrol('):
        return found('suspicious','sitecore_parsecontrol_truncated_probe','精确XAML处理路由和事件参数以ParseControl调用开始，内容截断，仅按表达式入口探测',target+'|parsecontrol(')
    if (method=='get' and target in ['/index.php?s=/index/\\think\\app/invokefunction']):
        return found('suspicious','thinkphp_execution_entry_probe','访问具体框架函数调用入口而非普通页面，参数不足，不提升为已构造执行利用',target)
    if (method=='get' and re.fullmatch(r'/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/(?:pages/ssf_wp_uploads_path/csv/import/)?[a-z]{6,16}\.csv\.php',target)):
        return found('suspicious','uploaded_double_extension_script_probe','上传目录中访问随机名CSV/PHP双扩展脚本，支持上传后执行路径探测，未见脚本源码',target)
    if method in ['get','post','put','head','options']:
        scanner=headers.get('x-scanner','');device=headers.get('x-scan-device-flag','');ua=headers.get('user-agent','')
        if (re.fullmatch(r'(?:topvas|openvas-vt|topsec-vt)\s+[0-9.]+',scanner)
            or device=='aqsm-xray-qyzyc-o-domain-core'
            or re.search(r'\b(?:nuclei/|sqlmap/|nikto/|fuzz faster u fool|nmap scripting engine|libredtail-http)\b',ua)):
            return found('suspicious','explicit_active_scanner_header','完整请求明确携带漏洞扫描工具标记；扫描不代表利用成功，至少不按普通业务请求处理',target+'|scanner-marker:'+scanner+'|'+device+'|'+ua)
    return None
