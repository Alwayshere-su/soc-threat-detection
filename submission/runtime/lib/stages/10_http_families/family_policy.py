"""Content-only, externally researched additional family decisions."""
import base64,re
from dataclasses import dataclass
from request_view import parse,decode,parameters


@dataclass(frozen=True)
class Finding:
    label:str
    category:str
    reason:str
    evidence:str
    reference:str


def folded(value):return base64.b64encode(value.encode()).decode().casefold()


def fingerprint(value,phrase):
    data=phrase.encode()
    for offset in range(3):
        part=data[offset:];part=part[:len(part)//3*3]
        if len(part)>=9 and base64.b64encode(part).decode().casefold() in value.casefold():return True
    return False


def assess(message):
    data=parse(message)
    if data is None:return None
    method=data['method'];target=data['target'];headers=data['headers'];body=data['body']
    route,_,query=target.partition('?');route=decode(route).casefold()
    q=parameters(query);form=parameters(body)
    if q is None or form is None:return None
    if (method=='POST' and route=='/index.php' and q=={'c':'blocked','action':'continue'}
        and form.get('args_reason')=='filetypewarn' and bool(form.get('user'))
        and form.get('url')==form.get('user')==form.get('filetype')):
        value=form.get('user_encoded','').casefold()
        if value.startswith(folded("\\';curl http://")) and fingerprint(value,'.jorm0.surf #'):
            return Finding('malicious','sophos_encoded_command_callback',
                '已知warn-proceed入口、特定表单结构及编码命令拼接/回连指纹共同出现；未执行或声称恢复完整字节',
                '/index.php?c=blocked&action=continue|user_encoded=quote+curl+callback',
                'https://www.vulncheck.com/blog/cve-2023-1671-analysis')
    if method=='GET' and route=='/client/index.php':
        cookies=parameters(headers.get('cookie','').replace(';','&'))
        if cookies:
            cookies={k.strip():v for k,v in cookies.items()}
            if (cookies.get('e')=='ab' and 'pwn' in cookies and 'ldcsasessid' in cookies
                and cookies.get('exec','').casefold()==folded('system("cat /etc/passwd");')):
                return Finding('malicious','ivanti_cookie_encoded_execution',
                    'CVE-2021-44529特定Cookie触发字段与完整PHP命令的折叠编码指纹共同出现；不是普通会话Cookie',
                    '/client/index.php|e+exec+pwn+LDCSASESSID|system-read-passwd-fingerprint',
                    'https://www.exploit-db.com/exploits/50833')
    if method=='GET' and route=='/picturespreview':
        expected='http://127.0.0.1/1.txt"><svg/onload=alert(document.domain)>'
        if q.get('urls','').casefold()==folded(expected):
            return Finding('malicious','kkfileview_encoded_svg_xss',
                '图片预览参数完整匹配URL闭合及SVG事件脚本的折叠编码值，属于具体XSS探测结构；非无损解码',
                '/picturesPreview|urls=URL-close+svg-onload-alert-fingerprint',
                'https://github.com/kekingcn/kkFileView/issues/407')
    if method=='GET' and route=='/lwa/webpages/lwaclient.aspx':
        value=q.get('meeturl','').casefold()
        if value.startswith('ahr0cdov') and fingerprint(value,'.jorm0.surf/'):
            return Finding('suspicious','lync_encoded_callback_probe',
                '公开服务端抓取入口的meeturl参数含HTTP前缀及回连域编码指纹，支持SSRF探测；原始编码已折叠，不声称完整还原或成功',
                '/lwa/WebPages/LwaClient.aspx|meeturl=http+callback-fingerprint',
                'https://frycos.github.io/vulns4free/2022/09/26/skype-audit-part2.html')
    if (method=='GET' and route=='/plugins/weathermap/editor.php'
        and q.get('plug')=='0' and q.get('mapname')=='poc.conf'
        and q.get('action')=='set_map_properties' and q.get('debug')=='existing'
        and q.get('map_title')=='46ea1712d4b13b55b3f680cc5b8b54e8'):
        return Finding('suspicious','weathermap_known_file_write_probe',
            '配置编辑请求同时携带公开扫描PoC的固定验证标记与poc.conf测试文件，支持写入探测；未见可执行脚本',
            '/plugins/weathermap/editor.php|poc.conf|set_map_properties|public-verification-marker',
            'https://github.com/chaitin/xray/blob/master/pocs/cacti-weathermap-file-write.yml')
    if (method in ['GET',''] and route.startswith('/api/hassio/app/')
        and headers.get('host') and not query):
        if route=='/api/hassio/app/.\t./supervisor/info' or (method=='' and route=='/api/hassio/app/../supervisor/info'):
            return Finding('malicious','homeassistant_tab_or_fragment_auth_traversal',
                '已知Supervisor鉴权绕过路径包含制表符穿越变体或完整URI/HTTP头片段，原始研究明确描述该路径处理差异；不声称执行成功',
                route+'|framed-supervisor-info-traversal',
                'https://github.com/elttam/publications/blob/master/writeups/home-assistant/supervisor-authentication-bypass-advisory.md')
    if (method=='POST' and route=='/api/v1/attachments/flowisetest/'+'../'*8+'tmp'
        and headers.get('content-type','').casefold()=='multipart/form-data; boundary=----flowisepocboundary'
        and body.casefold().startswith('------flowisepocboundary\ncontent-disposition: form-data; name=')):
        return Finding('malicious','flowise_encoded_traversal_upload_attempt',
            '已知附件上传路由中的chatId被构造成连续越界路径，配合特定multipart探测边界；正文截断不证明写入成功，但越界上传意图明确',
            route+'|multipart-traversal-upload-attempt',
            'https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-h42x-xx2q-6v6g')
    return None
