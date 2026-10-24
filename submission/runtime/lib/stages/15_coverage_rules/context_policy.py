"""Narrow static evidence rules. No payload execution or network operations."""
import base64,re
from urllib.parse import unquote
from final_policy import Finding,request,parameters
from cdg_codec import decode,REFERENCE
from request_view import preserve,FRAME

def recovered_attack(message):
    text=FRAME.sub('',preserve(message),count=1).split('||||',1)[0].strip()
    # Preserve genuine operations and model/relay traffic, even if it quotes attacks.
    if re.search(r'"messages"\s*:|"role"\s*:|rs_operation_load_log|interceptcommand|operationcontent|\[root@|boco4a:|"adapter"\s*:|"payloads"\s*:',text,re.I):return None
    if re.match(r'^(?:GET|POST|PUT|PATCH)\s+/(?:api/array2singlemsg|gateway/api/|v1/|largemodel/)',text,re.I):return None
    command=r'/cgi-bin/awstats/awstats\.pl\?configdir=\|cat /etc/passwd;\s*\|'
    if re.search(r'rs_application_aqztsavelog',text,re.I):
        # Accept a native IDS record or an actual attack request followed by IDS records.
        native=re.match(r'^[^\r\n]{0,180}\s*xdproducer',text,re.I)
        direct=re.match(r'^get\s+'+command+r'\s+http/',text,re.I)
        if (native and re.search(r'httpfirstline\(1118\)='+command,text,re.I)) or direct:
            return Finding('malicious','awstats_command_in_native_security_record','原生安全事件的HTTP请求字段或开头请求明确包含AWStats管道执行cat系统账户文件；不是仅凭告警名称或正常模型转发内容判定','native-IDS-or-leading-HTTP|awstats-configdir-pipe-cat-passwd','https://nvd.nist.gov/vuln/detail/CVE-2005-0116')
    boundary=re.search(r'"\s*,\s*"(?:get|post)\s+/',text,re.I)
    if not boundary:return None
    # Some fragments start at the previous request body; others start at a header
    # tail immediately followed by a quoted full request. Only known concrete XXE
    # entry routes and declared-and-used external entities qualify.
    if not re.search(r'"\s*,\s*"(?:get|post)\s+/(?:servlets/omadsservlet|jc6/servlet/pathfile\?geturl|hrss/dorado/smartweb2\.showrpcloadingtip\.d|seeyon/m-signature/runsignature/run/getajaxdataservlet|xmlpserver/convert\?xml=)',text,re.I):return None
    subject=unquote(text)
    entity=re.search(r'<!entity\s+(%\s*)?([\w-]+)\s+system\s+["\x27](file:///etc/passwd|file:///c:/windows/win\.ini|https?://[^"\x27\s]+\.jorm0\.surf/)["\x27]\s*>',subject,re.I)
    if entity:
        ref=('%' if entity[1] else '&')+entity[2]+';'
        if ref.casefold() in subject[entity.end():].casefold():
            return Finding('malicious','request_sequence_concrete_xxe','请求序列片段保留已知XML入口与外部实体声明及实际引用，目标为系统文件或安全回连站点；不把正常聊天或运维记录中的引用当攻击','request-list-fragment|known-XML-entry|external-entity-declared-and-used')
    return None

def assess(message):
    f=recovered_attack(message)
    if f:return f
    d=request(message)
    if not d:return None
    route,_,query=d['target'].partition('?');route=unquote(route).casefold()
    q=parameters(query);form=parameters(d['body'])
    if q is None or form is None:return None
    method=d['method'];h=d['headers']
    if method=='GET' and route=='/images/../info.html' and not h.get('authorization') and not h.get('cookie'):
        return Finding('suspicious','teamcity_public_path_auth_probe','公开目录下的父级路径请求对应TeamCity认证绕过检测路径；没有响应，保守标探测',route+'|GET|no-session','https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/')
    if method=='GET' and route=='/trwfe/service/../ws/identity/user/sysadmin' and not h.get('authorization') and not h.get('cookie'):
        return Finding('malicious','tippay_traversal_admin_identity_read','借助service父级路径访问系统管理员身份接口，匹配公开敏感账户信息读取PoC；不声称实际获得密码',route+'|parent-route|sysadmin|no-session','https://github.com/onewinner/Lightx/blob/66baef13ea408675c6c144ae6e01b1df0a9278eb/config/pocs/tippay-sysadmin-info-leak.yaml')
    if method=='' and q=={} and d['target'].casefold()=='ld_debug=help' and h.get('x-original-uri','').casefold()=='/cgi-bin/login?ld_debug=help':
        return Finding('suspicious','goahead_cgi_loader_variable_probe','HTTP片段和原始URI头共同指向CGI的LD_DEBUG环境变量注入检测参数；无代码执行结果', '/cgi-bin/login|LD_DEBUG=help|matching-original-uri','https://github.com/projectdiscovery/nuclei-templates/blob/17f5725dc10ced09f464dd2d255c19957aad51e7/http/cves/2017/CVE-2017-17562.yaml')
    if method=='GET' and route=='/formloginauth.htm' and q==dict(authcode='1',username='admin',gourl='',action='login') and not d['body']:
        return Finding('malicious','totolink_client_forged_auth_success','无密码的登录请求直接指定authCode=1和管理员身份，符合公开认证结果伪造请求；不声称登录成功',route+'|authCode=1|username=admin|action=login|no-password','https://github.com/projectdiscovery/nuclei-templates/blob/17f5725dc10ced09f464dd2d255c19957aad51e7/http/cves/2021/CVE-2021-42887.yaml')
    if method=='GET' and route=='/authtoken/index' and q.get('loginname')=='system' and q.get('token')=='c94ad0c0aee8b1f23b138484f014131f':
        return Finding('malicious','sailan_public_fixed_admin_token','系统账户登录接口使用公开漏洞样例的固定认证令牌，支持伪造管理员登录尝试',route+'|loginName=system|public-fixed-token','https://github.com/eeeeeeeeee-code/POC/tree/11c00cc5e129cb7d6ed8a99ef1fc108ae83719b8/wpoc')
    if method=='POST' and re.fullmatch(r'/cdgserver3/+linkfilterservice',route) and all(k in form for k in ['path','userid','cur']):
        try:values={k:decode(form[k]) for k in ['path','userid','cur']}
        except ValueError:return None
        if values==dict(path=b'/frame.jsp',userid=b'systemadmin',cur=b'3925-01-10 00:00:00'):
            return Finding('malicious','cdg_decoded_admin_future_expiry','公开CDG算法无损解码出系统管理员、框架入口及3925年时间戳，构成已知管理员身份与有效期伪造组合',route+'|decoded-systemadmin|decoded-frame.jsp|decoded-year3925',REFERENCE)
    if method=='POST' and re.fullmatch(r'/cdgserver3/(?:autosignservice1|createdocservice1|emailauditservice|fileauditservice|getmakeoutsendfileinfoservice|systemservice)',route):
        body=d['body'];declared=h.get('content-length','')
        if not re.fullmatch(r'[A-Pa-p]{128,}',body):return None
        complete=not (declared.isdigit() and int(declared)>len(body.encode()))
        if len(body)%2:
            if complete:return None
            body=body[:-1]
        try:plain=decode(body,complete=complete)
        except ValueError:return None
        required=[b'<java.util.PriorityQueue',b'org.apache.commons.beanutils.BeanComparator',b'<property>outputProperties</property>',b'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',b'<byte-array>']
        if not all(x in plain for x in required):return None
        m=re.search(rb'<byte-array>\s*([A-Za-z0-9+/=]+)',plain)
        if not m:return None
        encoded=m[1];encoded=encoded[:len(encoded)//4*4]
        try:bytecode=base64.b64decode(encoded,validate=True)
        except ValueError:return None
        if not bytecode.startswith(b'\xca\xfe\xba\xbe') or b'AbstractTranslet' not in bytecode:return None
        return Finding('malicious','cdg_decoded_beanutils_templates_gadget','仅解码可用完整AES块；已见BeanComparator/outputProperties与TemplatesImpl字节码加载链，嵌入Java类头及AbstractTranslet标记，支持反序列化攻击尝试；未反序列化或执行',route+'|decoded-PriorityQueue-BeanComparator-outputProperties-TemplatesImpl|CAFEBABE|AbstractTranslet|prefix-only='+str(not complete),REFERENCE)
    return None
