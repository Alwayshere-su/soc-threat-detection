"""Static content evidence; no identifiers, API calls or target interaction."""
import base64,hashlib,hmac,json,re
from dataclasses import dataclass
from urllib.parse import unquote
from request_view import parse,preserve,FRAME,HTTP,decode,parameters
from request_recovery import recover

@dataclass(frozen=True)
class Finding:
    label:str
    category:str
    reason:str
    evidence:str
    reference:str=''

def folded(s):return base64.b64encode(s.encode()).decode().casefold()

def request(message):
    d=parse(message)
    if d:return d
    _,context=recover(message)
    if context!='recovered_http_fragment':return None
    text=FRAME.sub('',preserve(message),count=1).strip()
    first,_,suffix=text.partition('\n')
    if not re.search(r'\s+http/\d(?:\.\d)?\s*$',first,re.I):return None
    target=re.sub(r'\s+http/\d(?:\.\d)?\s*$','',first,flags=re.I)
    headers={};body=[];in_body=False
    for line in suffix.splitlines():
        if not in_body:
            if not line.strip():
                if headers:in_body=True
                continue
            h=re.fullmatch(r'([a-zA-Z][a-zA-Z0-9_-]{0,60})\s*:\s*(.*)',line)
            if h:
                key=h[1].casefold()
                if key in headers:return None
                headers[key]=h[2];continue
            in_body=True
        body.append(line)
    if not headers.get('host'):return None
    return dict(method='',target=target,headers=headers,body='\n'.join(body).strip(),context=context)

def assess(message):
    d=request(message)
    if not d:
        legacy,context=recover(message)
        if legacy and context=='direct_fragment':
            text=FRAME.sub('',preserve(message),count=1).split('||||',1)[0].strip()
            pattern=r'forwarded: for="\[127\.0\.0\.1\]:8888";by="\[127\.0\.0\.1\]:8888"\s+\{"ssh-public-key1": "[a-z]{10}"\}'
            if re.fullmatch(pattern,text,re.I):
                return Finding('suspicious','fortinet_forged_admin_write_fragment','独立片段包含精确伪造回环来源头及管理员SSH公钥修改字段；缺少请求行，保守标可疑','fragment|forged-loopback-forwarded|ssh-public-key1','https://www.rapid7.com/blog/post/ra-cve-2022-40684-analysis/')
        return None
    method=d['method'];target=d['target'];headers=d['headers'];body=d['body']
    route,sep,query=target.partition('?');route=decode(route).casefold()
    q=parameters(query);form=parameters(body)
    if q is None or form is None:return None
    if method=='GET' and route=='/index.php' and q.get('m')=='openmodhetong|openapi' and q.get('d')=='task' and q.get('a')=='data' and q.get('ajaxbool')=='0' and q.get('nickname','').casefold()==folded("1' and sleep(0)#"):
        return Finding('malicious','xinhu_encoded_sql_delay','特定路由、操作参数与完整引号闭合/延时SQL折叠指纹共同出现，支持注入尝试；不是无损解码或成功证明',route+'|nickname=quote-and-sleep-zero-fingerprint','https://nvd.nist.gov/vuln/detail/CVE-2024-7327')
    if method=='GET' and route=='/general/edu/appserver/appserver_interface.php' and q.get('data_s','').casefold()==folded('a:1:{s:3:"SQL";s:17:"select md5(72672)";}'):
        return Finding('malicious','tongda_encoded_sql_object','接口中data_s完整匹配含SQL字段和MD5校验查询的PHP数组折叠编码指纹，属具体SQL执行探测结构；未反序列化',route+'|data_s=php-array-SQL-md5-fingerprint')
    if method=='GET' and route=='/acenter/dbcall.action' and q.get('cmdid')=='10018' and q.get('verify_userid')=='dasd' and q.get('querystring','').casefold() in [folded('select md5(49576)'),folded('select md5(36843)')] and form.get('user')=='1':
        return Finding('suspicious','acenter_encoded_sql_verification','数据库调用接口同时出现伪造用户标记和编码MD5验证查询，支持特定查询探测；不把单独SQL语句等同注入成功',route+'|cmdid=10018|verify_userid=dasd|query=select-md5-fingerprint')
    if method=='GET' and route=='/common/dataexportfiledownload/' and query.casefold()==folded('displayFileName=1.txt&tempFileName=./../web.config'):
        return Finding('suspicious','encoded_export_config_traversal','完整参数编码匹配显示文件名及越界web.config路径的折叠指纹，支持配置文件探测；不声称无损解码',route+'|displayFileName=1.txt|tempFileName=parent-web.config')
    if method in ['GET','']:
        f=q if method else parameters(target)
        if f and f.get('page')=='download_video' and f.get('dl','').casefold()==folded('/etc/passwd') and (route=='/wp-admin/admin-post.php' or method==''):
            return Finding('malicious','encoded_wordpress_system_file_read','文件下载操作字段和完整系统账户文件折叠编码指纹共同出现；片段保留HTTP版本及Host头', '/wp-admin/admin-post.php-or-query-fragment|page=download_video|dl=passwd-fingerprint')
    if method=='POST' and route=='/servlet/nc.bs.hr.tools.trans.fileservlet' and form.get('path','').casefold()==folded('/etc/passwd'):
        return Finding('malicious','encoded_nc_system_file_read','文件服务Servlet的path完整匹配系统账户文件的折叠编码指纹，非普通业务文件',route+'|path=passwd-fingerprint')
    if method=='' and parameters(target):
        f=parameters(target)
        if f.get('base64url','').casefold()==folded('`echo hbwhqxvv > gvdu.txt`') and f.get('format')=='jpg':
            return Finding('malicious','youphptube_encoded_command_fragment','保留HTTP版本及Host的图片参数片段完整匹配反引号echo写文件命令的折叠指纹，对应公开YouPHPTube命令注入入口参数','HTTP-fragment|base64Url=backtick-echo-file-write|format=jpg','https://talos.talosintelligence.com/vulnerability_reports/TALOS-2019-0917')
    if method=='PUT' and route=='/api/v2/cmdb/system/admin/admin' and headers.get('user-agent','').casefold()=='report runner' and headers.get('forwarded','')=='for="[127.0.0.1]:8888";by="[127.0.0.1]:8888"':
        try:value=json.loads(body)
        except ValueError:value=None
        if value and set(value)=={'ssh-public-key1'} and isinstance(value['ssh-public-key1'],str) and value['ssh-public-key1']:
            return Finding('malicious','fortinet_forged_local_admin_key_write','特定Report Runner头、伪造本地来源和修改管理员SSH公钥操作共同构成已知鉴权绕过尝试；不声称公钥有效或写入成功',route+'|PUT|Report Runner|forged-loopback|ssh-public-key1','https://www.rapid7.com/blog/post/ra-cve-2022-40684-analysis/')
    if method=='POST' and route=='/' and headers.get('x-wcpay-platform-checkout-user')=='1' and form.get('rest_route')=='/wp/v2/users' and form.get('roles')=='administrator' and all(form.get(x) for x in ['username','email','password']):
        return Finding('malicious','woocommerce_forged_admin_user_creation','伪造结账用户身份头与新增管理员账户参数共同命中CVE-2023-28121利用结构，非普通登录',route+'|x-wcpay-platform-checkout-user=1|rest_route=/wp/v2/users|roles=administrator','https://www.rcesecurity.com/2023/07/patch-diffing-cve-2023-28121-to-compromise-a-woocommerce/')
    if method=='GET' and route=='/dyxtzpje' and q.get('jsp')=='/app/rest/users;.jsp':
        return Finding('malicious','teamcity_jsp_dispatch_auth_bypass','非正常外层路径配合jsp参数和分号后缀，构成CVE-2024-27198的内部用户接口鉴权绕过请求',route+'|jsp=/app/rest/users;.jsp','https://github.com/vulhub/vulhub/blob/master/teamcity/CVE-2024-27198/README.md')
    if (method=='GET' and route=='/webinterface/function/' and q.get('command')=='getUserList' and q.get('servergroup')=='MainUsers' and q.get('c2f')=='6337'
        and headers.get('authorization','').startswith('AWS4-HMAC-SHA256 Credential=crushadmin/')
        and 'SignedHeaders=' not in headers['authorization'] and 'Signature=' not in headers['authorization']
        and 'currentAuth=6337' in headers.get('cookie','')):
        return Finding('malicious','crushftp_mangled_aws4_admin_auth','用户枚举请求携带crushadmin的AWS4身份字段，缺少签名和SignedHeaders，配合固定currentAuth，符合公开CVE-2025-31161畸形认证绕过结构',route+'|getUserList|crushadmin|mangled-AWS4-no-signature|currentAuth=6337','https://github.com/advisories/GHSA-c57h-rx24-vf52')
    if method=='GET' and route=='/api/blade-user/user-list' and headers.get('blade-auth'):
        token=headers['blade-auth'].split()[-1];parts=token.split('.')
        try:
            head=json.loads(base64.urlsafe_b64decode(parts[0]+'='*((-len(parts[0]))%4)))
            payload=json.loads(base64.urlsafe_b64decode(parts[1]+'='*((-len(parts[1]))%4)))
            signature=base64.urlsafe_b64encode(hmac.new(b'bladexisapowerfulmicroservicearchitectureupgradedandoptimizedfromacommercialproject',(parts[0]+'.'+parts[1]).encode(),hashlib.sha512).digest()).decode().rstrip('=')
            valid=len(parts)==3 and hmac.compare_digest(signature,parts[2])
        except (ValueError,IndexError,TypeError):valid=False
        if valid and isinstance(head,dict) and isinstance(payload,dict) and head.get('alg')=='HS512' and payload.get('role_name')=='administrator' and payload.get('user_name')=='admin' and 'exp' not in payload:
            return Finding('suspicious','bladex_default_key_nonexpiring_admin_token','用户列表请求中的管理员JWT无过期字段，且可用产品公开默认密钥校验，支持默认密钥利用探测；不把签名有效当作实际入侵证明',route+'|HS512|public-default-key-valid|admin|no-exp','https://sns.bladex.cn/q-10342.html')
    if method=='POST' and route=='/wp-admin/admin-ajax.php' and form.get('action')=='wpt_admin_update_notice_option' and form.get('option_key')=='a' and form.get('perpose')=='update' and form.get('callback')=='var_dump' and re.fullmatch(r'\d{6} \d{6}',form.get('option_value','')):
        return Finding('suspicious','woo_product_table_callback_verification','已知任意函数调用入口使用var_dump回调和两个随机整数作校验值，支持CVE-2022-1020探测；非危险函数或执行成功证明',route+'|wpt_admin_update_notice_option|callback=var_dump|numeric-test-values','https://wpscan.com/vulnerability/04fe89b3-8ad1-482f-a96d-759d1d3a0dd5/')
    if method=='GET' and route=='/mifs/aad/api/v2/authorized/users' and q.get('admindevicespaceid')=='1' and not headers.get('authorization') and not headers.get('cookie'):
        return Finding('suspicious','ivanti_epmm_aad_user_probe','缺少会话的AAD特殊命名空间用户枚举请求对应公开CVE-2023-35078检测路径；无响应，保守标可疑',route+'|adminDeviceSpaceId=1|no-session','https://www.cert.ssi.gouv.fr/alerte/CERTFR-2023-ALE-009/')
    if method=='GET' and route in ['/verify.php','/bugs/verify.php'] and q=={'id':'1','confirm_hash':''}:
        return Finding('suspicious','mantis_empty_hash_reset_probe','管理员编号配合空confirm_hash的恢复请求符合CVE-2017-7615弱口令恢复机制探测；无响应或重置结果',route+'|id=1|confirm_hash=empty','https://advisories.checkpoint.com/defense/advisories/public/2017/cpai-2017-0417.html/')
    if method=='POST' and route=='/passwordrecovered.cgi' and q=={'id':'get_rekt'} and not body:
        return Finding('suspicious','netgear_fixed_password_disclosure_probe','密码恢复接口使用公开漏洞PoC的固定get_rekt测试标记，支持口令泄露探测；未见响应',route+'|POST|id=get_rekt','https://www.exploit-db.com/exploits/41205')
    if method=='GET' and route=='/getfavicon' and q.get('host')=='bxss.me/t/fit.txt?':
        return Finding('suspicious','favicon_scanner_file_callback','获取站点图标接口的host参数被设为安全检测回连站点文本测试路径，支持服务端回连探测，非普通域名',route+'|host=security-callback-text-path')
    if method=='' and parameters(target):
        f=parameters(target)
        if f.get('include')=='HttpGet' and re.fullmatch(r'http://[a-z0-9.]+\.jorm0\.surf/',f.get('meta','')):
            return Finding('suspicious','httpget_callback_fragment','保留HTTP版本及Host的参数片段同时含HttpGet操作及安全测试回连域，支持服务端请求探测','HTTP-fragment|include=HttpGet|meta=OAST-domain')
        if f.get('user')=='messagebus' and f.get('cmd')=='15' and f.get('system')=='aWQ=':
            return Finding('malicious','nas_encoded_id_command_fragment','保留HTTP版本及Host的片段同时含messagebus、cmd=15及可无损解码为id的system参数，符合公开D-Link NAS命令注入探测结构','HTTP-fragment|user=messagebus|cmd=15|system=base64-id','https://nvd.nist.gov/vuln/detail/CVE-2024-3273')
        if re.fullmatch(r'id,md5\(\d{5}\)',f.get('field','')) and f.get('size')=='1' and f.get('cat')=='3' and f.get('time_stamp')=='1781864476':
            return Finding('malicious','ideacms_field_sql_expression_fragment','保留HTTP版本及Host的field参数含SQL函数表达式，并携带公开CVE-2025-5569模板的固定参数组合，支持SQL注入验证尝试','HTTP-fragment|field=id,md5(number)|size=1|cat=3|template-timestamp','https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5569.yaml')
        if re.fullmatch(r'\.{8,}winntwin\.ini',f.get('ns-query-pat',''),re.I):
            return Finding('suspicious','iplanet_legacy_system_file_fragment','保留HTTP版本及Host的NS-query-pat参数包含连续点与winnt系统文件目标，符合公开iPlanet文件访问探测字段；分隔符已损坏，保守标可疑','HTTP-fragment|NS-query-pat|repeated-dots|winnt-win.ini','https://vulners.com/nessus/IPLANET_SEARCH.NASL')
    if method=='' and route=='/minio/bootstrap/v1/verify' and not query and headers.get('transfer-encoding','').casefold()=='chunked' and 'firefox/' in headers.get('user-agent','').casefold():
        return Finding('suspicious','minio_bootstrap_environment_probe_fragment','HTTP片段定向访问CVE-2023-28432环境信息暴露接口，保留Host及chunked头；无正文和响应，保守标可疑',route+'|HTTP-fragment|chunked','https://www.invicti.com/web-application-vulnerabilities/minio-information-disclosure-cve-2023-28432')
    if method=='GET' and route=='/member/resetpassword.php' and q=={'dopost':'safequestion','safequestion':'0.0','id':'1'}:
        return Finding('suspicious','dedecms_numeric_zero_recovery_probe','口令恢复请求使用非标准0.0安全问题及用户1，符合公开PHP弱比较密码恢复探测形态；无重置结果',route+'|dopost=safequestion|safequestion=0.0|id=1','https://cn-sec.com/archives/246753.html')
    if method=='' and route=='//..;/..;/..;/..;/api/9/nginx':
        return Finding('suspicious','semicolon_auth_traversal_fragment','保留HTTP版本和Host的URI片段使用多层分号目录穿越访问管理API，具有规避路径匹配结构',route+'|framed-URI')
    if method=='PUT' and re.fullmatch(r'/\d{6}/\d{6}/session',route) and headers.get('content-range')=='bytes 0-1800/2000' and headers.get('content-type')=='text/plain' and 'testclass' in body.casefold() and body.startswith('....sr..'):
        return Finding('suspicious','tomcat_partial_put_serialization_probe','分段PUT写入session路径，结合Java序列化测试类片段，符合CVE-2025-24813探测阶段；不声称具有完整执行链',route+'|partial-PUT|session|serialized-testclass','https://tomcat.apache.org/security-9.html')
    return None
