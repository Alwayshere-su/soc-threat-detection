"""Additional scoped evidence after extended85. Static parsing only."""
import base64,json,re
from urllib.parse import unquote
from final_policy import Finding,request,parameters,folded

NUCLEI='https://github.com/projectdiscovery/nuclei-templates/blob/17f5725dc10ced09f464dd2d255c19957aad51e7/'
POC='https://github.com/eeeeeeeeee-code/POC/tree/11c00cc5e129cb7d6ed8a99ef1fc108ae83719b8/wpoc/'
def unique_json(text):
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise ValueError('ambiguous repeated JSON field')
            out[k]=v
        return out
    try:return json.loads(text,object_pairs_hook=pairs)
    except ValueError:return None

def finding(label,category,reason,evidence,reference):return Finding(label,category,reason,evidence,reference)

def assess(message):
    d=request(message)
    if not d:return None
    route,_,query=d['target'].partition('?');route=unquote(route).casefold()
    q=parameters(query);form=parameters(d['body']);h=d['headers'];method=d['method'];body=d['body']
    if q is None or form is None:return None
    no_session=not h.get('authorization') and not h.get('cookie')
    # A stray SQL delimiter in a numeric identifier is a probe, not a complete
    # executable SQL expression. Scope it to the observed vulnerable actions.
    numeric_quote=(method=='GET' and route=='/board/forumrunner/request.php' and q.get('cmd')=='get_spam_data' and q.get('postids')=="-1'}") or (method=='GET' and route=='/portal/pt/yercommon/linkvoucher' and q.get('pageid')=='login' and q.get('pkbill')=="1'") or (method=='' and parameters(d['target'])=={'userids':'-1','tpids':"1'"})
    if numeric_quote:
        return finding('suspicious','numeric_identifier_sql_delimiter_probe','数字编号后出现SQL闭合单引号或额外右括号，配合具体读取动作或HTTP片段头支持异常输入探测；不当作完整SQL执行','known-numeric-id-action|stray-SQL-closing-delimiter',POC+'用友OA')
    flyrise='/v8AMQAJAC8ACQAvAAkALwAJAC8ALgAuAC8ALgAuAC8ALgAuAC8AagBiAG8AcwBzAC8AdwBlAGIALwBmAGUALgB3AGEAcgAvAFcARQBCAC0ASQBOAEYALwB3AGUAYgAuAHgAbQBs'
    if method=='POST' and route=='/servlet/webchat/attachment/1' and form.get('mailattachment')=='1' and form.get('attachpk','').casefold()==flyrise.casefold():
        return finding('malicious','flyrise_complete_encoded_private_file_traversal','附件下载参数完整匹配公开UTF-16路径编码的多级穿越至应用WEB-INF/web.xml样例；使用完整折叠指纹，不声称受损Base64可无损解码',route+'|mailAttachment=1|complete-public-UTF16-traversal-fingerprint','https://github.com/damn77789/nuclei-pocs/blob/81fb60243f8c8e930e9c4f1b65e2110e6e5a9204/folder-5/poc-yaml-flyrise-enterprise-attachment-anyfile-read.yaml')
    if method=='POST' and route=='/api/support/user/account/loginbypassword':
        value=unique_json(body)
        if isinstance(value,dict) and isinstance(value.get('username'),str) and isinstance(value.get('password'),dict):
            operators=value['password']
            if set(operators)=={'$ne'} and isinstance(operators['$ne'],str):
                return finding('malicious','fastgpt_password_nosql_auth_bypass','登录密码被替换为MongoDB非等查询对象，利用字符串密码与查询运算符的类型混淆尝试绕过认证；不是普通密码登录',route+'|password-object|Mongo-$ne','https://github.com/Tencent/AI-Infra-Guard/blob/8e715c3826878c9ae251b60e2fd4967a56048a71/data/vuln/fastgpt/CVE-2026-40351.yaml')
    if method=='GET' and route.rstrip('/')=='/helpdesk/webobjects/helpdesk.woa/ra/oriontickets':
        auth=h.get('authorization','').split(None,1)
        public=base64.b64encode(b'helpdeskIntegrationUser:dev-C4F8025E7').decode().casefold()
        if len(auth)==2 and auth[0].casefold()=='basic' and auth[1].casefold()==public:
            return finding('malicious','solarwinds_hardcoded_integration_account','工单接口认证值完整匹配公开硬编码集成账户凭据的折叠指纹，属于CVE-2024-28987后门账户利用尝试；不把任意Basic认证当攻击',route+'|full-public-hardcoded-basic-fingerprint',NUCLEI+'http/cves/2024/CVE-2024-28987.yaml')
    if method=='POST' and re.fullmatch(r'/evo-apigw/+evo-oauth/oauth/token',route) and form.get('username','').casefold()=='justfortest' and form.get('password')=='1' and form.get('grant_type')=='password' and form.get('client_id')=='web_client' and form.get('client_secret')=='web_client':
        return finding('malicious','dahua_icc_public_test_backdoor','OAuth令牌请求使用公开justForTest后门账户和固定密码及客户端字段，区别于一般账户登录',route+'|public-justForTest-backdoor|fixed-client-fields',POC+'大华')
    if method=='GET' and route=='/admin/access/setup/default.aspx' and q.get('action','').casefold()=='createadministrator' and all(q.get(k) for k in ['adminusername','adminpassword','adminemail','adminname']) and no_session:
        return finding('malicious','dynamicweb_unauth_admin_creation','无会话直接调用Dynamicweb初始化接口创建管理员，匹配CVE-2022-25369的具体写入操作',route+'|createadministrator|account-fields|no-session',NUCLEI+'http/cves/2022/CVE-2022-25369.yaml')
    if method=='POST' and route=='/cgi-bin/jumpto.php' and q.get('class')=='user' and q.get('page')=='config_save' and q.get('isphp')=='1' and form.get('call_function')=='user' and form.get('opt')=='3' and form.get('level')=='2' and form.get('user') and form.get('newpassword') and no_session:
        return finding('malicious','cdata_unauth_privileged_user_creation','无Cookie或认证的用户创建接口明确指定opt=3、level=2及新用户名密码，匹配CVE-2023-3305访问控制缺陷请求',route+'|user-config-save|opt3-level2|create-account|no-session','https://github.com/sleepyvv/vul_report/blob/main/C-data/BrokenAccessControl.md')
    if method in ['GET','POST'] and route=='/importexport.php' and q.get('type')=='exportexcelbysql' and q.get('sql','').casefold()==folded('select 1,2,md5(39004)'):
        return finding('malicious','smart_s200_encoded_sql_hash_execution','导出接口的sql参数完整匹配选择常数和MD5校验值的编码指纹，结合exportexcelbysql操作指向公开SQL执行漏洞检测',route+'|exportexcelbysql|select-constants-md5-fingerprint',NUCLEI+'http/cves/2024/CVE-2024-27718.yaml')
    cmseasy='Ud-ZGLMFKBOhqavNJNK5WRCu9igJtYN1rVCO8hMFRM8NIKe6qmhRfWexXUiOqRN4aCe9aUie4Rtw5'
    if method=='GET' and route=='/' and q.get('case')=='crossall' and q.get('act')=='execsql' and q.get('sql','').casefold()==cmseasy.casefold():
        return finding('malicious','cmseasy_public_encrypted_sql_execution','crossall/execsql请求中的完整加密SQL值匹配公开取账户密码MD5样例的折叠指纹，不是仅凭sql参数名判定',route+'|crossall-execsql|complete-public-encrypted-query-fingerprint','https://github.com/Threekiii/Awesome-POC/blob/0f9e22b660cb1ea12c1c3668f9128d93e08da412/CMS漏洞/CmsEasy%20crossall_act.php%20SQL注入漏洞.md')
    # No response: retain uncertainty for readonly exposure checks. Require exact
    # product endpoint/parameters, a full HTTP GET and absence of a session.
    if method=='GET' and no_session:
        rules=[
            (route=='/exportemployeedetails.aspx' and q.get('actionname','').casefold() in ['exportemployeedetails','exportemployeeotherdetails'],'smartoffice_employee_export_probe','SmartOffice已公开未授权员工资料导出入口，且缺少会话；按敏感信息探测标可疑，不声称已导出','export-employee|known-action', 'https://github.com/vulncheck-oss/0day.today.archive/blob/3664abdd71985a44aff3260896a8f36e2f4a9682/web-applications/38811.txt'),
            (route=='/org/service/service.asmx/getuserxml4geps' and not query,'glodon_account_xml_exposure_probe','广联达已公开账户XML泄露入口被无会话请求；无响应，标可疑','account-XML|no-session','https://github.com/zan8in/afrog/blob/3d88df1f2ccf3312219479fe7f1a1e6a4605f90c/pocs/afrog-pocs/vulnerability/glodon-linkworks-Service.asmx-disclosure.yaml'),
            (route=='/api/scrape/kube-system' and not query,'kubeview_system_namespace_exposure_probe','无会话读取公开CVE-2022-45933的kube-system抓取入口，存在集群证书暴露风险；无响应，标可疑','kube-system-scrape|no-session',NUCLEI+'http/cves/2022/CVE-2022-45933.yaml'),
            (route=='/api/get_visitor_info' and q=={'table':'userinfo'},'zktime_user_table_exposure_probe','访客信息接口被指定读取用户账户表，匹配ZKTime公开信息泄露检测结构；无响应，标可疑','visitor-API|table=userinfo',POC),
            (route=='/easy7/rest/user/loadalluserbeans' and not query,'easy7_all_users_exposure_probe','无会话请求Easy7公开全部用户信息泄露接口；无响应，标可疑','all-user-beans|no-session','https://github.com/haiqingge/vuln-reproductions/tree/9f0d4eb46676f34b51e2dd9a8ab424c560bcc45c/tiandy-easy7-loadalluserbeans-info-leak'),
            (route=='/admin/cascade_/user_edit.action' and q=={'id':'1'},'dahua_cascade_admin_disclosure_probe','无会话请求大华DSS公开用户编辑信息泄露检测路径和编号；无响应，标可疑','cascade-user-edit|id1|no-session',POC+'大华'),
            (route=='/background/reservationcomplete.php' and q=={'id':'1'},'yonyou_reservation_login_probe','用友CRM公开逻辑登录绕过路径及固定编号被无会话访问；缺少后续会话结果，标可疑','reservationcomplete|id1|no-session',POC+'用友OA'),
        ]
        for ok,category,reason,evidence,reference in rules:
            if ok:return finding('suspicious',category,reason,route+'|'+evidence,reference)
    # Exact public authentication-filter pretext plus a different sensitive
    # operation in a multipart body; malformed delimiter still only a probe.
    pretext="zDp4Wp4gRip+iIpiGZp4DRw6+/JV/uuu7uNf7NfN1/u71'/NOJM/NOJN/uu/JT"
    if method=='POST' and route in ['/smartbi/vision/rmiservlet','/vision/rmiservlet'] and q.get('windowunloading','').casefold()==pretext.casefold() and 'multipart/form-data' in h.get('content-type','').casefold():
        fields={m[1].casefold():m[2].strip().casefold() for m in re.finditer(r'content-disposition:\s*form-data;\s*name="([\w]+)"\s*\n\s*\n([^\n]*)',body,re.I)}
        if fields.get('classname')=='configclientservice' and fields.get('methodname')=='getsystemconfigs' and fields.get('params')=='[]':
            return finding('suspicious','smartbi_encoded_whitelist_pretext_config_probe','完整公开白名单编码指纹与正文中另一项读取系统配置操作共同出现；本地分隔符与原始利用结构存在差异，保守标绕过探测，非RCE成功',route+'|public-checkVersion-pretext|multipart-ConfigClientService-getSystemConfigs','https://github.com/ax1sX/SecurityList/blob/5a99da1aa91685827c1e72429fff9dc63ce7967c/Java_OA/Smartbi_Audit.md')
    return None
