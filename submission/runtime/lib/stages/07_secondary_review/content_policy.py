"""Independent, content-only decisions after inspecting the 116 scoped requests.

No event IDs, source labels, DeepSeek labels, external requests or private answers
enter assess(). Published patterns identify attempted exploitation, not success.
"""
from dataclasses import dataclass
import re

VERSION='medium_request_review_content_v1'
REFERENCES={
    'memberhero':'https://patchstack.com/articles/patching-remote-code-execution-in-the-member-hero-plugin/',
    'armember':'https://wpscan.com/vulnerability/28d26aa6-a8db-4c20-9ec7-39821c606a08/',
    'mantis':'https://openwall.com/lists/oss-security/2017/04/16/3',
    'netgear':'https://ssd-disclosure.com/ssd-advisory-netgear-dgnd3700v2-preauth-root-access/',
    'owncloud':'https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/',
    'confluence':'https://www.thezdi.com/blog/2021/9/21/cve-2021-26084-details-on-the-recently-exploited-atlassian-confluence-ognl-injection-bug',
    'jolokia':'https://www.tenable.com/plugins/was/113200',
    'credentials':'https://nvd.nist.gov/vuln/detail/CVE-2025-26001',
}

@dataclass(frozen=True)
class Decision:
    label:str|None
    family:str
    reason:str
    evidence:str
    reference:str=''

def assess(message,recover,decode_part):
    data,context=recover(message)
    if not data:return Decision(None,'unresolved_frame','请求主体不足，暂不修改','')
    target=decode_part(data['target']);body=decode_part(data['body'])
    headers=decode_part('\n'.join(k+': '+v for k,v in data['headers']))
    active=target+'\n'+body+'\n'+headers
    def d(label,family,reason,reference='',evidence=None):
        return Decision(label,family,reason,evidence if evidence is not None else active,REFERENCES.get(reference,reference))
    if '/wp-admin/admin-ajax.php' in target and 'action=memberhero_send_form' in target and '_memberhero_hook=phpinfo' in target:
        return d('malicious','memberhero_arbitrary_callback','特定未认证AJAX动作配合任意PHP回调选择，属于CVE-2022-0885利用尝试','memberhero')
    if 'arm_shortcode_form_ajax_action' in body and 'arm_action=change-password' in body and 'key2=x&action2=rp&login2=admin' in body:
        return d('malicious','armember_account_takeover','特制重置动作直接为管理员设置新口令，与CVE-2022-1903利用结构一致','armember')
    if re.search(r'^/mantis[^/]*/verify\.php\?id=1&confirm_hash=$',target):
        return d('malicious','mantis_empty_confirmation_bypass','管理员确认流程使用空校验哈希，与CVE-2017-7615未授权访问利用结构一致','mantis')
    if target.startswith('/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm'):
        return d('malicious','netgear_recovered_password_disclosure','口令恢复页配合特制鉴权绕过参数，与公开凭据泄露利用一致','netgear')
    if '/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/getphpinfo.php' in target:
        return d('malicious','owncloud_graphapi_credential_disclosure','直接访问官方明确要求删除的凭据暴露脚本，属于CVE-2023-49103利用尝试','owncloud')
    if re.search(r'querystring=aaa\x27\s*#\{""\["class"\]\}\s*\x27bbb',active):
        return d('malicious','confluence_expression_injection','引号闭合、表达式及类对象访问组成输入逃逸，而非普通搜索字符串','confluence')
    if '/jolokia/exec/com.sun.management:type=diagnosticcommand/compilerdirectivesadd/!/tmp!/' in target:
        return d('malicious','jolokia_arbitrary_file_operation','远程诊断执行动作指定临时文件，符合公开任意文件读取探测组合','jolokia')
    if '/jsherp-boot/platformconfig/getplatform/..;/..;/..;/jsherp-boot/user/getalllist' in target:
        return d('malicious','jsherp_semicolon_privilege_bypass','白名单路由配合多级分号路径穿越，目标是用户数据读取；与普通列表查询不同')
    if target=='/cgi-bin/admin.cgi?command=getusernamepassword':
        return d('malicious','device_password_disclosure','特定设备命令直接获取用户名和密码，符合公开凭据泄露利用参数','credentials')
    if 'ntkoupload.jsp' in target and 'name="newfilename"' in body and re.search(r'd:/htoa/tomcat/webapps/oaapp/htpages/app/module/login/[a-z]+\.txt',body) and 'content-type: image/png' in body:
        return d('malicious','absolute_login_directory_upload','文本内容伪装图片，绝对落地位置指定到登录模块目录，支持任意位置写入探测')
    business_attack_marker=bool(re.search(r'\bunion\s+(?:all\s+)?select\b|\bsleep\s*\(|<!entity|<!doctype|\$\{jndi:|<script\b',active))
    if target=='/yhq_mass/api/v1/mcp/massai/massaigeneralsql?input=select top 500 区县 from dbo.sys_user' and 'apache-httpclient/' in headers and not business_attack_marker:
        return d('benign','business_agent_database_query','业务MCP/SQL查询接口接收完整区县查询，客户端上下文完整，未见拼接逃逸')
    soap_query=re.search(r'<backstr\b[^>]*>(.*?)</backstr>',body,re.S)
    if target=='/jlwebserver/services/queryxs?wsdl' and 'borland soap' in headers and '<ns1:select ' in body and soap_query and soap_query[1].strip()=="select get_hyjftx('8100',-1)txxs from dual" and not business_attack_marker:
        return d('benign','business_soap_function_query','完整SOAP选择操作调用业务函数，SQL位于协议允许的查询字段，无注入闭合或附加语句')
    # Explicit probes; a console name or public metadata name alone is insufficient.
    if 'x-file-name:' in active and re.search(r'x-file-name:\s*[a-z]+\.jsp',active) and 'x-file-type: image' in active:
        return d('suspicious','script_image_type_mismatch','上传头中脚本后缀与图像类型矛盾，未显示脚本执行代码')
    if re.search(r'file_name=[a-z]+\.jsp\.&file_size=',active) and 'comm_type=init' in active:
        return d('suspicious','trailing_dot_script_upload_probe','初始化上传指定脚本后缀加尾点，属于扩展名解析探测')
    if target=='/ ../':return d('suspicious','malformed_parent_path_probe','请求目标含畸形父目录结构，符合目录探测')
    if target in ['/.;/metrics/metrics','/.;/metrics/threads']:
        return d('suspicious','semicolon_metrics_probe','诊断路由前插入分号路径段，符合路由/权限过滤探测')
    if target=='/client/index.php?.php/gsb/users.php':
        return d('suspicious','php_route_confusion_probe','非普通参数形式的PHP脚本路由组合，符合路由解析探测')
    if target=='/api/integrations?/webhooks/trigger':
        return d('suspicious','webhook_route_confusion_probe','受保护集成列表路由附加webhook白名单后缀，符合鉴权路由探测')
    if target.startswith('/autodiscover/autodiscover.json?@test.com/owa/?'):
        return d('suspicious','exchange_proxy_route_probe','自动发现接口配合用户信息符号及OWA路由，属于特殊后端路由探测')
    if target=='/robots.txt/nginx_file_test.php':
        return d('suspicious','nginx_resource_parser_probe','将文本资源作为父路径访问PHP测试文件，符合解析/路径探测')
    if '/s/anything/_/meta-inf/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml' in target:
        return d('suspicious','jira_internal_build_metadata_probe','使用特殊资源路由读取Jira内部构建元数据，偏向版本/路径探测')
    if target=='/wbm/login/?next=https://interact.sh':
        return d('suspicious','login_redirect_callback_probe','登录跳转参数指定专用回连域名，支持开放重定向探测；不宣称已发生SSRF')
    if re.search(r'/machord_doc\.jsp;1\.jpg\?',target):
        return d('suspicious','semicolon_upload_parser_probe','脚本路径拼接分号和图片后缀，属于服务器扩展名解析探测')
    if target=='/cgi-bin/systools/systoolsdetectnet.cgi' and re.search(r'(?:^|&)targethost=\|[a-z]+\|(?:&|$)',body):
        return d('suspicious','diagnostic_command_separator_probe','网络诊断目标使用管道字符包裹测试标记，支持命令注入探测但未确认完整命令')
    if target=='/backupsettings.dat':
        return d('suspicious','configuration_backup_probe','直接定位配置备份数据文件，支持敏感资源发现探测')
    if target=='/lang/log/httpd.log':
        return d('suspicious','webserver_log_discovery','语言资源目录内定位Web服务器日志，支持信息暴露/资源发现探测')
    # Record why the remainder is held rather than forcing the API suggestion.
    if re.search(r'/druid/(?:index|websession)\.html|/solr/admin/cores|/mysql/index\.php|^/jmx-console$|^/manager/html$',target):
        return d(None,'hold_bare_management_interface','仅管理/诊断页面或查询接口，单条请求不足以区分业务访问与扫描')
    if re.search(r'/api/login|/user/authentication',target):
        return d(None,'hold_authentication_context','只有认证接口及凭据，缺少爆破/利用上下文，暂不把可疑降为正常')
    if re.search(r'/(?:database|db)\.sql(?:$|\?)|gibbon\.sql',target):
        return d(None,'hold_dump_severity_boundary','明确面向数据库转储文件，缺少依据将既有恶意降为可疑')
    if '/api/cors/data:text/html;base64,' in target:
        return d(None,'hold_encoded_script_probe','存在编码HTML/脚本探测结构，尚不能可靠还原；不因接口名或失败状态降级')
    if '/inter/pdf_maker.php' in target or '/openpubliccourse.aspx?cid=' in target:
        return d(None,'hold_scanner_with_opaque_input','扫描器标记和不透明输入并存，标记本身不足以否定原有恶意载荷判断')
    if 'destdir=./sysinfo/' in active:
        return d(None,'hold_output_directory_fragment','只有相对输出目录片段，既不足以确认恶意，也不足以确认正常业务')
    return d(None,'hold_insufficient_context','缺少足够的新证据支持修改，保持当前最佳预测')
