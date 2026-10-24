"""Roll-forward evidence decisions; no remote interaction or payload execution."""
import json,re
from urllib.parse import unquote
from final_policy import Finding,request,parameters
from request_view import FRAME,preserve

def native_probe(message):
    text=FRAME.sub('',preserve(message),count=1).split('||||',1)[0].strip()
    if re.search(r'"messages"\s*:|"role"\s*:|rs_operation_load_log|interceptcommand|operationcontent',text,re.I):return None
    if re.match(r'^(?:GET|POST|PUT)\s+/',text,re.I):return None
    if text.casefold().startswith('x-timestamp:') and 'event_rule_id=' in text.casefold() and 'r_body=' in text.casefold():
        m=re.search(r'\n\s*\n\s*(\{[^\r\n]+)',text)
        if m:
            try:value,_=json.JSONDecoder().raw_decode(m[1])
            except ValueError:value={}
            url=value.get('dburl','') if isinstance(value,dict) else ''
            if isinstance(value,dict) and value.get('dbdriver','').casefold()=='org.h2.driver' and value.get('dbtype','').casefold()=='h2' and re.fullmatch(r"jdbc:h2:mem:test;[.i]n[.i]t=runscr[.i]pt from 'http://[a-z0-9.-]+\.jorm0\.surf//poc\.sql'",url,re.I):
                return Finding('suspicious','native_h2_remote_script_probe','原生告警片段开头的实际H2连接JSON指定外部安全回连站点SQL脚本；INIT/RUNSCRIPT存在字符损坏且返回404，仅判断攻击探测，不宣称代码执行','native-security-record|H2-driver|remote-script-OAST|damaged-keywords','https://h2database.com/html/features.html#execute_sql_on_connection')
    if text.startswith('\":') and 'r_body="http/1.1 404' in text.casefold() and 'event_name=' in text.casefold() and re.search(r'^x-scanner:[ \t]*t[ \t]*$',text,re.I|re.M):
        if re.search(r'\bget\s+/json_db/kefu_list\.aspx\s+http/1\.1',text,re.I):
            return Finding('suspicious','native_security_record_explicit_scanner_probe','原生安全事件序列内保留具体HTTP请求和X-Scanner标记；序列中的404不证明利用成功或属于同一请求，仅依据显式扫描标记及请求结构判可疑，区别于正常模型转发','native-security-record|HTTP-request|explicit-X-Scanner|mixed-record-no-success-claim','')
    return None

def assess(message):
    f=native_probe(message)
    if f:return f
    d=request(message)
    if not d:return None
    route,_,query=d['target'].partition('?');route=unquote(route).casefold();q=parameters(query)
    if q is None:return None
    if d['method']=='GET' and route in ['/security/users','/system/deviceinfo','/system/configurationfile','/onvif-http/snapshot'] and q.get('auth','').casefold()=='YWRtaW46MTEK'.casefold():
        return Finding('malicious','hikvision_public_magic_query_auth_bypass','设备敏感接口携带公开CVE-2017-7921特殊auth值的完整折叠指纹，支持已知绕过认证尝试；不是普通带令牌API请求，也不声称获取内容成功',route+'|full-public-magic-auth-fingerprint','https://seclists.org/fulldisclosure/2017/Sep/23')
    if d['method']=='GET' and route=='/api/v2/cmdb/system/admin' and not query and d['headers'].get('user-agent','').casefold()=='node.js' and d['headers'].get('forwarded','').casefold()=='by=' and not d['headers'].get('authorization') and not d['headers'].get('cookie'):
        return Finding('suspicious','fortinet_nodejs_malformed_forwarded_probe','管理员接口使用公开CVE-2022-40684检测中的Node.js身份及异常空by来源头；缺少完整伪造本机地址，保守标畸形绕过探测，非成功绕过',route+'|Node.js|empty-Forwarded-by|no-session','https://github.com/projectdiscovery/nuclei-templates/blob/17f5725dc10ced09f464dd2d255c19957aad51e7/http/cves/2022/CVE-2022-40684.yaml')
    if d['method']=='GET' and route=='/api/scrape/kube-system' and not query and not d['headers'].get('authorization') and not d['headers'].get('cookie'):
        return Finding('benign','withdraw_kubeview_route_only_probe','公开实现确认这是正常命名空间数据抓取API；本条无版本、敏感响应、伪造凭据或同目标多攻击序列，单凭路由及无会话不足以覆盖原判，撤回上一轮修改；不是确认绝对正常',route+'|legitimate-scrape-function-counterexample|no-record-specific-exploit-evidence','https://github.com/benc-uk/kubeview/blob/0.1.31/cmd/server/routes.go')
    return None
