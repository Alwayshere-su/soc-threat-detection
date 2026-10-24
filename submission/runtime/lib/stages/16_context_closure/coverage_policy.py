"""Native fragment evidence. Static matching only; no missing endpoint is invented."""
import re
from final_policy import Finding
from request_recovery import recover,OPERATIONS,QUOTED
from request_view import preserve,parameters
from deep_policy import unique_json
FRAME=re.compile(r'^\s*\d+(?:,\d+){3,},')
HRMS='VHmj0PAATTP2HJBPAATTPcyRcHb6hPAATTP2HJFPAATTP59XObqwUZaPAATTP2HJBPAATTP6EvXjT'
HRMS_REF='https://github.com/vaycore/HrmsTool/blob/acd17d8f82b11f475d89e1ca970b33881a2aa8df/README.md'
DAHUA_REF='https://github.com/projectdiscovery/nuclei-templates/blob/17f5725dc10ced09f464dd2d255c19957aad51e7/http/vulnerabilities/dahua/dahua-icc-backdoor-user.yaml'
PIPE_REF='https://github.com/damn77789/nuclei-pocs/blob/81fb60243f8c8e930e9c4f1b65e2110e6e5a9204/folder-7/poc-yaml-secgate-3600-systoolsdetectnet-cgi-rce.yaml'
def assess(message):
 t=preserve(message).strip();rq,ctx=recover(message)
 if ctx!='direct_fragment' or not rq or OPERATIONS.search(t) or QUOTED.search(t):return None
 native=bool(FRAME.match(t));clean=FRAME.sub('',t,count=1).split('||||',1)[0].strip()
 # Complete, case-preserved public ciphertext vector; document gives its plaintext.
 # This is a vector lookup, not a claim of locally decrypting arbitrary ciphertext.
 if native and clean=='filepath='+HRMS:
  return Finding('malicious','hongjing_native_complete_system_file_cipher','原生报文片段的完整且保留大小写的filepath密文逐字符匹配作者公开向量，文档明文为C:/Windows/win.ini；支持系统文件读取尝试，无响应且未本地执行解密工具','native-form|exact-case-preserved-public-cipher|author-plaintext-C:/Windows/win.ini',HRMS_REF)
 # Packet prefix removed by the existing conservative recovery routine. Exact six
 # public fields, but absent request route: retain probe uncertainty.
 auth=rq['body'].split('\nresponse_code:',1)[0].strip()
 form=parameters(auth)
 expected={'username':'justfortest','password':'1','grant_type':'password','client_id':'web_client','client_secret':'web_client','public_key':''}
 if form and {k:v.casefold() for k,v in form.items()}==expected and (native or (t.count('.')>=8 and t.find('username=')>0)):
  return Finding('suspicious','dahua_native_backdoor_credential_probe','原生数据包片段完整匹配公开大华ICC后门检测的六个认证字段；缺少路由和响应，保守作为后门账户探测，不认定认证成功','native-fragment|complete-six-public-backdoor-fields|route-unavailable',DAHUA_REF)
 if not native:return None
 form=parameters(clean)
 if form and set(form)=={'username','password'} and re.fullmatch(r'%\{\d{6,12}\+\d{6,12}\}',form['username']):
  return Finding('suspicious','native_ognl_arithmetic_login_probe','原生登录参数的用户名为完整%{大整数+大整数}表达式，符合OGNL表达式求值探测结构；缺少路由与结果，不标命令执行','native-form|username-OGNL-two-large-integers|password-field','https://cwiki.apache.org/confluence/display/WW/OGNL')
 value=unique_json(clean)
 if isinstance(value,dict) and set(value)=={'usercode','password'} and value['usercode']=="1'" and isinstance(value['password'],str):
  return Finding('suspicious','native_numeric_login_quote_probe','原生登录JSON中数字用户编号后多出闭合单引号，支持SQL语法边界探测；不是完整注入表达式或成功证明','native-JSON|usercode-numeric-single-quote|password-field','')
 if re.fullmatch(r'targethost=\|[a-z]{6,12}',clean,re.I):
  return Finding('suspicious','native_targethost_shell_separator_probe','原生目标主机参数使用管道符加随机词而非主机名；与公开网络诊断命令注入参数机制及本地完整请求的管道输入结构相符，仍缺少实际路由和结果','native-form|targethost-leading-shell-pipe-random-word|no-execution-claim',PIPE_REF)
 return None
