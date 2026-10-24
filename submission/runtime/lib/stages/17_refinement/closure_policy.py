"""Account creation and explicit cross-record file-write verification evidence."""
import hashlib,re
from urllib.parse import unquote
from final_policy import Finding
from request_view import parse,parameters
from deep_policy import unique_json
DAYS_REF='https://github.com/xinyisleep/pocscan/blob/ee0c74e68ec95b82a4e4ebcdb961d6ed18a44b77/浪擎科技 DAYS灾备系统 存在任意用户创建逻辑漏洞DSO-07087.py'
def digest(message):return hashlib.sha256(message.encode()).hexdigest()
def writer(p):
 if not p or p['method']!='POST':return None
 route,_,query=p['target'].partition('?');q=parameters(query)
 if q is None:return None
 route=route.casefold()
 if route=='/seeyon/wpsassistservlet' and q.get('flag')=='save' and q.get('fileid')=='2':
  target=unquote(q.get('realfiletype','')).casefold()
  if target.count('../')>=2 and '/webapps/root/' in target and re.search(r'<%\s*out\.println\s*\(',p['body'],re.I):
   name=target.rsplit('/',1)[-1]
   if re.fullmatch(r'[a-z0-9]{6,16}\.jsp',name):return '/'+name,'seeyon-jsp-write-verification'
 if route=='/webreport/reportserver' and q.get('op')=='svginit' and q.get('cmd')=='design_save_svg':
  target=unquote(q.get('filepath','')).casefold();j=unique_json(p['body'])
  if target.count('../')>=2 and '/webreport/' in target and isinstance(j,dict) and isinstance(j.get('__content__'),str) and j.get('__charset__')=='utf-8':
   name=target.rsplit('/',1)[-1]
   if re.fullmatch(r'[a-z0-9]{6,16}\.jsp',name):return '/webreport/'+name,'webreport-jsp-write-verification'
 return None
def build_context(raw):
 writes={};gets=[]
 for r in raw.itertuples(index=False):
  if r.pipeline!='payload':continue
  p=parse(r.message_sanitized)
  if not p:continue
  host=p['headers'].get('host','').casefold()
  if not host:continue
  w=writer(p)
  if w:
   key=(str(r.src_ip),str(r.timestamp),host,w[0]);writes.setdefault(key,[]).append((digest(r.message_sanitized),w[1]))
  if p['method']=='GET' and '?' not in p['target']:
   gets.append((digest(r.message_sanitized),(str(r.src_ip),str(r.timestamp),host,p['target'].casefold())))
 result={}
 for content,key in gets:
  if key in writes:result[content]=sorted(set(writes[key]))
 return result
def assess(message,context=None):
 p=parse(message)
 if not p:return None
 route,_,query=p['target'].partition('?');form=parameters(p['body']);h=p['headers']
 if p['method']=='POST' and route.casefold()=='/authctrl/add_user' and not query and form and set(form)=={'usertype','username','password','retrypassword'} and form['usertype']=='2' and re.fullmatch(r'[a-z]{6,32}',form['username'],re.I) and form['password'] and form['password']==form['retrypassword'] and not h.get('cookie') and not h.get('authorization'):
  return Finding('malicious','days_unauth_admin_account_creation','无Cookie或Authorization的创建用户请求明确指定usertype=2及完整用户名与一致确认密码，匹配DAYS公开管理用户创建漏洞结构；标利用尝试，不认定创建成功','POST|/authctrl/add_user|usertype2|account-and-matching-password-confirmation|no-session',DAYS_REF)
 links=(context or {}).get(digest(message),[])
 if p['method']=='GET' and links:
  evidence='GET|exact-written-JSP-path|same-source-host-timestamp|'+','.join(a+':'+b for a,b in links)
  return Finding('suspicious','same_transaction_jsp_write_verification','访问的随机JSP路径与另一条具有具体目录穿越文件写入结构的POST完全对应，源IP、实际Host、时间戳均一致；按写入结果验证探测处理，无响应不能认定执行成功',evidence,'local-supplied-records:exact-artifact-link-not-label-transfer')
 return None
