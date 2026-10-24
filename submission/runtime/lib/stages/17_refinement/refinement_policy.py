"""Evidence-based subtype refinement plus one restored default-token account creation."""
import re
from final_policy import Finding
from request_view import parse,parameters
from jwt_codec import verify_folded_default
TEAMCITY='https://www.rapid7.com/blog/post/ra-cve-2024-27199-analysis/'
HONGJING='https://github.com/Huu1j/crawl_xz/blob/dfec80ab4a719e93a4eef205967c5aa8233badd3/butian/2929-记某景的一次代码审计.md'
NACOS='https://github.com/projectdiscovery/nuclei-templates/blob/17f5725dc10ced09f464dd2d255c19957aad51e7/http/misconfiguration/nacos/nacos-create-user.yaml'
ARCADYAN='https://www.tenable.com/security/research/tra-2021-13'
def assess(message):
 p=parse(message)
 if not p:return None
 route,_,query=p['target'].partition('?');route=route.casefold();q=parameters(query);h=p['headers'];no_session=not h.get('cookie') and not h.get('authorization')
 if q is None:return None
 if p['method']=='GET' and no_session and not query and route=='/res/../admin/diagnostic.jsp':
  return Finding('malicious','teamcity_explicit_public_path_admin_auth_bypass','公开资源前缀/res/与目录回退共同定向管理员诊断JSP，完整匹配CVE-2024-27199鉴权绕过构造；按利用尝试判恶意，不要求或声称响应成功',route+'|GET|public-path-to-protected-admin|no-session',TEAMCITY)
 if p['method']=='GET' and no_session and not query and route=='/w_selfservice/oauthservlet/../../system/options/customreport/officeserver.jsp':
  return Finding('malicious','hongjing_whitelist_namespace_admin_auth_bypass','以公开审计确认的oauthservlet鉴权白名单前缀配合两级目录回退访问管理OfficeServer JSP，具备具体过滤器规避结构；按绕过尝试判恶意，不认定文件上传或执行成功',route+'|GET|whitelist-prefix-two-parent-traversal|protected-OfficeServer|no-session',HONGJING)
 if p['method']=='POST' and no_session and route=='/nacos/v1/auth/users/' and set(q)=={'username','password','accesstoken'} and q['username'] and q['password']:
  v=verify_folded_default(q['accesstoken'])
  if v and v['subject']=='nacos' and v['grammar_candidate_count']==1 and (v['expiry']<1700000000 or v['expiry']>4000000000):
   return Finding('malicious','nacos_default_key_folded_jwt_user_creation','创建用户请求同时携带固定sub/exp格式下唯一可恢复的Nacos令牌候选，完整签名折叠指纹与公开默认密钥计算结果一致且过期时间异常；支持默认密钥身份伪造利用尝试，非任意JWT无损解码或登录成功证明','POST|/nacos/v1/auth/users/|create-account-fields|restored-sub=nacos|expiry='+str(v['expiry'])+'|unique-fixed-grammar-candidate|full-folded-HS256-public-default-key-match',NACOS)
 if p['method']=='GET' and no_session and not query and route=='/images/../info.html':
  return Finding('suspicious','arcadyan_unencoded_info_path_probe','此路径与Arcadyan/Buffalo图像目录回退探测相关，旧TeamCity归属错误；本地未保留公开利用中关键的编码分隔符且无响应，维持可疑，不升级为已确认鉴权绕过',route+'|GET|unencoded-parent-info-page|no-response|attribution-corrected',ARCADYAN)
 return None
