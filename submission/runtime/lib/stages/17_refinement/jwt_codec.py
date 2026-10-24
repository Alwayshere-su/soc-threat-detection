"""Constrained folded JWT fingerprint reconstruction; not lossless generic decoding.

Only compact {sub:nacos|admin,exp:9..13 decimal digits} payloads and the known
HS256 header are considered. The public Nacos demo secret is decoded with the
upstream historical tolerant Base64 behavior. No private-key search or network.
"""
import base64,hashlib,hmac,itertools,json,math,re
DEFAULT='SecretKey012345678901234567890123456789012345678901234567890123456789'
PUBLIC='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g'
PUBLIC_KEY=base64.b64decode(DEFAULT[:-1])
def b64(s):return base64.urlsafe_b64decode(s+'='*((-len(s))%4))
def b64s(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
HEADER=b64s(b'{"alg":"HS256"}')
def restore(encoded,prefix):
 if not re.fullmatch(r'[A-Za-z0-9_-]+',encoded) or len(encoded)%4==1:return []
 n=len(b64(encoded));digits=n-len(prefix)-1
 if digits not in range(9,14):return []
 allowed=[{ord(c)} for c in prefix]+[set(range(48,58)) for _ in range(digits)]+[{125}];blocks=[]
 for start in range(0,len(encoded),4):
  block=encoded[start:start+4];choices=[tuple(set([c.lower(),c.upper()])) if c.isalpha() else (c,) for c in block];feasible=set();offset=start//4*3
  for v in itertools.product(*choices):
   try:part=b64(''.join(v))
   except ValueError:continue
   if all(offset+i<len(allowed) and ch in allowed[offset+i] for i,ch in enumerate(part)):feasible.add(part)
  if not feasible or len(feasible)>4:return []
  blocks.append(sorted(feasible))
 if math.prod(len(x) for x in blocks)>100:return []
 return [b''.join(parts) for parts in itertools.product(*blocks) if len(b''.join(parts))==n and b64s(b''.join(parts)).casefold()==encoded.casefold()]
def verify_folded_default(token):
 parts=token.split('.')
 if len(parts)!=3 or parts[0].casefold()!=HEADER.casefold():return None
 if not re.fullmatch(r'[A-Za-z0-9_-]{43}',parts[2]):return None
 matches=[];candidate_count=0
 for user in ['nacos','admin']:
  for body in restore(parts[1],'{"sub":"'+user+'","exp":'):
   candidate_count+=1;sig=b64s(hmac.new(PUBLIC_KEY,(HEADER+'.'+b64s(body)).encode(),hashlib.sha256).digest())
   if hmac.compare_digest(sig.casefold(),parts[2].casefold()):matches.append(json.loads(body))
 if len(matches)!=1:return None
 return dict(subject=matches[0]['sub'],expiry=matches[0]['exp'],grammar_candidate_count=candidate_count,full_folded_signature_match=True)
def self_check():
 p=PUBLIC.split('.');assert hmac.compare_digest(b64s(hmac.new(PUBLIC_KEY,(p[0]+'.'+p[1]).encode(),hashlib.sha256).digest()),p[2])
 for token in [PUBLIC,PUBLIC.casefold()]:
  found=verify_folded_default(token);assert found and found['subject']=='nacos' and found['expiry']==99999999999
 assert verify_folded_default(PUBLIC[:-1]+('a' if PUBLIC[-1]!='a' else 'b')) is None
 return True
