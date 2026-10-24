"""Static CDG string decoding from public CodeDecoder behavior.

Only AES block operations and bytes. Never XML parsing, deserialization or execution.
For truncated inputs, decode complete blocks only; never treat a truncated remainder
as a genuine final XOR tail.
"""
import re
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

KEY=bytes(x%256 for x in [-21,-112,90,-68,5,44,85,-86,-21,-112,90,-68,5,44,85,-86])
REFERENCE='https://github.com/LuckyTain/Esafenet-analize/blob/5589894b5b5710ce659014a686fbadf22d3ba51f/src/CodeDecoder.java'

def unpack(text):
    if not text or len(text)%2 or not re.fullmatch(r'[A-Pa-p]+',text):raise ValueError('not an even-length CDG byte string')
    # A=1,...,O=15,P=0. Lowercasing preserves the low four bits.
    return bytes(((ord(text[i])&15)<<4)|(ord(text[i+1])&15) for i in range(0,len(text),2))

def decode(text,complete=True):
    data=unpack(text);n=len(data)//16*16
    dec=Cipher(algorithms.AES(KEY),modes.ECB()).decryptor()
    blocks=dec.update(data[:n])+dec.finalize()
    if complete:return blocks+bytes(v^i for i,v in enumerate(data[n:]))
    return blocks

def encode(data):
    n=len(data)//16*16;enc=Cipher(algorithms.AES(KEY),modes.ECB()).encryptor()
    result=enc.update(data[:n])+enc.finalize()+bytes(v^i for i,v in enumerate(data[n:]))
    return ''.join(chr(64+(v>>4 or 16))+chr(64+(v&15 or 16)) for v in result)

def self_check():
    for original,cipher in [(b'/frame.jsp','BOFGGPFBFIFPBHFMGKGi'),(b'systemadmin','GCGHGAGGFAFHFGFCFEFPFD')]:
        assert decode(cipher)==original and encode(original).casefold()==cipher.casefold()
    vector='AFMALANMJCEOENIBDJMKFHBANGEPKHNOFJBMIFJPFNKFOKHJNMLCOIDDJGNEIPOLOKGAFAFJHDEJPHEPLFJHDGPBNELNFIICGFNGEOEFBKCDDCGJEPIKFHJFAOOHJEPNNCLFHDAFDNCGBAEELJFFHABJPDPIEEMIBOECDMDLEPBJGBGCGLEMBDFAGOGM'
    expected=b'fileName=../../../Program Files (x86)/ESAFENET/CDocGuard Server/tomcat64/webapps/ROOT/tttT.jsp'
    assert decode(vector)==expected and encode(expected)==vector
    for i in [1,15,16,17,31,32,33,95]:
        data=bytes(range(i));assert decode(encode(data))==data
        assert decode(encode(data).lower())==data
    assert decode(vector[:70],complete=False)==expected[:32]
    return True
