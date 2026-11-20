import socket,struct,threading,subprocess,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=str(ROOT/'target/debug/wheredns'); OUT=[]
def enc(n): return b''.join(bytes([len(s)])+s.encode() for s in n.rstrip('.').split('.'))+b'\0'
def rr(n,t,data,cls=1): return enc(n)+struct.pack('!HHIH',t,cls,60,len(data))+data
def question(q):
 p=12; labels=[]
 while q[p]:
  n=q[p];labels.append(q[p+1:p+1+n].decode());p+=n+1
 p+=1;return '.'.join(labels),struct.unpack('!H',q[p:p+2])[0],q[12:p+4]
class DNS:
 def __init__(self,fn,addr=('127.0.0.1',0)):
  self.s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.s.bind(addr);self.s.settimeout(3);self.addr=self.s.getsockname();self.fn=fn;self.seen=[];threading.Thread(target=self.serve,daemon=True).start()
 def serve(self):
  try:
   while True:
    q,p=self.s.recvfrom(65535);n,t,qtail=question(q);self.seen.append([n,t]);code,rs=self.fn(n,t);r=q[:2]+struct.pack('!HHHHH',0x8180|code,1,len(rs),0,0)+qtail+b''.join(rs);self.s.sendto(r,p)
  except socket.timeout: pass
 def args(self): return ['--resolver',f'{self.addr[0]}:{self.addr[1]}','--allow-private','--json','--timeout','1']
def run(label,args,expected=None,data=None):
 p=subprocess.run([BIN]+args,input=data,capture_output=True,timeout=8);row=dict(case=label,exit=p.returncode,stdout=p.stdout.decode(errors='replace'),stderr=p.stderr.decode(errors='replace'));OUT.append(row);print(json.dumps(row));
 if expected is not None: assert p.returncode==expected,row
 return row

failures=[]
for typ, family, address in [(1,socket.AF_INET,'127.0.0.1'),(28,socket.AF_INET6,'::1')]:
 for mode in ['positive','cname','nxdomain','negative-alias','servfail','refused','class3','class4','alias3','alias4','terminal3','terminal4','contradictory','mixed-valid']:
  h=socket.socket(family);h.bind((address,0));h.listen();h.settimeout(.15);hits=[]
  def sink():
   try:
    c,_=h.accept();hits.append(c.recv(4096));c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');c.close()
   except socket.timeout:pass
  th=threading.Thread(target=sink);th.start()
  def reply(n,t,m=mode,ty=typ):
   if t!=ty:return 0,[]
   wire=socket.inet_pton(family,address)
   if m in ['cname','negative-alias','alias3','alias4','terminal3','terminal4','contradictory']:
    records=[rr(n,5,enc('alias.test'),int(m[-1]) if m.startswith('alias') else 1),rr('alias.test',ty,wire,int(m[-1]) if m.startswith('terminal') else 1)]
   else:records=[rr(n,ty,wire,int(m[-1]) if m.startswith('class') else 1)]
   if m=='contradictory':records.append(rr(n,ty,wire))
   if m=='mixed-valid':records.extend([rr(n,ty,wire,3),rr(n,ty,wire,4)])
   return (3 if m in ['nxdomain','negative-alias'] else 2 if m=='servfail' else 5 if m=='refused' else 0),records
  dns=DNS(reply)
  row=run(f'{typ} {mode}',[f'http://example.test:{h.getsockname()[1]}/','web']+dns.args())
  th.join();h.close()
  positive=mode in ['positive','cname','mixed-valid']
  if row['exit']!=(0 if positive else 1) or bool(hits)!=positive:failures.append(row['case'])
for code in [0,3]:
 dns=DNS(lambda n,t,c=code:(c,[]));run('negative evidence',['example.test','dns','A','AAAA']+dns.args(),0)
assert not failures,failures
print(f'{len(OUT)} eligibility regressions passed')
