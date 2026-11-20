import socket,struct,threading,subprocess,json,os,pathlib,time,signal
import tempfile
BIN=str(pathlib.Path(__file__).resolve().parents[1]/'target/debug/wheredns')
OUT=[]
def run(label,args,data=None,env=None):
 p=subprocess.run([BIN]+args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=8)
 row={'case':label,'exit':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')};OUT.append(row);print(json.dumps(row));return row
class DNS:
 def __init__(self,mode):
  self.mode=mode;self.u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.u.bind(('127.0.0.1',0));self.port=self.u.getsockname()[1];self.u.settimeout(3);self.t=socket.socket();self.t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);self.t.bind(('127.0.0.1',self.port));self.t.listen();self.t.settimeout(3);self.queries=[];threading.Thread(target=self.serve,daemon=True).start()
 def response(self,q,tcp=False):
  typ=struct.unpack('!H',q[-4:-2])[0];self.queries.append(typ)
  if self.mode in ('servfail','refused'):return q[:2]+struct.pack('!HHHHH',(0x8185 if self.mode=='refused' else 0x8182),1,0,0,0)+q[12:]
  if self.mode=='tc':return q[:2]+struct.pack('!HHHHH',0x8380,1,0,0,0)+q[12:]
  if self.mode=='ptrfail' and typ==12:return b'bad'
  if typ==1:
   owner=b'\x09unrelated\x04test\x00' if self.mode=='unrelated' else b'\xc0\x0c'
   rr=owner+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('127.0.0.1')
   return q[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+q[12:]+rr
  return q[:2]+struct.pack('!HHHHH',0x8180,1,0,0,0)+q[12:]
 def serve(self):
  try:
   while True:
    q,p=self.u.recvfrom(65535);self.u.sendto(self.response(q),p)
    if self.mode=='tc':
     c,_=self.t.accept();n=struct.unpack('!H',c.recv(2))[0];q=c.recv(n);r=self.response(q,True);c.sendall(struct.pack('!H',len(r))+r);c.close()
  except (TimeoutError,OSError):pass
 def args(self):return ['--resolver',f'127.0.0.1:{self.port}','--allow-private','--json','--timeout','1']
s=DNS('refused');run('DNS REFUSED',['example.test','dns','A']+s.args())
s=DNS('servfail');run('Propagation lookup failure',['example.test','prop']+s.args())
s=DNS('servfail');run('DNS SERVFAIL',['example.test','dns','A']+s.args())
s=DNS('tc');run('TCP response still truncated',['example.test','dns','A']+s.args())
s=DNS('ptrfail');run('PTR malformed response',['127.0.0.1','ip']+s.args())
# Local HTTP server with fixture-only traffic, unrelated A RR should not become connection destination.
h=socket.socket();h.bind(('127.0.0.1',0));h.listen();h.settimeout(3);hp=h.getsockname()[1];hits=[]
def http():
 try:
  c,_=h.accept();hits.append(c.recv(4096).decode());c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');c.close()
 except (TimeoutError,OSError):pass
threading.Thread(target=http,daemon=True).start();s=DNS('unrelated');run('Unrelated DNS owner drives HTTP',[f'http://example.test:{hp}/','web']+s.args());print('UNRELATED_HTTP_HITS',json.dumps(hits))
# PATH-injected fixture is a local test executable, never an actual ping.
fixture_dir=tempfile.TemporaryDirectory();d=pathlib.Path(fixture_dir.name);ping=d/'ping';ping.write_text('#!/bin/sh\nprintf "fixture unreachable\\n"\nexit 1\n');ping.chmod(0o700);env=dict(os.environ,PATH=str(d)+':'+os.environ['PATH']);run('Ping exits nonzero',['127.0.0.1','ping','--allow-private','--json'],env=env)
run('Header invalid UTF8',['headers','--json'],b'Subject: good\n\xffinvalid')
run('Header initial empty separator',['headers','--json'],b'\nSubject: body-not-a-header\n')
run('Oversized whitespace headers',['headers','--json'],b' '*65537)

failures=[]
for row in OUT:
 expected=0 if row['case']=='Header initial empty separator' else (2 if row['case'].startswith(('Header invalid','Oversized')) else 1)
 if row['exit']!=expected: failures.append(row['case'])
 if row['case']=='Header initial empty separator' and json.loads(row['stdout'])['fields']: failures.append('body parsed as headers')
if hits: failures.append('unrelated address used')
assert not failures, failures
print(f'{len(OUT)} loopback regressions passed')
