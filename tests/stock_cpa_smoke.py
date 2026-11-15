"""Opt-in Docker test against pinned stock CPA; only synthetic credentials.
Requires a built dist/cpa-relay.so, Docker, and OpenSSL. No production access.
Private fixture/log files remain at the printed path for inspection.
"""
import base64,datetime,json,os,pathlib,secrets,subprocess,time,urllib.request,urllib.error,ssl,tempfile,ipaddress
root=pathlib.Path(tempfile.mkdtemp(prefix='cpa-relay-stock-'))
repo=pathlib.Path(__file__).resolve().parents[1]
name='cpa-relay-test-'+secrets.token_hex(4)
addresses={}
print('Private synthetic fixture/logs:',root,flush=True)
os.umask(0o077)
image='eceasy/cli-proxy-api:v8.0.63@sha256:8377845ba3ec132c3bc41765d348e693703dc88e232d37f7a7eafc2721bff553'
def run(*args):return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout
for role in ('exporter','receiver'):
 for sub in ('auth','state','plugins'):(root/role/sub).mkdir(parents=True,mode=0o700)
 (root/role/'plugins/cpa-relay.so').write_bytes((repo/'dist/cpa-relay.so').read_bytes())
secret=secrets.token_urlsafe(32);admin=secrets.token_urlsafe(32);api=secrets.token_urlsafe(32)
(root/'env').write_text('CPA_RELAY_BEARER='+secret+'\nSSL_CERT_FILE=/fixture/cert.pem\n')
run('docker','network','create','--internal',name)
subnet=json.loads(run('docker','network','inspect',name))[0]['IPAM']['Config'][0]['Subnet']
network=ipaddress.ip_network(subnet)
addresses={'exporter':str(network[2]),'receiver':str(network[3])}
run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-days','1','-subj','/CN='+name+'-exporter','-addext','subjectAltName=DNS:'+name+'-exporter,IP:'+addresses['exporter'])
for role in ('exporter','receiver'):
 for asset in ('cert.pem','key.pem'):(root/role/asset).write_bytes((root/asset).read_bytes())
 cfg={'config-version':8,'server':{'host':'0.0.0.0','port':8317,'commercial-mode':True},'management':{'allow-remote':True,'secret-key':admin,'disable-control-panel':True},'access':{'api-keys':[api]},'oauth':{'auth-dir':'/fixture/auth'},'observability':{'logs':{'request-log':False}},'plugins':{'enabled':True,'dir':'/fixture/plugins','configs':{'cpa-relay':{'enabled':True,'priority':100,'role':role,'secret_env':'CPA_RELAY_BEARER','accounts':['acct-test'],'state_dir':'/fixture/state'}}}}
 if role=='exporter':cfg['server']['tls']={'enable':True,'cert':'/fixture/cert.pem','key':'/fixture/key.pem'}
 else:cfg['plugins']['configs']['cpa-relay'].update({'auth_dir':'/fixture/auth','receiver_id':'test','endpoint':'https://'+name+'-exporter:8317/v0/resource/plugins/cpa-relay/snapshot','poll_seconds':1,'max_stale_seconds':10,'expiry_skew_seconds':5})
 (root/role/'config.json').write_text(json.dumps(cfg))
def credential(generation):
 exp=int(time.time())+3600
 payload=base64.urlsafe_b64encode(json.dumps({'exp':exp,'generation':generation}).encode()).decode().rstrip('=')
 return {'type':'codex','access_token':'e30.'+payload+'.fake','account_id':'acct-test','email':'test@example.invalid','expired':datetime.datetime.fromtimestamp(exp,datetime.timezone.utc).isoformat(),'last_refresh':datetime.datetime.now(datetime.timezone.utc).isoformat(),'refresh_token':'REFRESH_CANARY_NEVER_EXPORT','id_token':'ID_CANARY_NEVER_EXPORT','disabled':False}
source=root/'exporter/auth/source.json';source.write_text(json.dumps(credential(1)))
context=ssl.create_default_context(cafile=str(root/'cert.pem'))
def call(role,path,key=None):
 url=('https' if role=='exporter' else 'http')+'://'+addresses[role]+':8317'+path
 req=urllib.request.Request(url,headers={'Authorization':'Bearer '+key} if key else {})
 try:
  with urllib.request.urlopen(req,context=context,timeout=4) as r:return r.status,json.load(r)
 except urllib.error.HTTPError as e:return e.code,json.loads(e.read())
def wait(predicate,label):
 end=time.monotonic()+30
 while time.monotonic()<end:
  try:
   if predicate():print('PASS:',label,flush=True);return
  except (OSError,ValueError):pass
  time.sleep(.5)
 raise RuntimeError(label)
try:
 for i,role in enumerate(('exporter','receiver')):
  run('docker','run','-d','--name',name+'-'+role,'--network',name,'--env-file',str(root/'env'),'-v',str(root/role)+':/fixture',image,'./CLIProxyAPI','-config','/fixture/config.json')
  actual=json.loads(run('docker','inspect',name+'-'+role))[0]['NetworkSettings']['Networks'][name]['IPAddress']
  assert actual==addresses[role], 'unexpected fixture IP allocation'
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==200,'actual CPA receiver ready after background host callbacks')
 code,snap=call('exporter','/v0/resource/plugins/cpa-relay/snapshot',secret)
 assert code==200 and 'REFRESH_CANARY' not in json.dumps(snap) and 'ID_CANARY' not in json.dumps(snap)
 assert call('exporter','/v0/resource/plugins/cpa-relay/snapshot')[0]==401
 print('PASS: exporter authentication and projection')
 files=list((root/'receiver/auth').glob('cpa-relay-*.json'));assert len(files)==1
 assert 'refresh_token' not in json.loads(files[0].read_text())
 code,listing=call('receiver','/v0/management/auth-files',admin);assert code==200
 assert any(f.get('name')==files[0].name and not f.get('disabled') for f in listing['files'])
 updated=credential(2);tmp=source.with_suffix('.tmp');tmp.write_text(json.dumps(updated));tmp.replace(source)
 wait(lambda:json.loads(files[0].read_text())['access_token']==updated['access_token'],'new access token replaced in same file')
 source.unlink()
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==503 and not files[0].exists(),'authoritative removal closes readiness and removes file')
 wait(lambda:not any(f.get('name')==files[0].name for f in call('receiver','/v0/management/auth-files',admin)[1]['files']),'removed credential absent from actual CPA runtime')
 for role in ('exporter','receiver'):
  logs=run('docker','logs',name+'-'+role)
  assert 'REFRESH_CANARY' not in logs and 'ID_CANARY' not in logs
 print('PASS: basic container stdout canary check (not exhaustive log audit)')
 print('ALL REAL CPA TESTS PASSED; no real credentials or upstream inference used')
finally:
 for role in ('receiver','exporter'):
  subprocess.run(['docker','logs',name+'-'+role],stdout=open(root/(role+'.log'),'w'),stderr=subprocess.STDOUT)
  subprocess.run(['docker','rm','-f',name+'-'+role],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 subprocess.run(['docker','network','rm',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
