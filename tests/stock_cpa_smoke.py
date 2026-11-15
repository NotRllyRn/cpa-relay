"""Opt-in Docker test against pinned stock CPA; only synthetic credentials.
Requires a built dist/cpa-relay.so, Docker, and OpenSSL. No production access.
Private fixture/log files remain at the printed path for inspection.
"""
import base64,datetime,json,os,pathlib,secrets,subprocess,time,urllib.request,urllib.error,urllib.parse,ssl,tempfile,ipaddress
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
 cfg={'config-version':8,'server':{'host':'0.0.0.0','port':8317,'commercial-mode':True},'management':{'allow-remote':True,'secret-key':admin,'disable-control-panel':True},'access':{'api-keys':[api]},'oauth':{'auth-dir':'/fixture/auth'},'observability':{'logs':{'request-log':False}},'plugins':{'enabled':True,'dir':'/fixture/plugins','configs':{'cpa-relay':{'enabled':True,'priority':100,'role':role,'secret_env':'CPA_RELAY_BEARER','state_dir':'/fixture/state'}}}}
 if role=='exporter':
  cfg['server']['tls']={'enable':True,'cert':'/fixture/cert.pem','key':'/fixture/key.pem'}
 else:cfg['plugins']['configs']['cpa-relay'].update({'enabled':False,'auth_dir':'/fixture/auth','receiver_id':'test','endpoint':'https://'+name+'-exporter:8317/v0/resource/plugins/cpa-relay/snapshot','poll_seconds':1,'max_stale_seconds':30,'expiry_skew_seconds':5})
 (root/role/'config.json').write_text(json.dumps(cfg))
def credential(generation):
 exp=int(time.time())+3600
 payload=base64.urlsafe_b64encode(json.dumps({'exp':exp,'generation':generation}).encode()).decode().rstrip('=')
 return {'type':'codex','access_token':'e30.'+payload+'.fake','account_id':'acct-test','email':'test@example.invalid','expired':datetime.datetime.fromtimestamp(exp,datetime.timezone.utc).isoformat(),'last_refresh':datetime.datetime.now(datetime.timezone.utc).isoformat(),'refresh_token':'REFRESH_CANARY_NEVER_EXPORT','id_token':'ID_CANARY_NEVER_EXPORT','disabled':False}
source=root/'exporter/auth/source.json';source.write_text(json.dumps(credential(1)))
other=credential(900);other['email']='other@example.invalid'
other_source=root/'exporter/auth/other.json';other_source.write_text(json.dumps(other))
def receiver_files():return list((root/'receiver/auth').glob('cpa-relay-*.json'))
def snapshot_count(count):
 code,snap=call('exporter','/v0/resource/plugins/cpa-relay/snapshot',secret)
 return code==200 and len(snap['accounts'])==count
def atomic_source(path,data):
 tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(data));tmp.replace(path)
context=ssl.create_default_context(cafile=str(root/'cert.pem'))
def call(role,path,key=None,method='GET',body=None):
 url=('https' if role=='exporter' else 'http')+'://'+addresses[role]+':8317'+path
 headers={'Authorization':'Bearer '+key} if key else {}
 data=None
 if body is not None:
  data=json.dumps(body).encode();headers['Content-Type']='application/json'
 req=urllib.request.Request(url,headers=headers,method=method,data=data)
 try:
  with urllib.request.urlopen(req,context=context,timeout=4) as r:return r.status,json.load(r)
 except urllib.error.HTTPError as e:
  raw=e.read()
  try:body=json.loads(raw)
  except ValueError:body={}
  return e.code,body
def wait(predicate,label):
 end=time.monotonic()+30
 while time.monotonic()<end:
  try:
   if predicate():print('PASS:',label,flush=True);return
  except (OSError,ValueError):pass
  time.sleep(.5)
 raise RuntimeError(label)
def assert_ready_models():
 # This samples readiness before checking both per-credential registration and
 # public model discovery. It does not make an upstream inference request.
 assert call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==200
 code,listing=call('receiver','/v0/management/auth-files',admin);assert code==200
 active=[f for f in listing['files'] if f.get('name','').startswith('cpa-relay-') and not f.get('disabled')]
 assert active
 code,discovery=call('receiver','/v1/models',api);assert code==200
 public={m['id'] for m in discovery['data']}
 for f in active:
  code,registration=call('receiver','/v0/management/auth-files/models?name='+urllib.parse.quote(f['name']),admin)
  assert code==200 and registration['models'], 'readiness without per-account model registration'
  assert any(m['id'] in public for m in registration['models']), 'registered account has no discoverable model'
 print('PASS: sampled readiness implies per-account model registration and model discovery (not inference)',flush=True)
try:
 for i,role in enumerate(('exporter','receiver')):
  run('docker','run','-d','--name',name+'-'+role,'--network',name,'--env-file',str(root/'env'),'-v',str(root/role)+':/fixture',image,'./CLIProxyAPI','-config','/fixture/config.json')
  actual=json.loads(run('docker','inspect',name+'-'+role))[0]['NetworkSettings']['Networks'][name]['IPAddress']
  assert actual==addresses[role], 'unexpected fixture IP allocation'
 # Let stock CPA finish its initial directory scan before materializing new
 # records; otherwise its initial load can race the callback model registration.
 wait(lambda:call('receiver','/v0/management/plugins',admin)[0]==200,'stock receiver management started')
 time.sleep(2)
 assert call('receiver','/v0/management/plugins/cpa-relay/enabled',admin,method='PATCH',body={'enabled':True})[0]==200
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==200,'actual CPA receiver ready after background save and model confirmation')
 assert_ready_models()
 code,snap=call('exporter','/v0/resource/plugins/cpa-relay/snapshot',secret)
 assert code==200 and 'REFRESH_CANARY' not in json.dumps(snap) and 'ID_CANARY' not in json.dumps(snap)
 assert snap['version']==2 and len(snap['accounts'])==2
 assert len({a['credential_id'] for a in snap['accounts']})==2
 assert len({a['account_id'] for a in snap['accounts']})==1
 assert all(value not in json.dumps(snap) for value in ('source.json','other.json','/fixture/auth/'))
 print('PASS: automatic discovery preserves two physical logins sharing a workspace without relaying filenames')
 assert call('exporter','/v0/resource/plugins/cpa-relay/snapshot')[0]==401
 print('PASS: exporter authentication and projection')
 files=receiver_files();assert len(files)==2
 assert all('refresh_token' not in json.loads(f.read_text()) for f in files)
 by_email={json.loads(f.read_text())['email']:f for f in files}
 primary=by_email['test@example.invalid'];secondary=by_email['other@example.invalid']
 unchanged={f:f.stat().st_mtime_ns for f in files};time.sleep(3)
 assert all(f.stat().st_mtime_ns==mtime for f,mtime in unchanged.items()), 'unchanged sync rewrote credential'
 print('PASS: repeated unchanged full snapshots do not rewrite credential files')
 original=source.read_bytes();source.write_text('{}')
 wait(lambda:call('exporter','/v0/resource/plugins/cpa-relay/snapshot',secret)[0]==503,'malformed physical read rejects entire export')
 cached=json.loads((root/'receiver/state/state.json').read_text())['snapshot']['generated_at']
 time.sleep(3)
 assert all(f.exists() for f in files), 'failed export deleted fresh receiver credentials'
 assert json.loads((root/'receiver/state/state.json').read_text())['snapshot']['generated_at']==cached, 'failed fetch extended generation'
 source.write_bytes(original)
 wait(lambda:snapshot_count(2),'valid source restored')
 updated=credential(2);atomic_source(source,updated)
 wait(lambda:json.loads(primary.read_text())['access_token']==updated['access_token'],'new access token replaced correct same-workspace file')
 assert secondary.stat().st_mtime_ns==unchanged[secondary], 'refresh rewrote another same-workspace login'
 third=source.with_name('new.json');third_data=credential(500);third_data['email']='new@example.invalid';atomic_source(third,third_data)
 wait(lambda:len(receiver_files())==3,'new same-workspace credential discovered on next sync')
 other_source.unlink()
 wait(lambda:len(receiver_files())==2 and not secondary.exists(),'source deletion removes only its relay record')
 source.unlink();third.unlink()
 wait(lambda:snapshot_count(0) and not receiver_files() and call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==503,'valid empty inventory disables and deletes all owned records')
 assert json.loads((root/'receiver/state/state.json').read_text())['managed']==[]
 atomic_source(source,updated)
 wait(lambda:len(receiver_files())==1 and primary.exists(),'new discovery after delete-all')
 files=[primary]
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==200,'updated credential ready with registered models')
 assert_ready_models()
 assert call('receiver','/v0/management/cpa-relay/drain',method='POST')[0]==401
 code,drained=call('receiver','/v0/management/cpa-relay/drain',admin,method='POST')
 assert code==200 and drained.get('state')=='drained'
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==503 and not files[0].exists(),'authenticated drain closes admission and removes owned file')
 code,listing=call('receiver','/v0/management/auth-files',admin);assert code==200
 assert all(f.get('disabled') for f in listing['files'] if f.get('name')==files[0].name), 'drain left enabled runtime credential'
 assert json.loads((root/'receiver/state/state.json').read_text())['managed']==[]
 assert call('receiver','/v0/management/plugins/cpa-relay/enabled',admin,method='PATCH',body={'enabled':False})[0]==200
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]!=200 and not next(p for p in call('receiver','/v0/management/plugins',admin)[1]['plugins'] if p['id']=='cpa-relay')['enabled'],'stock CPA disable after drain')
 assert call('receiver','/v0/management/plugins/cpa-relay/enabled',admin,method='PATCH',body={'enabled':True})[0]==200
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==200,'stock CPA re-enable requires newer live snapshot')
 assert_ready_models()
 disabled=credential(3);disabled['disabled']=True;source.write_text(json.dumps(disabled))
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==503 and not files[0].exists(),'authoritative disabled-source omission closes readiness and removes managed file')
 wait(lambda:not any(f.get('name')==files[0].name for f in call('receiver','/v0/management/auth-files',admin)[1]['files']),'removed credential absent from actual CPA runtime')
 # Negative case: stock disable closes callback context before native shutdown.
 # Do NOT infer acknowledged withdrawal from an eventual watcher update.
 source.write_text(json.dumps(credential(4)))
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]==200,'active fixture restored for abrupt-disable test')
 assert_ready_models()
 assert call('receiver','/v0/management/plugins/cpa-relay/enabled',admin,method='PATCH',body={'enabled':False})[0]==200
 wait(lambda:call('receiver','/v0/resource/plugins/cpa-relay/ready')[0]!=200 and not next(p for p in call('receiver','/v0/management/plugins',admin)[1]['plugins'] if p['id']=='cpa-relay')['enabled'],'abrupt stock disable loses readiness; ingress must deny')
 assert json.loads((root/'receiver/state/state.json').read_text())['managed'], 'abrupt disable unexpectedly acknowledged cleanup'
 assert files[0].exists(), 'abrupt disable incorrectly reported physical cleanup'
 print('PASS: stock abrupt disable retains unacknowledged cleanup; no plugin-only shutdown guarantee')
 # Leading basename whitespace is a distinct, valid physical identity. Stock
 # trims Name, not the raw middle-of-path space. No filename pin exists now.
 source.unlink()
 alias=source.with_name(' source.json');alias_data=credential(901);alias_data['email']='alias@example.invalid';alias.write_text(json.dumps(alias_data))
 run('docker','restart',name+'-exporter')
 wait(lambda:any(f.get('path')=='/fixture/auth/ source.json' and f.get('name')=='source.json' for f in call('exporter','/v0/management/auth-files',admin)[1]['files']),'stock host observes leading-space physical identity under trimmed Name')
 code,renamed=call('exporter','/v0/resource/plugins/cpa-relay/snapshot',secret)
 assert code==200 and len(renamed['accounts'])==1
 original_id=next(a['credential_id'] for a in snap['accounts'] if a['email']=='test@example.invalid')
 assert renamed['accounts'][0]['credential_id']!=original_id
 assert '/fixture/auth/' not in json.dumps(renamed) and 'source.json' not in json.dumps(renamed)
 print('PASS: physical rename is opaque delete-and-add, not a trimmed-name identity alias')
 for role in ('exporter','receiver'):
  logs=run('docker','logs',name+'-'+role)
  assert 'REFRESH_CANARY' not in logs and 'ID_CANARY' not in logs
 print('PASS: basic container stdout canary check (not exhaustive log audit)')
 print('ALL REAL CPA TESTS PASSED; no real credentials or upstream inference used')
except Exception:
 # Only coarse diagnostics: never print tokens, account IDs, config or bodies.
 try:
  _,sources=call('exporter','/v0/management/auth-files',admin)
  print('Source diagnostics:',[{k:entry.get(k) for k in ('type','provider','runtime_only','disabled')} for entry in sources.get('files',[])],flush=True)
  code,status=call('receiver','/v0/management/cpa-relay/status',admin)
  print('Receiver diagnostic:',code,{k:status.get(k) for k in ('ready','state','last_attempt')},flush=True)
  _,listing=call('receiver','/v0/management/auth-files',admin)
  for entry in listing.get('files',[]):
   _,registered=call('receiver','/v0/management/auth-files/models?name='+urllib.parse.quote(entry.get('name','')),admin)
   print('Runtime diagnostic:',{k:entry.get(k) for k in ('status','unavailable','disabled','runtime_only','provider')},'models:',len(registered.get('models',[])),flush=True)
 except (OSError,ValueError):pass
 raise
finally:
 for role in ('receiver','exporter'):
  subprocess.run(['docker','logs',name+'-'+role],stdout=open(root/(role+'.log'),'w'),stderr=subprocess.STDOUT)
  subprocess.run(['docker','rm','-f',name+'-'+role],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 subprocess.run(['docker','network','rm',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
