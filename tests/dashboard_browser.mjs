// Disposable loopback integration fixture. Uses the built C ABI's actual HTML and headers.
// Run: PLAYWRIGHT_MODULE=/absolute/path/playwright/index.mjs node tests/dashboard_browser.mjs [dist/cpa-relay.so] [evidence-directory]
import {createServer} from 'node:http';
import {spawnSync} from 'node:child_process';
import {mkdir, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';
const root = path.dirname(fileURLToPath(import.meta.url));
const extraction = spawnSync('python3', [path.join(root, 'dashboard_payload.py'), process.argv[2] || 'dist/cpa-relay.so'], {encoding:'utf8'});
assert.equal(extraction.status, 0, extraction.stderr);
const shell = JSON.parse(extraction.stdout);
const html = Buffer.from(shell.Body, 'base64');
const output = path.resolve(process.argv[3] || '/tmp/cpa-relay-dashboard-evidence');
await mkdir(output, {recursive:true});
const pw = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const key = 'disposable-dashboard-test-key';
const statusPath = '/v0/management/cpa-relay/status', shellPath = '/v0/resource/plugins/cpa-relay/status';
const results = {timestamp:new Date().toISOString(),checks:[],failures:[],screenshots:[],errors:[]};
function check(name, condition, detail) { results.checks.push({name,passed:!!condition,detail}); if(!condition) results.failures.push(name); }
function receiver(overrides={}) {
  const now=Date.now(), stamp = ms=>new Date(now+ms).toISOString();
  return {role:'receiver',ready:true,state:'ready',reason:'degraded',last_attempt:'ok',accounts:12,synchronized_accounts:12,available_accounts:10,
    generated_at:stamp(-60000),fresh_until:stamp(3600000),snapshot_age_seconds:60,
    model_check_started_at:stamp(-50),model_check_completed_at:stamp(-10),model_check_duration_ms:40,model_check_valid_until:stamp(2950),last_sync_at:stamp(-30000), ...overrides};
}
let mode='ready', override=null, delay=0, requests=[];
const sockets = new Set();
const server = createServer((req,res)=>{
  const url = new URL(req.url,'http://127.0.0.1');
  if (url.pathname===shellPath) {
    for (const [name,values] of Object.entries(shell.Headers)) res.setHeader(name,values);
    res.writeHead(shell.StatusCode); res.end(html); return;
  }
  if (url.pathname==='/embed') {res.setHeader('Content-Type','text/html');res.end(`<!doctype html><html lang="en"><title>Same origin fixture</title><body><iframe title="Relay" src="${shellPath}" width="728" height="1500"></iframe></body></html>`);return;}
  if (url.pathname==='/redirect-target') {requests.push({redirectTarget:true});res.end('{}');return;}
  if (url.pathname!==statusPath) {res.writeHead(404);res.end();return;}
  const currentMode=mode, currentOverride=override, currentDelay=delay;
  requests.push({method:req.method,authorization:req.headers.authorization===`Bearer ${key}`,hasCookie:!!req.headers.cookie,hasReferer:!!req.headers.referer,cache:req.headers['cache-control'],mode:currentMode});
  const send = ()=>{
    if (currentMode==='auth401'||currentMode==='auth403') {res.writeHead(currentMode==='auth401'?401:403,{'Content-Type':'application/json'});res.end('{"error":"SENSITIVE_ERROR_BODY"}');return;}
    if (currentMode==='redirect') {res.writeHead(302,{Location:'/redirect-target'});res.end();return;}
    if (currentMode==='http') {res.writeHead(503,{'Content-Type':'application/json'});res.end('{"error":"SENSITIVE_ERROR_BODY"}');return;}
    res.writeHead(200,{'Content-Type':currentMode==='wrongtype'?'text/html':'application/json'});
    if(currentMode==='malformed') res.end('{"SENSITIVE_ERROR_BODY":');
    else if(currentMode==='oversized') res.end(' '.repeat(17000));
    else if(currentMode==='stream') {res.write('{');const id=setInterval(()=>{if(res.destroyed){clearInterval(id);return;}res.write(' '.repeat(4096));},10);}
    else res.end(JSON.stringify(currentOverride || receiver()));
  };
  if(currentDelay) setTimeout(send,currentDelay).unref(); else send();
});
server.on('connection', socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin='http://127.0.0.1:'+server.address().port;
const browser = await pw.chromium.launch({executablePath:process.env.CHROMIUM || '/usr/bin/chromium',args:['--no-sandbox']});
results.browser=browser.version();
let context, page;
const outgoing=[];
async function newPage(init) {
  if(context) await context.close();
  context = await browser.newContext({viewport:{width:1200,height:900},reducedMotion:'reduce'});
  context.on('request',r=>outgoing.push(r.url()));
  await context.addCookies([{name:'fixture-cookie',value:'must-not-send',url:origin}]);
  await context.addInitScript(()=>{
    window.storageWrites=0;const save=Storage.prototype.setItem;Storage.prototype.setItem=function(...args){window.storageWrites++;return save.apply(this,args);};
    window.violations=[];document.addEventListener('securitypolicyviolation',e=>window.violations.push(e.violatedDirective));
    const nativeFetch=window.fetch;
    window.fetch = function(url,options){window.lastFetchOptions={...options,headers:undefined,signal:!!options.signal};return nativeFetch.call(this,url,options);};
    window.announcements=[];
    document.addEventListener('DOMContentLoaded',()=>{if(!document.getElementById('announcement'))return;new MutationObserver(()=>window.announcements.push(document.getElementById('announcement').textContent)).observe(document.getElementById('announcement'),{childList:true,subtree:true,characterData:true});});
  });
  if(init) await context.addInitScript(init);
  page=await context.newPage();
  page.on('pageerror',e=>results.errors.push(String(e)));
  await page.goto(origin+shellPath);
}
async function login(){await page.getByLabel('CPA management key',{exact:true}).fill(key);await page.getByRole('button',{name:'Connect status',exact:true}).click();}
async function settled(){await page.waitForFunction(()=>document.getElementById('refresh').getAttribute('aria-disabled')==='false');}
async function ready(){await page.waitForFunction(()=>document.getElementById('readiness-title').textContent==='Ready at last check · reduced pool');await settled();}
async function refresh(){await page.getByRole('button',{name:'Refresh status',exact:true}).click();await settled();}
async function shot(name){await page.screenshot({path:path.join(output,name),fullPage:true});results.screenshots.push(name);}
async function cleared(label){check(label,await page.evaluate(()=>[...document.querySelectorAll('[data-value]')].every(e=>e.textContent==='') && document.getElementById('management-key').value==='' && document.getElementById('signed-in').hidden));}
try {
  await newPage();
  await page.waitForTimeout(1200);
  check('no protected request before explicit login',requests.length===0);
  check('actual ABI headers reach HTTP',(await page.request.get(origin+shellPath)).headers()['content-security-policy']===shell.Headers['Content-Security-Policy'][0]);
  await shot('login-desktop.png');
  await page.keyboard.press('Tab'); check('skip link first keyboard stop',await page.locator('.skip').evaluate(e=>e===document.activeElement));
  await login();await ready();
  check('password immediately cleared',await page.locator('#management-key').inputValue()==='');
  check('authenticated fixed read, no ambient cookies/referrer',requests.length===1&&requests[0].authorization&&!requests[0].hasCookie&&!requests[0].hasReferer&&requests[0].method==='GET');
  const options=await page.evaluate(()=>window.lastFetchOptions);
  check('secure fetch options',options.mode==='same-origin'&&options.credentials==='omit'&&options.cache==='no-store'&&options.redirect==='error'&&options.referrerPolicy==='no-referrer'&&options.signal);
  check('dynamic 12/10 prose',(await page.locator('#reason').innerText()).includes('10 of 12')&&(await page.locator('#reason').innerText()).includes('2 did not qualify'));
  check('timings collapsed',!(await page.locator('#runtime-details').evaluate(e=>e.open)));
  await shot('desktop-light-reduced.png');
  const before=await page.locator('#readiness-title').innerText();
  await page.waitForTimeout(3400);
  check('steady ready heading across lease expiry',await page.locator('#readiness-title').innerText()===before);
  check('expired observation labels candidates historical',await page.locator('#available-label').innerText()==='Candidates at last check');
  check('expiry does not infer closure',!(await page.locator('#check-explanation').innerText()).includes('is closed'));
  await page.waitForTimeout(2200); await settled();
  check('steady reduced qualifier after renewal',await page.locator('#readiness-title').innerText()===before);
  await page.evaluate(()=>window.announcements=[]);await page.waitForTimeout(11000);
  check('unchanged automatic success announcements quiet',await page.evaluate(()=>window.announcements.length===0));
  await page.getByLabel('Theme',{exact:true}).selectOption('dark');await shot('desktop-dark-reduced.png');
  await page.getByRole('button',{name:'Pause updates',exact:true}).click();const pausedRequests=requests.length;await page.waitForTimeout(5500);
  check('pause prevents automatic reads',requests.length===pausedRequests);
  await refresh(); check('manual refresh preserves focus',await page.locator('#refresh').evaluate(e=>e===document.activeElement));
  override=receiver({ready:false,state:'unready',reason:'models_pending',available_accounts:0});await refresh();
  check('pending preserves synchronized inventory',await page.locator('#synchronized').innerText()==='12'&&(await page.locator('#reason').innerText()).includes('12 accounts'));
  override=receiver({last_attempt:'fetch_failed',last_error:'fetch_failed',last_error_at:new Date(Date.now()-10000).toISOString()});await refresh();
  check('ready does not invent fetch recovery',(await page.locator('#last-error').innerText()).includes('fetch_failed')&&!(await page.locator('#last-error').innerText()).includes('recovered'));
  await page.locator('#diagnostics').evaluate(e=>e.open=true);
  await page.getByRole('button',{name:'Disconnect',exact:true}).click();await cleared('disconnect clears all derived DOM');
  check('disconnect returns focus',await page.locator('#management-key').evaluate(e=>e===document.activeElement));
  // A single previous-generation response must not log out or overwrite a new session.
  await newPage(()=>{const native=window.fetch;window.fetch=(url,options)=>native(url,{...options,signal:undefined});});
  mode='auth401';delay=900;await login();await page.waitForTimeout(150);await page.getByRole('button',{name:'Disconnect',exact:true}).click();
  mode='ready';delay=0;override=null;await login();await ready();await page.waitForTimeout(1100);
  check('late 401 cannot disconnect reconnected session',await page.locator('#signed-in').isVisible());
  // Same test for a late successful body reviving data after disconnect.
  delay=700;override=receiver({accounts:9,synchronized_accounts:9,available_accounts:8});await page.getByRole('button',{name:'Refresh status',exact:true}).click();await page.waitForTimeout(100);await page.getByRole('button',{name:'Disconnect',exact:true}).click();await page.waitForTimeout(850);await cleared('late success cannot revive disconnected DOM');
  delay=0;override=null;await newPage();
  for(const auth of ['auth401','auth403']){
    mode='ready';await login();await ready();mode=auth;await refresh();await cleared(auth+' clears all private DOM');
    const count=requests.length;await page.waitForTimeout(5500);check(auth+' stops retries',requests.length===count);
    check(auth+' generic error excludes response body',!(await page.locator('body').innerText()).includes('SENSITIVE_ERROR_BODY'));
  }
  // One in-flight read, including double manual clicks.
  mode='ready';delay=1500;const loginObserved=new Promise(resolve=>server.once('request',resolve));await login();await loginObserved;
  const single=requests.length;await page.locator('#refresh').evaluate(e=>{e.click();e.click();});await ready();
  check('one in-flight request',requests.length===single,{before:single,after:requests.length,recent:requests.slice(-3)});delay=0;
  await page.getByRole('button',{name:'Pause updates',exact:true}).click();
  for(const invalidMode of ['malformed','oversized','stream','wrongtype','redirect','http']){
    mode=invalidMode;await refresh();check(invalidMode+' generic bounded failure',(await page.locator('#notice').innerText()).includes('could not be read'));
    check(invalidMode+' retains prior observation',await page.locator('#synchronized').innerText()==='12');
  }
  check('redirect target never contacted',!requests.some(r=>r.redirectTarget));
  for(const patch of [{ready:'true'},{accounts:-1},{accounts:129},{available_accounts:13},{model_check_duration_ms:-1},{generated_at:'2026-02-30T00:00:00Z'},{last_error:{raw:'SENSITIVE_ERROR_BODY'}},{reason:null}]){
    mode='ready';override=receiver(patch);await refresh();check('rejects malformed schema '+JSON.stringify(patch),(await page.locator('#notice').innerText()).includes('could not be read'));
  }
  // Unknown codes are never rendered from untrusted strings or treated as ready.
  override=receiver({reason:'<img src=x onerror=alert(1)>',state:'unknown-new-state',last_error:'SENSITIVE_ERROR_BODY'});await refresh();
  check('unknown reason safe readiness fallback',await page.locator('#readiness-title').innerText()==='Status unknown');
  check('untrusted strings excluded from DOM',!(await page.locator('body').innerText()).includes('SENSITIVE_ERROR_BODY')&&await page.locator('img').count()===0);
  override=receiver();delete override.model_check_valid_until;await refresh();check('missing telemetry does not invent readiness',await page.locator('#readiness-title').innerText()==='Status unknown');
  override=null;mode='ready';await refresh();delay=9500;const timeoutStart=Date.now();await refresh();check('8s timeout is bounded',(await page.locator('#notice').innerText()).includes('timed out')&&Date.now()-timeoutStart<9000);delay=0;
  // Repeated failed auto reads must remain quiet after the initial transition.
  mode='http';await page.getByRole('button',{name:'Resume updates',exact:true}).click();await settled();
  check('first automatic failure transition announces',(await page.locator('#announcement').innerText()).includes('could not be read'));
  await page.evaluate(()=>window.announcements=[]);await page.waitForTimeout(11000);
  check('identical automatic failures quiet',await page.evaluate(()=>window.announcements.length<=1&&window.announcements.every(x=>x.startsWith('Status unknown.'))),await page.evaluate(()=>window.announcements));
  await page.getByRole('button',{name:'Refresh status',exact:true}).click();await settled();
  check('manual failure announces',await page.evaluate(()=>window.announcements.some(x=>x.includes('could not be read'))));
  // Visual matrix, actual live HTML with synthetic diagnostics only in this fixture.
  mode='ready';override=null;await refresh();await page.getByRole('button',{name:'Pause updates',exact:true}).click();
  for(const width of [1200,1024,820,768,728,390,320]){
    await page.setViewportSize({width,height:900});
    for(const theme of ['light','dark']){
      await page.getByLabel('Theme',{exact:true}).selectOption(theme);
      const geometry=await page.evaluate(()=>({width:document.documentElement.scrollWidth,viewport:innerWidth,small:[...document.querySelectorAll('button,input,select,summary')].filter(e=>e.getBoundingClientRect().height>0&&e.getBoundingClientRect().height<44).map(e=>e.id||e.tagName)}));
      check(width+'/'+theme+' no overflow',geometry.width<=geometry.viewport,geometry);check(width+'/'+theme+' 44px targets',geometry.small.length===0,geometry.small);
      if([1200,728,390,320].includes(width))await shot(width+'-'+theme+'-receiver.png');
    }
  }
  await page.setViewportSize({width:1200,height:900});
  const variants={unconfigured:{role:'',ready:false,state:'unconfigured',reason:'unconfigured',last_attempt:'unconfigured',accounts:0,synchronized_accounts:0,available_accounts:0},blocked:receiver({ready:false,state:'unready',reason:'no_available_accounts',available_accounts:0}),stale:receiver({ready:false,state:'unready',reason:'snapshot_stale',available_accounts:0,fresh_until:new Date(Date.now()-10000).toISOString()}),exporter:{role:'exporter',ready:true,state:'exporter',reason:'exporter',last_attempt:'ok',accounts:85,synchronized_accounts:0,available_accounts:0},starting:{role:'receiver',ready:false,state:'starting',reason:'starting',last_attempt:'starting',accounts:0,synchronized_accounts:0,available_accounts:0}};
  for(const [name,value]of Object.entries(variants)){override=value;await refresh();await shot(name+'-desktop.png');if(name==='unconfigured')check('valid unconfigured backend shape is not ready',await page.locator('#readiness-title').innerText()==='Not ready · unconfigured'&&await page.locator('#available').innerText()==='—');if(name==='exporter')check('exporter uses exported count, receipt unknown',await page.locator('#synchronized').innerText()==='85'&&await page.locator('#available').innerText()==='—'&&await page.locator('#runtime-details').isHidden());}
  check('no CSP violations',await page.evaluate(()=>window.violations.length===0));
  check('no credential persistence',await page.evaluate(()=>localStorage.length===0&&sessionStorage.length===0&&window.storageWrites===0));
  check('no external resources or token URLs',outgoing.every(url=>url.startsWith(origin+'/')&&!url.includes(key)));
  check('key never reflected in document',!(await page.content()).includes(key));
  await page.evaluate(()=>window.dispatchEvent(new PageTransitionEvent('pagehide')));await cleared('pagehide clears private DOM');
  // Same-origin framing and cross-origin refusal enforced by HTTP CSP.
  mode='ready';override=null;await page.goto(origin+'/embed');const frame=page.frameLocator('iframe');await frame.getByLabel('CPA management key',{exact:true}).fill(key);await frame.getByRole('button',{name:'Connect status',exact:true}).click();await frame.getByText('Ready at last check · reduced pool',{exact:true}).waitFor();check('actual same-origin iframe works',true);await shot('same-origin-iframe.png');
  // A second port is a distinct, reachable origin; refusal must be CSP, not DNS failure.
  const cross=createServer((_req,res)=>{res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Cross origin fixture</title><iframe src="'+origin+shellPath+'"></iframe>');});
  await new Promise(resolve=>cross.listen(0,'127.0.0.1',resolve));
  let refused=false;
  page.on('console',message=>{if(message.text().includes('frame-ancestors'))refused=true;});
  try{await page.goto('http://127.0.0.1:'+cross.address().port);await page.waitForTimeout(1000);check('cross-origin iframe refused by frame-ancestors',refused&&!page.frames().some(f=>f!==page.mainFrame()&&f.url().includes(shellPath)));}finally{cross.closeAllConnections();await new Promise(resolve=>cross.close(resolve));}
  // Route only the static shell on a synthetic insecure origin. No remote socket is opened.
  await page.route('http://relay-ui.invalid/**',route=>route.fulfill({status:200,headers:Object.fromEntries(Object.entries(shell.Headers).map(([name,values])=>[name,values.join(', ')])),body:html}));
  await page.goto('http://relay-ui.invalid'+shellPath);const insecureCount=requests.length;await login();
  check('non-loopback HTTP refuses management key',(await page.locator('#login-error').innerText()).includes('Use HTTPS')&&requests.length===insecureCount&&await page.locator('#management-key').inputValue()==='');
  check('no JavaScript errors',results.errors.length===0,results.errors);
} catch(error) {results.failures.push('runner: '+error.message);results.errors.push(error.stack);}
finally {
  await browser.close();for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));
  await writeFile(path.join(output,'results.json'),JSON.stringify(results,null,2));
  console.log(JSON.stringify({checks:results.checks.length,failures:results.failures,evidence:output}));
}
if(results.failures.length)process.exitCode=1;
