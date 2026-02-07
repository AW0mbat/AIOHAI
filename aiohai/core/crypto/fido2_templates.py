#!/usr/bin/env python3
"""
AIOHAI Core Crypto — FIDO2 HTML Templates
==========================================
HTML templates for the FIDO2 approval server UI.

O1 FIX: Extracted from fido_gate.py for readability.
These are standard Python module imports — NOT runtime file loading
(which would be a security concern). Python's import system handles
these deterministically at startup.

Import from: aiohai.core.crypto.fido2_templates
"""

__all__ = [
    '_DASHBOARD_HTML',
    '_APPROVAL_HTML',
    '_REGISTER_HTML',
    '_ERROR_HTML',
    '_get_dashboard_html',
    '_get_approval_html',
    '_get_register_html',
    '_get_error_html',
]


# =============================================================================
# GETTER FUNCTIONS
# =============================================================================

def _get_dashboard_html():
    return _DASHBOARD_HTML

def _get_approval_html():
    return _APPROVAL_HTML

def _get_register_html():
    return _REGISTER_HTML

def _get_error_html():
    return _ERROR_HTML


# =============================================================================
# HTML Templates (inline — no external file loading for security)
# =============================================================================

_DASHBOARD_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ rp_name }} Approvals</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;min-height:100vh;padding:1rem}
.hdr{padding:1rem 0;border-bottom:1px solid #2a2a3a;margin-bottom:1rem;display:flex;justify-content:space-between;align-items:center}
.hdr h1{font-size:1.1rem}.dot{width:8px;height:8px;border-radius:50%;background:#4f8;animation:p 2s infinite}
@keyframes p{50%{opacity:.5}}.empty{text-align:center;padding:3rem;color:#888}.card{background:#12121a;border:1px solid #2a2a3a;border-radius:12px;padding:1rem;margin-bottom:.75rem}
.card.del{border-left:3px solid #f44}.op{font-family:monospace;font-size:.8rem;font-weight:700;padding:.15rem .5rem;border-radius:4px;background:rgba(255,68,68,.15);color:#f44;display:inline-block}
.tgt{font-family:monospace;font-size:.85rem;margin:.5rem 0;word-break:break-all}.desc{font-size:.85rem;color:#888}
.btns{display:flex;gap:.5rem;margin-top:1rem}.btn{flex:1;padding:.75rem;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-size:.85rem}
.btn-a{background:#4af;color:#000}.btn-r{background:#1a1a28;color:#888;border:1px solid #2a2a3a}
.nav{position:fixed;bottom:0;left:0;right:0;background:#12121a;border-top:1px solid #2a2a3a;display:flex;padding:.5rem 0}
.nav a{flex:1;text-align:center;color:#888;text-decoration:none;font-size:.7rem;padding:.5rem}
.nav a.on{color:#4af}.badge{background:#f44;color:#fff;font-size:.6rem;padding:.1rem .35rem;border-radius:9px;margin-left:.2rem}
.toast{position:fixed;bottom:4rem;left:50%;transform:translateX(-50%) translateY(100px);background:#1a1a28;border:1px solid #2a2a3a;border-radius:8px;padding:.75rem 1.25rem;font-size:.85rem;opacity:0;transition:.3s;z-index:99}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}.toast.ok{border-color:#4f8}.toast.err{border-color:#f44}</style></head>
<body><div class="hdr"><h1>🔐 {{ rp_name }}</h1><div class="dot"></div></div>
<div id="list"><div class="empty">🛡️<br><br>No pending approvals</div></div>
<div class="nav"><a href="/" class="on">🛡️ Approvals<span class="badge" id="badge" style="display:none">0</span></a><a href="/register">🔑 Devices</a></div>
<div class="toast" id="toast"></div>
<script>
async function poll(){try{const r=await fetch('/api/pending');const d=await r.json();render(d.requests||{})}catch(e){}}
function render(reqs){const l=document.getElementById('list');const b=document.getElementById('badge');const e=Object.entries(reqs);
b.textContent=e.length;b.style.display=e.length?'inline':'none';
if(!e.length){l.innerHTML='<div class="empty">🛡️<br><br>No pending approvals</div>';return}
l.innerHTML=e.map(([id,r])=>{const rem=Math.max(0,Math.floor((new Date(r.expires_at)-Date.now())/1000));
return`<div class="card del"><div style="display:flex;justify-content:space-between"><span class="op">${r.operation_type}</span><span style="font-family:monospace;font-size:.75rem;color:#888">${Math.floor(rem/60)}:${String(rem%60).padStart(2,'0')}</span></div>
<div class="tgt">${esc(r.target)}</div><div class="desc">${esc(r.description)}</div>
<div class="btns"><button class="btn btn-a" onclick="doApprove('${id}')">🔐 Approve</button><button class="btn btn-r" onclick="doReject('${id}')">✕ Reject</button></div></div>`}).join('')}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function toast(m,t){const e=document.getElementById('toast');e.textContent=m;e.className='toast show '+(t||'');setTimeout(()=>e.className='toast',3000)}
function b64d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function b64e(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function decOpts(o){const p=o.publicKey||o;if(p.challenge)p.challenge=b64d(p.challenge);if(p.allowCredentials)p.allowCredentials=p.allowCredentials.map(c=>({...c,id:b64d(c.id)}));return p}
function encCred(c){return{id:c.id,rawId:b64e(c.rawId),type:c.type,response:{authenticatorData:b64e(c.response.authenticatorData),clientDataJSON:b64e(c.response.clientDataJSON),signature:b64e(c.response.signature),userHandle:c.response.userHandle?b64e(c.response.userHandle):null}}}
async function doApprove(rid){const u=localStorage.getItem('aiohai_username');if(!u){toast('Set username at /register','err');return}
try{const br=await fetch('/auth/approve/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:rid,username:u})});
if(!br.ok){toast((await br.json()).error||'Failed','err');return}const opts=await br.json();
const cred=await navigator.credentials.get({publicKey:decOpts(opts)});
const cr=await fetch('/auth/approve/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:opts.session_id,credential:encCred(cred)})});
if(cr.ok){toast('✓ Approved','ok');poll()}else{toast((await cr.json()).error||'Failed','err')}}
catch(e){if(e.name==='NotAllowedError')toast('Cancelled','err');else toast(e.message,'err')}}
async function doReject(rid){const u=localStorage.getItem('aiohai_username')||'unknown';
await fetch('/auth/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:rid,username:u})});toast('Rejected','ok');poll()}
poll();setInterval(poll,2000);
</script></body></html>"""

_APPROVAL_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve — {{ rp_name }}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}
.card{background:#12121a;border:1px solid #2a2a3a;border-radius:16px;padding:2rem;max-width:420px;width:100%;text-align:center}
.icon{font-size:3rem;margin-bottom:1rem}.title{font-size:1.1rem;font-weight:700;margin-bottom:.5rem}
.sub{font-size:.85rem;color:#888;margin-bottom:1.5rem}.detail{background:#1a1a28;border-radius:8px;padding:1rem;margin-bottom:1.5rem;text-align:left}
.row{display:flex;justify-content:space-between;margin-bottom:.5rem}.lbl{font-size:.7rem;color:#888;text-transform:uppercase;letter-spacing:1px;font-family:monospace}
.val{font-family:monospace;font-size:.85rem;word-break:break-all}.val.red{color:#f44}
.btn{width:100%;padding:1rem;border:none;border-radius:12px;font-size:1rem;font-weight:700;cursor:pointer;margin-bottom:.75rem}
.btn-a{background:#4af;color:#000}.btn-r{background:#1a1a28;color:#888;border:1px solid #2a2a3a}
.btn:disabled{opacity:.5}#st{font-size:.8rem;color:#888;margin-top:1rem;min-height:1.5rem}
.done{padding:2rem;text-align:center}.done .icon{font-size:4rem}.done.ok{color:#4f8}.done.no{color:#f44}</style></head>
<body><div class="card" id="card"><div class="icon">🔐</div><div class="title">Hardware Approval Required</div>
<div class="sub">Authenticate to approve this operation</div>
<div class="detail"><div class="row"><span class="lbl">Operation</span><span class="val red">{{ request.operation_type }}</span></div>
<div class="row"><span class="lbl">Target</span><span class="val">{{ request.target }}</span></div>
<div class="row"><span class="lbl">Tier</span><span class="val">TIER {{ request.tier }}</span></div>
{% if request.description %}<div class="row"><span class="lbl">Details</span><span class="val">{{ request.description }}</span></div>{% endif %}</div>
<button class="btn btn-a" id="abtn" onclick="go()">🔐 Approve with Biometrics</button>
<button class="btn btn-r" onclick="rej()">✕ Reject</button><div id="st"></div></div>
<script>const RID='{{ request.request_id }}';
function b64d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function b64e(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function decO(o){const p=o.publicKey||o;if(p.challenge)p.challenge=b64d(p.challenge);if(p.allowCredentials)p.allowCredentials=p.allowCredentials.map(c=>({...c,id:b64d(c.id)}));return p}
function encC(c){return{id:c.id,rawId:b64e(c.rawId),type:c.type,response:{authenticatorData:b64e(c.response.authenticatorData),clientDataJSON:b64e(c.response.clientDataJSON),signature:b64e(c.response.signature),userHandle:c.response.userHandle?b64e(c.response.userHandle):null}}}
async function go(){const u=localStorage.getItem('aiohai_username');if(!u){document.getElementById('st').textContent='Set username at /register';return}
const b=document.getElementById('abtn');b.disabled=true;b.textContent='⏳ Authenticating...';
try{const br=await fetch('/auth/approve/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:RID,username:u})});
if(!br.ok)throw new Error((await br.json()).error);const opts=await br.json();document.getElementById('st').textContent='Touch key or verify biometrics...';
const cred=await navigator.credentials.get({publicKey:decO(opts)});
const cr=await fetch('/auth/approve/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:opts.session_id,credential:encC(cred)})});
if(cr.ok){document.getElementById('card').innerHTML='<div class="done ok"><div class="icon">✅</div><div class="title">Approved</div><p style="margin-top:1rem;color:#888">You can close this page.</p></div>'}
else throw new Error((await cr.json()).error)}
catch(e){b.disabled=false;b.textContent='🔐 Approve with Biometrics';document.getElementById('st').textContent='Error: '+e.message}}
async function rej(){const u=localStorage.getItem('aiohai_username')||'unknown';
await fetch('/auth/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:RID,username:u})});
document.getElementById('card').innerHTML='<div class="done no"><div class="icon">❌</div><div class="title">Rejected</div><p style="margin-top:1rem;color:#888">You can close this page.</p></div>'}
</script></body></html>"""

_REGISTER_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register — {{ rp_name }}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;min-height:100vh;padding:1.5rem}
.hdr{text-align:center;margin-bottom:2rem}.hdr h1{font-size:1.2rem;margin-bottom:.5rem}.hdr p{font-size:.85rem;color:#888}
.fg{margin-bottom:1.25rem}.fl{font-size:.7rem;text-transform:uppercase;letter-spacing:2px;color:#888;margin-bottom:.5rem;display:block;font-family:monospace}
.fi{width:100%;padding:.75rem;background:#12121a;border:1px solid #2a2a3a;border-radius:8px;color:#e8e8f0;font-size:.9rem}
.fi:focus{outline:none;border-color:#4af}select.fi{appearance:none;-webkit-appearance:none}
.dg{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:1.5rem}
.dc{background:#12121a;border:2px solid #2a2a3a;border-radius:12px;padding:1.25rem;text-align:center;cursor:pointer;transition:.2s}
.dc:hover{border-color:#4af}.dc.sel{border-color:#4af;box-shadow:0 0 20px rgba(68,170,255,.15)}
.dc .di{font-size:2rem;margin-bottom:.5rem}.dc .dn{font-size:.8rem;font-weight:700}.dc .dd{font-size:.7rem;color:#888;margin-top:.25rem}
.btn{width:100%;padding:1rem;border:none;border-radius:12px;font-size:1rem;font-weight:700;cursor:pointer;background:#4af;color:#000}
.btn:disabled{opacity:.5}#st{text-align:center;font-size:.85rem;margin-top:1rem;min-height:1.5rem}#st.ok{color:#4f8}#st.err{color:#f44}
.devs{margin-top:2rem}.di-item{background:#12121a;border:1px solid #2a2a3a;border-radius:8px;padding:1rem;margin-bottom:.5rem;display:flex;justify-content:space-between}
.di-info .di-t{font-weight:700;font-size:.9rem}.di-info .di-m{font-size:.75rem;color:#888;font-family:monospace}
a.back{display:block;text-align:center;margin-top:1.5rem;color:#4af;text-decoration:none;font-size:.85rem}</style></head>
<body><div class="hdr"><h1>🔑 Register Device</h1><p>Add a security key or biometric authenticator</p></div>
<div class="fg"><label class="fl">Username</label><input class="fi" id="uname" placeholder="e.g. admin"></div>
<div class="fg"><label class="fl">Device Name</label><input class="fi" id="dname" placeholder="e.g. iPhone 15 Face ID"></div>
<label class="fl">Type</label>
<div class="dg"><div class="dc sel" id="cp" onclick="sel('platform')"><div class="di">📱</div><div class="dn">Biometric</div><div class="dd">Face ID, Touch ID</div></div>
<div class="dc" id="ck" onclick="sel('security_key')"><div class="di">🔑</div><div class="dn">Security Key</div><div class="dd">Nitrokey, YubiKey</div></div></div>
<button class="btn" id="rbtn" onclick="reg()">Register Device</button><div id="st"></div>
<div class="devs"><label class="fl">Registered Devices</label><div id="dl"><p style="color:#888;font-size:.85rem;text-align:center">Loading...</p></div></div>
<a href="/" class="back">&larr; Back to Approvals</a>
<script>let stype='platform';
function sel(t){stype=t;document.getElementById('cp').classList.toggle('sel',t==='platform');document.getElementById('ck').classList.toggle('sel',t==='security_key')}
const sv=localStorage.getItem('aiohai_username');if(sv)document.getElementById('uname').value=sv;
function b64d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function b64e(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function decCO(o){const p=o.publicKey||o;if(p.challenge)p.challenge=b64d(p.challenge);if(p.user&&p.user.id)p.user.id=b64d(p.user.id);
if(p.excludeCredentials)p.excludeCredentials=p.excludeCredentials.map(c=>({...c,id:b64d(c.id)}));return p}
function encAR(c){return{id:c.id,rawId:b64e(c.rawId),type:c.type,response:{attestationObject:b64e(c.response.attestationObject),clientDataJSON:b64e(c.response.clientDataJSON)}}}
async function reg(){const u=document.getElementById('uname').value.trim();const d=document.getElementById('dname').value.trim();const st=document.getElementById('st');const btn=document.getElementById('rbtn');
if(!u){st.textContent='Username required';st.className='err';return}if(!d){st.textContent='Device name required';st.className='err';return}
localStorage.setItem('aiohai_username',u);btn.disabled=true;st.textContent='Starting...';st.className='';
try{const br=await fetch('/auth/register/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,device_name:d,authenticator_type:stype,role:'admin'})});
if(!br.ok)throw new Error((await br.json()).error);const opts=await br.json();st.textContent='Touch key or verify biometrics...';
const cred=await navigator.credentials.create({publicKey:decCO(opts)});
const cr=await fetch('/auth/register/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:opts.session_id,credential:encAR(cred)})});
const res=await cr.json();if(cr.ok){st.textContent='✓ '+res.message;st.className='ok';loadDevs()}else throw new Error(res.error)}
catch(e){st.textContent='Error: '+e.message;st.className='err'}finally{btn.disabled=false}}
async function loadDevs(){try{const r=await fetch('/api/users');const d=await r.json();const l=document.getElementById('dl');
let h='';for(const[n,i]of Object.entries(d))for(const dv of i.devices)h+=`<div class="di-item"><div class="di-info"><div class="di-t">${dv.name}</div><div class="di-m">${n} · ${i.role} · ${dv.type}</div></div></div>`;
l.innerHTML=h||'<p style="color:#888;font-size:.85rem;text-align:center">No devices registered</p>'}catch(e){}}
loadDevs();
</script></body></html>"""

_ERROR_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error</title>
<style>body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.e{text-align:center}.e .i{font-size:3rem;margin-bottom:1rem}.e h1{font-size:1.2rem;margin-bottom:.5rem}.e p{color:#888;font-size:.9rem}
.e a{color:#4af;text-decoration:none;display:block;margin-top:1.5rem}</style></head>
<body><div class="e"><div class="i">⚠️</div><h1>{{ message }}</h1><p>The request may have expired or been processed.</p><a href="/">&larr; Back</a></div></body></html>"""

