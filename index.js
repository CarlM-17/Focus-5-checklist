// Fresh Focus 5 - Fresh Department Checklist (Railway)
// Two-file Node/Express app. Native https + crypto for Google Sheets (no googleapis package).

const express = require('express');
const https = require('https');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '4mb' }));

const PORT = process.env.PORT || 3006;
const SHEET_ID = process.env.SHEET_ID || '12uZjLN6arvwZPF03nBh52BtFRP6IKmcCpYqN_uJvc_M';

let SA = {};
try { SA = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON || '{}'); }
catch (e) { console.error('Bad GOOGLE_SERVICE_ACCOUNT_JSON:', e.message); }

// ---------- Google auth (JWT -> access token) ----------
let tokenCache = { token: null, exp: 0 };

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

function httpsReq(opts, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        if (res.statusCode >= 400) reject(new Error(`${res.statusCode}: ${data}`));
        else resolve(data);
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (tokenCache.token && tokenCache.exp - 60 > now) return tokenCache.token;
  if (!SA.client_email || !SA.private_key) throw new Error('Service account not configured');

  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: SA.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };
  const unsigned = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(claim));
  const sig = crypto.createSign('RSA-SHA256').update(unsigned).sign(SA.private_key);
  const jwt = unsigned + '.' + b64url(sig);

  const body = 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + jwt;
  const resp = await httpsReq(
    {
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    },
    body
  );
  const j = JSON.parse(resp);
  tokenCache = { token: j.access_token, exp: now + (j.expires_in || 3600) };
  return j.access_token;
}

// ---------- Sheets helpers ----------
async function sheetsGet(range) {
  const tok = await getAccessToken();
  const resp = await httpsReq({
    hostname: 'sheets.googleapis.com',
    path: `/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${tok}` },
  });
  return JSON.parse(resp).values || [];
}

async function sheetsAppend(range, values) {
  const tok = await getAccessToken();
  const body = JSON.stringify({ values });
  const resp = await httpsReq(
    {
      hostname: 'sheets.googleapis.com',
      path: `/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${tok}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    },
    body
  );
  return JSON.parse(resp);
}

async function sheetsBatchUpdateValues(data) {
  const tok = await getAccessToken();
  const body = JSON.stringify({ valueInputOption: 'USER_ENTERED', data });
  const resp = await httpsReq(
    {
      hostname: 'sheets.googleapis.com',
      path: `/v4/spreadsheets/${SHEET_ID}/values:batchUpdate`,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${tok}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    },
    body
  );
  return JSON.parse(resp);
}

// ---------- API ----------
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const rows = await sheetsGet('AreaManagers!A2:C');
    const found = rows.find(
      (r) =>
        (r[0] || '').trim().toLowerCase() === (username || '').trim().toLowerCase() &&
        String(r[1] || '') === String(password || '')
    );
    if (!found) return res.json({ ok: false, error: 'Invalid username or password' });
    const level = (found[2] || 'Area Manager').trim();
    res.json({ ok: true, manager: found[0], level });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/stores', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    const level = (req.query.level || '').trim().toLowerCase();
    // ListOfStores columns: A=No, B=Region, C=AREA, D=STORE ID, E=STORE NAME, F=Remarks, G=AreaManager
    const rows = await sheetsGet('ListOfStores!A2:G');
    const isRegional = level === 'regional manager';
    const stores = rows
      .filter((r) => isRegional || (r[6] || '').trim().toLowerCase() === manager)
      .map((r) => r[4])
      .filter(Boolean);
    res.json({ ok: true, stores });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/particulars', async (req, res) => {
  try {
    const rows = await sheetsGet('Particulars!A2:B');
    const items = rows.filter((r) => r[0] && r[1]).map((r) => ({ category: r[0], item: r[1] }));
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/submit', async (req, res) => {
  try {
    const { manager, store, date, entries, auditId } = req.body || {};
    if (!manager || !store || !date || !Array.isArray(entries) || !entries.length) {
      return res.json({ ok: false, error: 'Missing fields' });
    }
    const ts = new Date().toISOString();
    const id = auditId || 'A' + Date.now();

    if (auditId) await markEdited(auditId);

    const rows = entries.map((e) => [
      ts,
      id,
      manager,
      store,
      date,
      e.category || '',
      e.item || '',
      String(e.rating ?? ''),
      e.remarks || '',
      'ACTIVE',
    ]);
    await sheetsAppend('ChecklistData!A:J', rows);
    res.json({ ok: true, auditId: id });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

async function markEdited(auditId) {
  const rows = await sheetsGet('ChecklistData!A2:J');
  const data = [];
  rows.forEach((r, i) => {
    if (r[1] === auditId && (r[9] || 'ACTIVE') === 'ACTIVE') {
      data.push({ range: `ChecklistData!J${i + 2}`, values: [['EDITED']] });
    }
  });
  if (data.length) await sheetsBatchUpdateValues(data);
}

app.get('/api/history', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    const level = (req.query.level || '').trim().toLowerCase();
    const isRegional = level === 'regional manager';
    const rows = await sheetsGet('ChecklistData!A2:J');
    const map = new Map();
    rows.forEach((r) => {
      if ((r[9] || 'ACTIVE') !== 'ACTIVE') return;
      if (!isRegional && manager && (r[2] || '').trim().toLowerCase() !== manager) return;
      const id = r[1];
      if (!id) return;
      if (!map.has(id)) {
        map.set(id, {
          auditId: id,
          timestamp: r[0],
          manager: r[2],
          store: r[3],
          date: r[4],
          count: 0,
          sum: 0,
          max: 0,
        });
      }
      const a = map.get(id);
      a.count++;
      const rating = parseInt(r[7], 10);
      if (!isNaN(rating)) {
        a.sum += rating;
        a.max += 2;
      }
    });
    const list = [...map.values()].map((a) => ({
      ...a,
      score: a.max ? Math.round((a.sum / a.max) * 100) : 0,
    }));
    list.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
    res.json({ ok: true, audits: list });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/audit/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const rows = await sheetsGet('ChecklistData!A2:J');
    const entries = rows.filter((r) => r[1] === id && (r[9] || 'ACTIVE') === 'ACTIVE');
    if (!entries.length) return res.json({ ok: false, error: 'Not found' });
    const meta = { auditId: id, manager: entries[0][2], store: entries[0][3], date: entries[0][4] };
    const items = entries.map((r) => ({
      category: r[5],
      item: r[6],
      rating: r[7],
      remarks: r[8],
    }));
    res.json({ ok: true, meta, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- Frontend ----------
const HTML = `<!doctype html>
<html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Fresh Focus 5 - Checklist</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;color:#222}
header{background:#1f7a3a;color:#fff;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}
header h1{margin:0;font-size:17px}
header .who{font-size:12px;opacity:.9}
main{padding:12px;max-width:820px;margin:0 auto}
.card{background:#fff;border-radius:10px;padding:14px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
label{display:block;font-size:12px;color:#555;margin-bottom:4px;margin-top:8px}
input,select,textarea,button{font:inherit}
input,select,textarea{width:100%;padding:10px;border:1px solid #ccd;border-radius:8px;background:#fff}
textarea{min-height:44px;resize:vertical}
button{cursor:pointer;border:0;border-radius:8px;padding:10px 14px;background:#1f7a3a;color:#fff;font-weight:600}
button.ghost{background:#eef;color:#224}
button.sm{padding:6px 10px;font-size:13px}
.row{display:flex;gap:8px}
.row>*{flex:1}
.cat{margin-top:14px;font-weight:700;color:#1f7a3a;border-bottom:2px solid #1f7a3a;padding-bottom:4px}
.item{padding:10px 0;border-bottom:1px solid #eee}
.item .t{font-weight:600;margin-bottom:6px}
.rate{display:flex;gap:6px;margin-bottom:6px}
.rate button{flex:1;background:#eef;color:#334;padding:8px;font-weight:700}
.rate button.r0.on{background:#c33;color:#fff}
.rate button.r1.on{background:#e0a020;color:#fff}
.rate button.r2.on{background:#1f7a3a;color:#fff}
.tabs{display:flex;gap:6px;margin-bottom:10px}
.tabs button{flex:1;background:#dde;color:#223}
.tabs button.active{background:#1f7a3a;color:#fff}
.score{font-size:28px;font-weight:700;color:#1f7a3a}
.hist{padding:10px;border:1px solid #dde;border-radius:8px;margin-bottom:8px;background:#fff;display:flex;justify-content:space-between;align-items:center;gap:8px}
.hist .meta{font-size:13px;color:#456}
.pill{display:inline-block;padding:2px 8px;border-radius:99px;background:#1f7a3a;color:#fff;font-size:12px;font-weight:700}
.err{color:#c33;margin-top:8px;font-size:13px}
.hidden{display:none}
.muted{color:#789;font-size:12px}
</style></head><body>

<header>
  <h1>Fresh Focus 5 - Checklist</h1>
  <div class="who"><span id="whoName"></span> <button id="logoutBtn" class="sm ghost hidden">Logout</button></div>
</header>

<main>

<div id="loginScreen" class="card">
  <h2 style="margin-top:0">Area Manager Login</h2>
  <label>Username</label>
  <input id="lu" autocomplete="username"/>
  <label>Password</label>
  <input id="lp" type="password" autocomplete="current-password"/>
  <div style="margin-top:12px"><button id="loginBtn">Login</button></div>
  <div id="loginErr" class="err"></div>
</div>

<div id="appScreen" class="hidden">
  <div class="tabs">
    <button data-tab="new" class="active">New Audit</button>
    <button data-tab="hist">History</button>
  </div>

  <div id="tabNew">
    <div class="card">
      <div class="row">
        <div>
          <label>Store</label>
          <select id="store"></select>
        </div>
        <div>
          <label>Date</label>
          <input id="date" type="date"/>
        </div>
      </div>
      <div style="margin-top:10px" class="muted">Score: <span id="scoreLive" class="score">0%</span> <span id="scoreDetail"></span></div>
      <div id="editBanner" class="muted hidden" style="margin-top:6px;color:#a60;font-weight:600">Editing existing audit</div>
    </div>

    <div id="checklist" class="card">Loading items...</div>

    <div class="card">
      <button id="submitBtn">Upload to Google Sheets</button>
      <button id="resetBtn" class="ghost" style="margin-left:8px">Reset</button>
      <div id="subErr" class="err"></div>
    </div>
  </div>

  <div id="tabHist" class="hidden">
    <div class="card">
      <button id="reloadHist" class="ghost sm">Refresh</button>
      <div id="histList" style="margin-top:10px">Loading...</div>
    </div>
  </div>
</div>

</main>

<script>
const S = { manager:null, level:null, particulars:[], ratings:{}, remarks:{}, editingId:null };

function $(q){return document.querySelector(q)}
function api(url, opts){ return fetch(url, opts).then(r=>r.json()) }

// ---- Login ----
$('#loginBtn').onclick = async () => {
  const u = $('#lu').value.trim(), p = $('#lp').value;
  $('#loginErr').textContent = '';
  const r = await api('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u,password:p})});
  if (!r.ok) { $('#loginErr').textContent = r.error || 'Login failed'; return; }
  S.manager = r.manager; S.level = r.level || 'Area Manager';
  localStorage.setItem('ff5_mgr', r.manager);
  localStorage.setItem('ff5_lvl', S.level);
  await enterApp();
};

$('#logoutBtn').onclick = () => { localStorage.removeItem('ff5_mgr'); localStorage.removeItem('ff5_lvl'); location.reload(); };

async function enterApp(){
  $('#loginScreen').classList.add('hidden');
  $('#appScreen').classList.remove('hidden');
  $('#logoutBtn').classList.remove('hidden');
  $('#whoName').textContent = S.manager + ' (' + S.level + ')';
  $('#date').value = new Date().toISOString().slice(0,10);
  await Promise.all([loadStores(), loadParticulars()]);
  renderChecklist();
}

async function loadStores(){
  const r = await api('/api/stores?manager=' + encodeURIComponent(S.manager) + '&level=' + encodeURIComponent(S.level||''));
  const sel = $('#store'); sel.innerHTML = '';
  (r.stores||[]).forEach(s => { const o=document.createElement('option'); o.value=s; o.textContent=s; sel.appendChild(o); });
  if (!r.stores || !r.stores.length) sel.innerHTML = '<option>(no stores assigned)</option>';
}

async function loadParticulars(){
  const r = await api('/api/particulars');
  S.particulars = r.items || [];
}

// ---- Checklist rendering ----
function renderChecklist(){
  const groups = {};
  S.particulars.forEach((p,i) => { (groups[p.category] = groups[p.category] || []).push({...p,i}); });
  const html = Object.keys(groups).map(cat => {
    const items = groups[cat].map(it => {
      const key = 'k'+it.i;
      const r = S.ratings[key];
      return \`<div class="item">
        <div class="t">\${escapeHtml(it.item)}</div>
        <div class="rate">
          <button class="r0 \${r==='0'?'on':''}" onclick="setRate('\${key}','0')">0 - Not complied</button>
          <button class="r1 \${r==='1'?'on':''}" onclick="setRate('\${key}','1')">1 - Needs improvement</button>
          <button class="r2 \${r==='2'?'on':''}" onclick="setRate('\${key}','2')">2 - Complied</button>
        </div>
        <textarea placeholder="Remarks / notes (optional)" oninput="S.remarks['\${key}']=this.value">\${escapeHtml(S.remarks[key]||'')}</textarea>
      </div>\`;
    }).join('');
    return \`<div class="cat">\${escapeHtml(cat)}</div>\${items}\`;
  }).join('');
  $('#checklist').innerHTML = html || '<div class="muted">No items in Particulars sheet.</div>';
  updateScore();
}

function setRate(key, val){
  S.ratings[key] = val;
  renderChecklist();
}

function updateScore(){
  let sum=0, max=0, done=0;
  Object.values(S.ratings).forEach(v => { const n=parseInt(v,10); if(!isNaN(n)){ sum+=n; max+=2; done++; } });
  const pct = max ? Math.round(sum/max*100) : 0;
  $('#scoreLive').textContent = pct + '%';
  $('#scoreDetail').textContent = \` (\${done}/\${S.particulars.length} rated)\`;
}

function escapeHtml(s){ return String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ---- Submit ----
$('#submitBtn').onclick = async () => {
  $('#subErr').textContent = '';
  const store = $('#store').value, date = $('#date').value;
  if (!store || !date) { $('#subErr').textContent = 'Store and date required'; return; }
  const entries = S.particulars.map((p,i) => ({
    category: p.category, item: p.item,
    rating: S.ratings['k'+i] ?? '',
    remarks: S.remarks['k'+i] || ''
  }));
  const btn = $('#submitBtn'); btn.disabled = true; btn.textContent = 'Uploading...';
  const r = await api('/api/submit', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({manager:S.manager, store, date, entries, auditId:S.editingId})});
  btn.disabled = false; btn.textContent = 'Upload to Google Sheets';
  if (!r.ok) { $('#subErr').textContent = r.error||'Failed'; return; }
  alert('Saved. Audit ID: ' + r.auditId);
  resetForm();
};

$('#resetBtn').onclick = resetForm;
function resetForm(){
  S.ratings = {}; S.remarks = {}; S.editingId = null;
  $('#editBanner').classList.add('hidden');
  renderChecklist();
}

// ---- Tabs ----
document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tabs button').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
  const t = b.dataset.tab;
  $('#tabNew').classList.toggle('hidden', t!=='new');
  $('#tabHist').classList.toggle('hidden', t!=='hist');
  if (t==='hist') loadHistory();
});

async function loadHistory(){
  $('#histList').textContent = 'Loading...';
  const r = await api('/api/history?manager=' + encodeURIComponent(S.manager) + '&level=' + encodeURIComponent(S.level||''));
  if (!r.ok) { $('#histList').textContent = r.error||'Failed'; return; }
  if (!r.audits.length) { $('#histList').textContent = 'No audits yet.'; return; }
  $('#histList').innerHTML = r.audits.map(a => \`
    <div class="hist">
      <div>
        <div><b>\${escapeHtml(a.store)}</b> - \${escapeHtml(a.date)}</div>
        <div class="meta">\${new Date(a.timestamp).toLocaleString()} - \${a.count} items - by \${escapeHtml(a.manager)}</div>
      </div>
      <div style="text-align:right">
        <div class="pill">\${a.score}%</div>
        <div style="margin-top:6px"><button class="sm ghost" onclick="editAudit('\${a.auditId}')">Edit</button></div>
      </div>
    </div>\`).join('');
}
$('#reloadHist').onclick = loadHistory;

async function editAudit(id){
  const r = await api('/api/audit/' + encodeURIComponent(id));
  if (!r.ok) { alert(r.error||'Failed'); return; }
  S.editingId = id;
  S.ratings = {}; S.remarks = {};
  // Match items by category+item text
  const key = (c,i)=>c+'||'+i;
  const map = {};
  r.items.forEach(it => map[key(it.category,it.item)] = it);
  S.particulars.forEach((p,i)=>{
    const m = map[key(p.category,p.item)];
    if (m) { if (m.rating!==''&&m.rating!=null) S.ratings['k'+i]=String(m.rating); if (m.remarks) S.remarks['k'+i]=m.remarks; }
  });
  $('#store').value = r.meta.store;
  $('#date').value = r.meta.date;
  $('#editBanner').classList.remove('hidden');
  document.querySelector('.tabs button[data-tab="new"]').click();
}

// Auto-login if remembered
const remembered = localStorage.getItem('ff5_mgr');
if (remembered) { S.manager = remembered; S.level = localStorage.getItem('ff5_lvl')||'Area Manager'; enterApp(); }
</script>
</body></html>`;

app.get('/', (req, res) => res.type('html').send(HTML));

app.listen(PORT, () => console.log('Fresh Focus 5 Checklist listening on', PORT));
