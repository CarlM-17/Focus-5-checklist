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

app.get('/api/summary', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    const level = (req.query.level || '').trim().toLowerCase();
    const from = (req.query.from || '').trim();
    const to = (req.query.to || '').trim();
    const areaFilter = (req.query.area || '').trim();
    const storeFilter = (req.query.store || '').trim();
    const isRegional = level === 'regional manager';

    const stores = await sheetsGet('ListOfStores!A2:G');
    const storeMap = {};
    const managerAreas = new Set();
    stores.forEach((r) => {
      const storeName = r[4], areaName = r[2] || '(no area)', mgr = r[6] || '';
      if (!storeName) return;
      storeMap[storeName] = { area: areaName, manager: mgr };
      if (mgr.trim().toLowerCase() === manager) managerAreas.add(areaName);
    });
    const allowedAreas = isRegional
      ? [...new Set(stores.map((r) => r[2] || '(no area)').filter(Boolean))]
      : [...managerAreas];

    const data = await sheetsGet('ChecklistData!A2:J');
    const rows = data.filter((r) => {
      if ((r[9] || 'ACTIVE') !== 'ACTIVE') return false;
      if (from && (r[4] || '') < from) return false;
      if (to && (r[4] || '') > to) return false;
      const areaOfRow = (storeMap[r[3]] || {}).area || '(unknown)';
      if (!isRegional && !managerAreas.has(areaOfRow)) return false;
      if (areaFilter && areaOfRow !== areaFilter) return false;
      if (storeFilter && (r[3] || '') !== storeFilter) return false;
      return true;
    });

    // Stores list for dropdown: respect manager access + area filter
    const allowedStores = stores
      .filter((r) => {
        const areaName = r[2] || '(no area)';
        const mgr = (r[6] || '').trim().toLowerCase();
        if (!isRegional && mgr !== manager) return false;
        if (areaFilter && areaName !== areaFilter) return false;
        return !!r[4];
      })
      .map((r) => r[4]);

    const bucket = (obj, key) => (obj[key] = obj[key] || { r0: 0, r1: 0, r2: 0, total: 0 });
    const perStore = {}, perArea = {}, perItem = {};
    rows.forEach((r) => {
      if (r[5] === 'AUDIT NOTES') return; // skip general-notes rows in aggregates
      const store = r[3] || '(unknown)';
      const areaOfRow = (storeMap[store] || {}).area || '(unknown)';
      const itemKey = (r[5] || '') + ' | ' + (r[6] || '');
      const s = bucket(perStore, store); s.area = areaOfRow;
      const a = bucket(perArea, areaOfRow);
      const it = bucket(perItem, itemKey);
      const rating = r[7];
      if (rating === '0') { s.r0++; a.r0++; it.r0++; }
      else if (rating === '1') { s.r1++; a.r1++; it.r1++; }
      else if (rating === '2') { s.r2++; a.r2++; it.r2++; }
      s.total++; a.total++; it.total++;
    });
    const withScore = (o) => ({ ...o, score: o.total ? Math.round(((o.r1 + o.r2 * 2) / (o.total * 2)) * 100) : 0 });

    res.json({
      ok: true,
      areas: allowedAreas.sort(),
      stores: [...new Set(allowedStores)].sort(),
      perArea: Object.entries(perArea).map(([name, v]) => ({ name, ...withScore(v) })).sort((a, b) => a.name.localeCompare(b.name)),
      perStore: Object.entries(perStore).map(([name, v]) => ({ name, ...withScore(v) })).sort((a, b) => (a.area || '').localeCompare(b.area || '') || a.name.localeCompare(b.name)),
      allItems: Object.entries(perItem).map(([name, v]) => ({ name, ...withScore(v) })).sort((a, b) => a.score - b.score),
      auditCount: new Set(rows.map((r) => r[1])).size,
      itemCount: rows.length,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- Frontend ----------
const HTML = `<!doctype html>
<html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<meta name="theme-color" content="#1f7a3a"/>
<meta name="apple-mobile-web-app-capable" content="yes"/>
<meta name="mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
<title>Fresh Focus 5 - Checklist</title>
<style>
*{box-sizing:border-box;-webkit-tap-highlight-color:rgba(0,0,0,0)}
html,body{overscroll-behavior-y:contain}
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;color:#222;padding-bottom:env(safe-area-inset-bottom)}
header{background:#1f7a3a;color:#fff;padding:12px 16px;padding-top:calc(12px + env(safe-area-inset-top));display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;gap:8px}
header h1{margin:0;font-size:16px;line-height:1.2}
header .who{font-size:12px;opacity:.95;text-align:right;display:flex;align-items:center;gap:6px;flex-shrink:0}
main{padding:12px;max-width:820px;margin:0 auto}
.card{background:#fff;border-radius:10px;padding:14px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
label{display:block;font-size:12px;color:#555;margin-bottom:4px;margin-top:8px}
input,select,textarea,button{font:inherit}
/* font-size:16px prevents iOS Safari auto-zoom on focus */
input,select,textarea{width:100%;padding:12px;border:1px solid #ccd;border-radius:8px;background:#fff;font-size:16px;min-height:44px}
textarea{min-height:56px;resize:vertical;font-size:15px}
button{cursor:pointer;border:0;border-radius:8px;padding:12px 14px;background:#1f7a3a;color:#fff;font-weight:600;min-height:44px;touch-action:manipulation;user-select:none;-webkit-user-select:none}
button:active{transform:scale(.97)}
button.ghost{background:#eef;color:#224}
button.sm{padding:8px 12px;font-size:13px;min-height:36px}
.row{display:flex;gap:8px;flex-wrap:wrap}
.row>*{flex:1 1 140px;min-width:0}
.cat{margin-top:14px;font-weight:700;color:#1f7a3a;border-bottom:2px solid #1f7a3a;padding-bottom:4px;position:sticky;top:56px;background:#fff;z-index:1}
.item{padding:12px 0;border-bottom:1px solid #eee}
.item .t{font-weight:600;margin-bottom:8px;font-size:15px;line-height:1.35}
.rate{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:8px}
.rate button{background:#eef;color:#334;padding:10px 4px;font-weight:700;font-size:13px;line-height:1.15;min-height:52px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.rate button .num{font-size:18px;line-height:1}
.rate button .lbl{font-size:11px;font-weight:600;opacity:.85;margin-top:2px}
.rate button.r0.on{background:#c33;color:#fff}
.rate button.r1.on{background:#e0a020;color:#fff}
.rate button.r2.on{background:#1f7a3a;color:#fff}
.tabs{display:flex;gap:6px;margin-bottom:10px;position:sticky;top:0;background:#f4f6f8;padding:8px 0;z-index:2}
.tabs button{flex:1;background:#dde;color:#223}
.tabs button.active{background:#1f7a3a;color:#fff}
.score{font-size:28px;font-weight:700;color:#1f7a3a}
.hist{padding:12px;border:1px solid #dde;border-radius:8px;margin-bottom:8px;background:#fff;display:flex;justify-content:space-between;align-items:center;gap:8px}
.hist .meta{font-size:12px;color:#456;margin-top:2px}
.pill{display:inline-block;padding:3px 10px;border-radius:99px;background:#1f7a3a;color:#fff;font-size:12px;font-weight:700}
.err{color:#c33;margin-top:8px;font-size:13px}
.hidden{display:none}
.muted{color:#789;font-size:12px}
/* Small phones */
@media (max-width:360px){
  header h1{font-size:14px}
  header .who{font-size:11px}
  .rate button{font-size:12px;padding:8px 2px}
  .rate button .num{font-size:16px}
  .rate button .lbl{display:none}
}
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
    <button data-tab="sum">Summary</button>
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
      <label style="font-weight:600;font-size:14px;color:#1f7a3a">General Notes</label>
      <textarea id="generalNotes" placeholder="Overall observations, action items, follow-ups..." style="min-height:100px"></textarea>
    </div>

    <div class="card">
      <button id="submitBtn">Upload Checklist</button>
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

  <div id="tabSum" class="hidden">
    <div class="card">
      <div class="row">
        <div><label>From</label><input id="sumFrom" type="date"/></div>
        <div><label>To</label><input id="sumTo" type="date"/></div>
        <div><label>Area</label><select id="sumArea"><option value="">All</option></select></div>
        <div><label>Store</label><select id="sumStore"><option value="">All</option></select></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button id="sumApply">Apply</button>
        <button id="sumExport" class="ghost">Export to Excel</button>
      </div>
      <div id="sumMeta" class="muted" style="margin-top:8px"></div>
    </div>
    <div id="sumOut"></div>
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
          <button class="r0 \${r==='0'?'on':''}" onclick="setRate('\${key}','0')"><span class="num">0</span><span class="lbl">Not complied</span></button>
          <button class="r1 \${r==='1'?'on':''}" onclick="setRate('\${key}','1')"><span class="num">1</span><span class="lbl">Needs improvement</span></button>
          <button class="r2 \${r==='2'?'on':''}" onclick="setRate('\${key}','2')"><span class="num">2</span><span class="lbl">Complied</span></button>
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
  const notes = $('#generalNotes').value.trim();
  if (notes) entries.push({ category:'AUDIT NOTES', item:'General Notes', rating:'', remarks: notes });
  const btn = $('#submitBtn'); btn.disabled = true; btn.textContent = 'Uploading...';
  const r = await api('/api/submit', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({manager:S.manager, store, date, entries, auditId:S.editingId})});
  btn.disabled = false; btn.textContent = 'Upload Checklist';
  if (!r.ok) { $('#subErr').textContent = r.error||'Failed'; return; }
  alert('Saved. Audit ID: ' + r.auditId);
  resetForm();
};

$('#resetBtn').onclick = resetForm;
function resetForm(){
  S.ratings = {}; S.remarks = {}; S.editingId = null;
  $('#generalNotes').value = '';
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
  $('#tabSum').classList.toggle('hidden', t!=='sum');
  if (t==='hist') loadHistory();
  if (t==='sum') { if(!$('#sumFrom').value){ const d=new Date(); const to=d.toISOString().slice(0,10); d.setDate(d.getDate()-30); $('#sumFrom').value=d.toISOString().slice(0,10); $('#sumTo').value=to; } loadSummary(); }
});

// ---- Summary ----
let SUM = null;
async function loadSummary(){
  $('#sumOut').innerHTML = '<div class="card muted">Loading...</div>';
  const qs = 'manager=' + encodeURIComponent(S.manager) + '&level=' + encodeURIComponent(S.level||'') +
             '&from=' + encodeURIComponent($('#sumFrom').value||'') + '&to=' + encodeURIComponent($('#sumTo').value||'') +
             '&area=' + encodeURIComponent($('#sumArea').value||'') +
             '&store=' + encodeURIComponent($('#sumStore').value||'');
  const r = await api('/api/summary?' + qs);
  if (!r.ok){ $('#sumOut').innerHTML = '<div class="card err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  SUM = r;
  // Populate area + store dropdowns (keep current selection if still valid)
  const curA = $('#sumArea').value;
  $('#sumArea').innerHTML = '<option value="">All</option>' + r.areas.map(a=>\`<option value="\${escapeHtml(a)}" \${a===curA?'selected':''}>\${escapeHtml(a)}</option>\`).join('');
  const curS = $('#sumStore').value;
  const validStore = r.stores.includes(curS) ? curS : '';
  if (!validStore && curS) $('#sumStore').value = '';
  $('#sumStore').innerHTML = '<option value="">All</option>' + r.stores.map(s=>\`<option value="\${escapeHtml(s)}" \${s===validStore?'selected':''}>\${escapeHtml(s)}</option>\`).join('');
  $('#sumMeta').textContent = \`\${r.auditCount} audits, \${r.itemCount} rated items\`;
  const rowHtml = (rows) => rows.map(x => \`<tr>
    <td>\${escapeHtml(x.name)}\${x.area?' <span class="muted">('+escapeHtml(x.area)+')</span>':''}</td>
    <td style="color:#c33;font-weight:700;text-align:center">\${x.r0}</td>
    <td style="color:#b8860b;font-weight:700;text-align:center">\${x.r1}</td>
    <td style="color:#1f7a3a;font-weight:700;text-align:center">\${x.r2}</td>
    <td style="text-align:center">\${x.total}</td>
    <td style="text-align:right"><span class="pill" style="background:\${x.score>=80?'#1f7a3a':x.score>=50?'#e0a020':'#c33'}">\${x.score}%</span></td>
  </tr>\`).join('');
  const tbl = (title, rows) => \`<div class="card"><h3 style="margin:0 0 8px;color:#1f7a3a">\${title}</h3>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="background:#eef;text-align:left"><th style="padding:6px">Name</th><th style="padding:6px">0</th><th style="padding:6px">1</th><th style="padding:6px">2</th><th style="padding:6px">Total</th><th style="padding:6px;text-align:right">Score</th></tr></thead>
    <tbody>\${rowHtml(rows)}</tbody></table></div></div>\`;
  $('#sumOut').innerHTML =
    (r.perArea.length ? tbl('Summary by Area', r.perArea) : '') +
    (r.perStore.length ? tbl('Summary by Store', r.perStore) : '') +
    (r.allItems.length ? tbl('Item Summary - all particulars (lowest score first)', r.allItems) : '') ||
    '<div class="card muted">No data for this filter.</div>';
}
$('#sumApply').onclick = loadSummary;
$('#sumFrom').onchange = loadSummary;
$('#sumTo').onchange = loadSummary;
$('#sumArea').onchange = () => { $('#sumStore').value=''; loadSummary(); };
$('#sumStore').onchange = loadSummary;

$('#sumExport').onclick = () => {
  if (!SUM){ alert('Load summary first'); return; }
  const store = $('#sumStore').value || 'All Stores';
  const area  = $('#sumArea').value  || 'All Areas';
  const from  = $('#sumFrom').value, to = $('#sumTo').value;
  const dateStr = (from && to) ? (from === to ? from : from + ' to ' + to) : (from || to || 'All dates');
  const scoreBg = s => s>=80 ? '#1f7a3a' : s>=50 ? '#e0a020' : '#c33';
  const storeRowsHtml = SUM.perStore.map(x => \`
    <tr>
      <td style="border:1px solid #b0b0b0;padding:6px 8px"><b>\${escapeHtml(x.name)}</b> <span style="color:#789">(\${escapeHtml(x.area||'')})</span></td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#c33;font-weight:bold">\${x.r0}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#b8860b;font-weight:bold">\${x.r1}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#1f7a3a;font-weight:bold">\${x.r2}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center">\${x.total}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;background:\${scoreBg(x.score)};color:#fff;font-weight:bold">\${x.score}%</td>
    </tr>\`).join('');
  const rowsHtml = SUM.allItems.map(x => \`
    <tr>
      <td style="border:1px solid #b0b0b0;padding:6px 8px">\${escapeHtml(x.name)}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#c33;font-weight:bold">\${x.r0}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#b8860b;font-weight:bold">\${x.r1}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#1f7a3a;font-weight:bold">\${x.r2}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center">\${x.total}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;background:\${scoreBg(x.score)};color:#fff;font-weight:bold">\${x.score}%</td>
    </tr>\`).join('');
  const html = \`<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8">
<xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>Fresh Compliance</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml>
</head><body style="font-family:Calibri,Arial,sans-serif">
  <h1 style="color:#1f7a3a;text-align:center;margin:0 0 12px">Fresh Compliance Result</h1>
  <table style="margin-bottom:14px;font-size:13px">
    <tr><td style="padding:2px 8px;font-weight:bold">Store:</td><td style="padding:2px 8px">\${escapeHtml(store)}</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Area:</td><td style="padding:2px 8px">\${escapeHtml(area)}</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Date:</td><td style="padding:2px 8px">\${escapeHtml(dateStr)}</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Audited by:</td><td style="padding:2px 8px">\${escapeHtml(S.manager)} (\${escapeHtml(S.level)})</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Generated:</td><td style="padding:2px 8px">\${new Date().toLocaleString()}</td></tr>
  </table>
  <table style="border-collapse:collapse;font-size:12px;margin-bottom:14px">
    <thead>
      <tr style="background:#1f7a3a;color:#fff">
        <th style="border:1px solid #b0b0b0;padding:8px;text-align:left;min-width:360px">Store</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:50px">0</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:50px">1</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:50px">2</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:60px">Total</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:70px">Score</th>
      </tr>
    </thead>
    <tbody>\${storeRowsHtml}</tbody>
  </table>
  <table style="border-collapse:collapse;font-size:12px">
    <thead>
      <tr style="background:#1f7a3a;color:#fff">
        <th style="border:1px solid #b0b0b0;padding:8px;text-align:left;min-width:360px">Name</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:50px">0</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:50px">1</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:50px">2</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:60px">Total</th>
        <th style="border:1px solid #b0b0b0;padding:8px;width:70px">Score</th>
      </tr>
    </thead>
    <tbody>\${rowsHtml}</tbody>
  </table>
</body></html>\`;
  const blob = new Blob(['\\ufeff'+html], {type:'application/vnd.ms-excel'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'Fresh_Compliance_Result_' + new Date().toISOString().slice(0,10) + '.xls';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

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
  const noteRow = r.items.find(it => it.category==='AUDIT NOTES' && it.item==='General Notes');
  $('#generalNotes').value = noteRow ? (noteRow.remarks || '') : '';
  // Match items by category+item text
  const key = (c,i)=>c+'||'+i;
  const map = {};
  r.items.forEach(it => map[key(it.category,it.item)] = it);
  S.particulars.forEach((p,i)=>{
    const m = map[key(p.category,p.item)];
    if (m) { if (m.rating!==''&&m.rating!=null) S.ratings['k'+i]=String(m.rating); if (m.remarks) S.remarks['k'+i]=m.remarks; }
  });
  $('#editBanner').classList.remove('hidden');
  document.querySelector('.tabs button[data-tab="new"]').click();
  // Set store/date AFTER tab switch (dropdown must be visible for value to stick reliably)
  const setStore = () => { const opt=[...$('#store').options].find(o=>o.value===r.meta.store); if(opt) $('#store').value=r.meta.store; };
  setStore();
  $('#date').value = r.meta.date;
  renderChecklist();
}

// Auto-login if remembered
const remembered = localStorage.getItem('ff5_mgr');
if (remembered) { S.manager = remembered; S.level = localStorage.getItem('ff5_lvl')||'Area Manager'; enterApp(); }
</script>
</body></html>`;

app.get('/', (req, res) => res.type('html').send(HTML));

app.listen(PORT, () => console.log('Fresh Focus 5 Checklist listening on', PORT));
