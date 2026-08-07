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
    const uLc = (username || '').trim().toLowerCase();
    // 1) AreaManagers
    const rows = await sheetsGet('AreaManagers!A2:C');
    const found = rows.find(
      (r) => (r[0] || '').trim().toLowerCase() === uLc && String(r[1] || '') === String(password || '')
    );
    if (found) {
      const level = (found[2] || 'Area Manager').trim();
      return res.json({ ok: true, manager: found[0], level });
    }
    // 2) StoreManagers: A=Store ID (username), B=Display name, C=Password
    const smRows = await sheetsGet('StoreManagers!A2:C');
    const sm = smRows.find(
      (r) => String(r[0] || '').trim().toLowerCase() === uLc && String(r[2] || '') === String(password || '')
    );
    if (sm) {
      const storeId = String(sm[0] || '').trim();
      const displayName = String(sm[1] || '').trim();
      const stores = await sheetsGet('ListOfStores!A2:G');
      const storeRow = stores.find((r) => String(r[3] || '').trim() === storeId);
      const storeName = storeRow ? (storeRow[4] || '').trim() : displayName || storeId;
      const area = storeRow ? (storeRow[2] || '').trim() : '';
      return res.json({
        ok: true,
        manager: displayName || storeId,
        level: 'Store Manager',
        storeId,
        storeName,
        area,
      });
    }
    return res.json({ ok: false, error: 'Invalid username or password' });
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
    await sheetsAppend('ChecklistData!A1:J1', rows);
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
    const storeFilter = (req.query.store || '').trim();
    const isRegional = level === 'regional manager';
    const isStoreMgr = level === 'store manager';
    const rows = await sheetsGet('ChecklistData!A2:J');
    const map = new Map();
    rows.forEach((r) => {
      if ((r[9] || 'ACTIVE') !== 'ACTIVE') return;
      if (storeFilter && (r[3] || '').trim().toLowerCase() !== storeFilter.toLowerCase()) return;
      if (!isRegional && !isStoreMgr && manager && (r[2] || '').trim().toLowerCase() !== manager) return;
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
    const isStoreMgr = level === 'store manager';

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
      if (!isRegional && !isStoreMgr && !managerAreas.has(areaOfRow)) return false;
      if (areaFilter && areaOfRow !== areaFilter) return false;
      if (storeFilter && (r[3] || '').trim().toLowerCase() !== storeFilter.toLowerCase()) return false;
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

// ---------- Store Manager (Y/N 3x-daily) ----------
async function markStoreEdited(auditId, store, date, slot) {
  const rows = await sheetsGet('StoreChecklistData!A2:K');
  const data = [];
  rows.forEach((r, i) => {
    const isActive = (r[10] || 'ACTIVE') === 'ACTIVE';
    if (!isActive) return;
    // Match by auditId OR by same store+date+slot (replace prior slot submission)
    const match = auditId
      ? r[1] === auditId
      : (r[3] === store && r[4] === date && r[5] === slot);
    if (match) data.push({ range: `StoreChecklistData!K${i + 2}`, values: [['EDITED']] });
  });
  if (data.length) await sheetsBatchUpdateValues(data);
}

app.post('/api/store-submit', async (req, res) => {
  try {
    const { login, store, date, slot, entries, auditId, generalNotes } = req.body || {};
    if (!login || !store || !date || !slot || !Array.isArray(entries) || !entries.length) {
      return res.json({ ok: false, error: 'Missing fields' });
    }
    if (!['8AM','12PM','3PM'].includes(slot)) return res.json({ ok:false, error:'Invalid slot' });
    const ts = new Date().toISOString();
    const id = auditId || 'S' + Date.now();
    // Supersede any earlier active submission for same store/date/slot (or the same auditId when editing)
    await markStoreEdited(auditId, store, date, slot);
    const rows = entries.map((e) => [
      ts, id, login, store, date, slot,
      e.category || '', e.item || '',
      String(e.result || ''),
      e.remarks || '',
      'ACTIVE',
    ]);
    if (generalNotes && generalNotes.trim()) {
      rows.push([ts, id, login, store, date, slot, 'AUDIT NOTES', 'General Notes', '', generalNotes.trim(), 'ACTIVE']);
    }
    await sheetsAppend('StoreChecklistData!A1:K1', rows);
    res.json({ ok: true, auditId: id });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/store-history', async (req, res) => {
  try {
    const store = (req.query.store || '').trim();
    const from = (req.query.from || '').trim();
    const to = (req.query.to || '').trim();
    const rows = await sheetsGet('StoreChecklistData!A2:K');
    const map = new Map();
    rows.forEach((r) => {
      if ((r[10] || 'ACTIVE') !== 'ACTIVE') return;
      if (store && r[3] !== store) return;
      if (from && (r[4] || '') < from) return;
      if (to && (r[4] || '') > to) return;
      const id = r[1];
      if (!id) return;
      if (!map.has(id)) {
        map.set(id, { auditId: id, timestamp: r[0], login: r[2], store: r[3], date: r[4], slot: r[5], y: 0, n: 0, total: 0 });
      }
      const a = map.get(id);
      if (r[6] === 'AUDIT NOTES') return;
      const result = String(r[8] || '').toUpperCase();
      if (result === 'Y') a.y++;
      else if (result === 'N') a.n++;
      a.total++;
    });
    const list = [...map.values()].map((a) => ({
      ...a,
      pass: a.total ? Math.round((a.y / a.total) * 100) : 0,
    }));
    list.sort((a, b) => (b.date + b.slot).localeCompare(a.date + a.slot));
    res.json({ ok: true, audits: list });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/store-audit/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const rows = await sheetsGet('StoreChecklistData!A2:K');
    const entries = rows.filter((r) => r[1] === id && (r[10] || 'ACTIVE') === 'ACTIVE');
    if (!entries.length) return res.json({ ok: false, error: 'Not found' });
    const meta = { auditId: id, login: entries[0][2], store: entries[0][3], date: entries[0][4], slot: entries[0][5] };
    const items = entries.map((r) => ({ category: r[6], item: r[7], result: r[8], remarks: r[9] }));
    res.json({ ok: true, meta, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/store-compliance', async (req, res) => {
  try {
    const store = (req.query.store || '').trim();
    const rows = await sheetsGet('StoreChecklistData!A2:K');
    // per date -> per slot -> {y,total}
    const byDate = {};
    rows.forEach((r) => {
      if ((r[10] || 'ACTIVE') !== 'ACTIVE') return;
      if (store && (r[3] || '').trim().toLowerCase() !== store.toLowerCase()) return;
      const d = r[4]; if (!d) return;
      const slot = r[5];
      if (!byDate[d]) byDate[d] = {};
      if (!byDate[d][slot]) byDate[d][slot] = { y: 0, n: 0, total: 0 };
      if (r[6] === 'AUDIT NOTES') return;
      const result = String(r[8] || '').toUpperCase();
      if (result === 'Y') byDate[d][slot].y++;
      else if (result === 'N') byDate[d][slot].n++;
      byDate[d][slot].total++;
    });
    // Return raw per-date data; frontend decides PENDING/MISSED based on local time
    const out = Object.keys(byDate).sort().reverse().map((d) => ({
      date: d,
      slots: ['8AM', '12PM', '3PM'].map((s) => {
        const v = byDate[d][s];
        if (!v) return { slot: s, done: false };
        return { slot: s, done: true, pass: v.total ? Math.round((v.y / v.total) * 100) : 0, y: v.y, total: v.total };
      }),
    }));
    res.json({ ok: true, days: out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/store-checks-monitor', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    const level = (req.query.level || '').trim().toLowerCase();
    const from = (req.query.from || '').trim();
    const to = (req.query.to || '').trim();
    const areaFilter = (req.query.area || '').trim();
    const storeFilter = (req.query.store || '').trim();
    const isRegional = level === 'regional manager';
    const isStoreMgr = level === 'store manager';

    const stores = await sheetsGet('ListOfStores!A2:G');
    const storeMap = {};
    const managerAreas = new Set();
    stores.forEach((r) => {
      const storeName = r[4], areaName = r[2] || '(no area)', mgr = r[6] || '';
      if (!storeName) return;
      storeMap[storeName] = { area: areaName };
      if (mgr.trim().toLowerCase() === manager) managerAreas.add(areaName);
    });
    const allowedAreas = isRegional
      ? [...new Set(stores.map((r) => r[2] || '(no area)').filter(Boolean))]
      : [...managerAreas];
    const allowedStores = stores
      .filter((r) => {
        const areaName = r[2] || '(no area)';
        if (!isRegional && (r[6] || '').trim().toLowerCase() !== manager) return false;
        if (areaFilter && areaName !== areaFilter) return false;
        return !!r[4];
      })
      .map((r) => r[4]);

    const data = await sheetsGet('StoreChecklistData!A2:K');
    const rows = data.filter((r) => {
      if ((r[10] || 'ACTIVE') !== 'ACTIVE') return false;
      if (from && (r[4] || '') < from) return false;
      if (to && (r[4] || '') > to) return false;
      const areaOfRow = (storeMap[r[3]] || {}).area || '(unknown)';
      if (!isRegional && !isStoreMgr && !managerAreas.has(areaOfRow)) return false;
      if (areaFilter && areaOfRow !== areaFilter) return false;
      if (storeFilter && r[3] !== storeFilter) return false;
      return true;
    });

    // per-store: distinct (date,slot) submitted / (unique date × 3)
    const perStore = {};
    const perItem = {};
    const slotSet = {}; // store -> set of "date|slot"
    const dateSet = {}; // store -> set of dates
    rows.forEach((r) => {
      const store = r[3] || '(unknown)';
      const areaOfRow = (storeMap[store] || {}).area || '(unknown)';
      const d = r[4] || '', slot = r[5] || '';
      slotSet[store] = slotSet[store] || new Set();
      dateSet[store] = dateSet[store] || new Set();
      if (d) dateSet[store].add(d);
      if (d && slot) slotSet[store].add(d + '|' + slot);
      if (r[6] === 'AUDIT NOTES') return;
      if (!perStore[store]) perStore[store] = { y: 0, n: 0, total: 0, area: areaOfRow };
      const s = perStore[store];
      const result = String(r[8] || '').toUpperCase();
      if (result === 'Y') s.y++;
      else if (result === 'N') s.n++;
      s.total++;
      const itemKey = (r[6] || '') + ' | ' + (r[7] || '');
      const it = perItem[itemKey] = perItem[itemKey] || { y: 0, n: 0, total: 0 };
      if (result === 'Y') it.y++;
      else if (result === 'N') it.n++;
      it.total++;
    });

    const perStoreArr = Object.entries(perStore).map(([name, v]) => {
      const dates = dateSet[name] ? dateSet[name].size : 0;
      const slotsDone = slotSet[name] ? slotSet[name].size : 0;
      const slotCompliance = dates ? Math.round((slotsDone / (dates * 3)) * 100) : 0;
      const pass = v.total ? Math.round((v.y / v.total) * 100) : 0;
      return { name, area: v.area, y: v.y, n: v.n, total: v.total, slotCompliance, pass, dates, slotsDone };
    }).sort((a, b) => (a.area || '').localeCompare(b.area || '') || a.name.localeCompare(b.name));

    const perItemArr = Object.entries(perItem).map(([name, v]) => ({
      name, y: v.y, n: v.n, total: v.total, pass: v.total ? Math.round((v.y / v.total) * 100) : 0,
    })).sort((a, b) => a.pass - b.pass);

    // Per-store per-day slot breakdown for consolidated Compliance Log
    const byStoreDate = {}; // "store||date" -> { store, date, slots:{8AM:{y,total},...} }
    rows.forEach((r) => {
      const store = r[3] || '(unknown)';
      const d = r[4] || '', slot = r[5] || '';
      if (!d || !slot) return;
      const k = store + '||' + d;
      if (!byStoreDate[k]) byStoreDate[k] = { store, date: d, slots: {} };
      const bucket = byStoreDate[k].slots[slot] = byStoreDate[k].slots[slot] || { y: 0, n: 0, total: 0 };
      if (r[6] === 'AUDIT NOTES') return;
      const result = String(r[8] || '').toUpperCase();
      if (result === 'Y') bucket.y++;
      else if (result === 'N') bucket.n++;
      bucket.total++;
    });
    const perDay = Object.values(byStoreDate).map((d) => ({
      store: d.store,
      date: d.date,
      slots: ['8AM', '12PM', '3PM'].map((s) => {
        const v = d.slots[s];
        if (!v) return { slot: s, done: false };
        return { slot: s, done: true, pass: v.total ? Math.round((v.y / v.total) * 100) : 0, y: v.y, total: v.total };
      }),
    })).sort((a, b) => b.date.localeCompare(a.date) || a.store.localeCompare(b.store));

    res.json({
      ok: true,
      areas: allowedAreas.sort(),
      stores: [...new Set(allowedStores)].sort(),
      perStore: perStoreArr,
      perItem: perItemArr,
      perDay: perDay,
      auditCount: new Set(rows.map((r) => r[1])).size,
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
    <button data-tab="hist">AM Check History</button>
    <button data-tab="sum">AM Check Summary</button>
    <button data-tab="mon">Store Checks</button>
    <button data-tab="scheck">Store Check</button>
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

  <div id="tabMon" class="hidden">
    <div class="card">
      <div class="row">
        <div><label>From</label><input id="monFrom" type="date"/></div>
        <div><label>To</label><input id="monTo" type="date"/></div>
        <div><label>Area</label><select id="monArea"><option value="">All</option></select></div>
        <div><label>Store</label><select id="monStore"><option value="">All</option></select></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button id="monApply">Apply</button>
        <button id="monExport" class="ghost">Export to Excel</button>
      </div>
      <div id="monMeta" class="muted" style="margin-top:8px"></div>
    </div>
    <div id="monOut"></div>
  </div>

  <div id="tabSCheck" class="hidden">
    <div class="tabs" style="top:56px">
      <button data-subtab="new" class="active">New Check</button>
      <button data-subtab="hist">Store Check History</button>
      <button data-subtab="clog">Compliance Log</button>
    </div>

    <div id="scSubNew">
    <div class="card">
      <div style="font-weight:600;color:#1f7a3a">Store: <span id="scStoreLbl"></span></div>
      <div style="margin-top:8px" class="row">
        <div><label>Date</label><input id="scDate" type="date"/></div>
        <div>
          <label>Slot</label>
          <div style="display:flex;gap:6px">
            <button type="button" class="ghost sm" data-slot="8AM">8AM</button>
            <button type="button" class="ghost sm" data-slot="12PM">12PM</button>
            <button type="button" class="ghost sm" data-slot="3PM">3PM</button>
          </div>
        </div>
      </div>
      <div class="muted" style="margin-top:6px">Current slot: <b id="scSlotLbl">-</b> - Pass rate: <span id="scScore" class="score" style="font-size:22px">0%</span> <span id="scScoreDetail"></span></div>
      <div id="scWindowMsg" style="margin-top:8px;font-size:13px"></div>
      <div style="margin-top:8px;padding:8px 10px;background:#eef7ff;border-left:3px solid #1f7a3a;font-size:12px;line-height:1.5;color:#345">
        <b>Submission windows (open 1 hour before, close at deadline):</b><br>
        &bull; 8AM: 07:00 - 09:00 (deadline 9AM)<br>
        &bull; 12PM: 11:00 - 13:00 (deadline 1PM)<br>
        &bull; 3PM: 14:00 - 16:00 (deadline 4PM)
      </div>
    </div>

    <div id="scChecklist" class="card">Loading items...</div>

    <div class="card">
      <label style="font-weight:600;font-size:14px;color:#1f7a3a">General Notes</label>
      <textarea id="scNotes" placeholder="Overall observations..." style="min-height:80px"></textarea>
    </div>

    <div class="card">
      <button id="scSubmit">Upload Store Check</button>
      <button id="scReset" class="ghost" style="margin-left:8px">Reset</button>
      <div id="scErr" class="err"></div>
    </div>
    </div>

    <div id="scSubHist" class="hidden">
      <div class="card">
        <button id="schReload" class="ghost sm">Refresh</button>
        <div id="schList" style="margin-top:10px">Loading...</div>
      </div>
    </div>

    <div id="scSubClog" class="hidden">
      <div class="card">
        <div style="font-weight:600;color:#1f7a3a">Store: <span id="clStoreLbl"></span></div>
        <div class="muted" style="margin-top:4px">Last 14 days - 3 slots per day (8AM, 12PM, 3PM)</div>
        <button id="clReload" class="ghost sm" style="margin-top:8px">Refresh</button>
      </div>
      <div id="clOut"></div>
    </div>
  </div>
</div>

</main>

<script>
const S = { manager:null, level:null, storeId:null, storeName:null, particulars:[], ratings:{}, remarks:{}, editingId:null,
            scResults:{}, scRemarks:{}, scSlot:null, scEditingId:null };

function $(q){return document.querySelector(q)}
function api(url, opts){ return fetch(url, opts).then(r=>r.json()) }

// ---- Login ----
$('#loginBtn').onclick = async () => {
  const u = $('#lu').value.trim(), p = $('#lp').value;
  $('#loginErr').textContent = '';
  const r = await api('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u,password:p})});
  if (!r.ok) { $('#loginErr').textContent = r.error || 'Login failed'; return; }
  S.manager = r.manager; S.level = r.level || 'Area Manager';
  S.storeId = r.storeId || null; S.storeName = r.storeName || null;
  localStorage.setItem('ff5_mgr', r.manager);
  localStorage.setItem('ff5_lvl', S.level);
  if (S.storeId) localStorage.setItem('ff5_sid', S.storeId); else localStorage.removeItem('ff5_sid');
  if (S.storeName) localStorage.setItem('ff5_sname', S.storeName); else localStorage.removeItem('ff5_sname');
  await enterApp();
};

$('#logoutBtn').onclick = () => { ['ff5_mgr','ff5_lvl','ff5_sid','ff5_sname'].forEach(k=>localStorage.removeItem(k)); location.reload(); };

async function enterApp(){
  $('#loginScreen').classList.add('hidden');
  $('#appScreen').classList.remove('hidden');
  $('#logoutBtn').classList.remove('hidden');
  $('#whoName').textContent = S.manager + ' (' + S.level + ')';
  $('#date').value = new Date().toISOString().slice(0,10);
  applyRoleUI();
  await loadParticulars();
  const isStoreMgr = (S.level||'').toLowerCase() === 'store manager';
  if (isStoreMgr) {
    $('#scStoreLbl').textContent = S.storeName || '';
    $('#clStoreLbl').textContent = S.storeName || '';
    $('#scDate').value = new Date().toISOString().slice(0,10);
    S.scSlot = autoSlot();
    highlightSlotBtn();
    $('#scSlotLbl').textContent = S.scSlot;
    renderStoreCheck();
    // Open Store Check by default
    document.querySelector('.tabs button[data-tab="scheck"]').click();
  } else {
    await loadStores();
    renderChecklist();
  }
}

function applyRoleUI(){
  const isStoreMgr = (S.level||'').toLowerCase() === 'store manager';
  // Hide/show tabs by role
  const show = (sel, on) => document.querySelector(sel) && document.querySelector(sel).classList.toggle('hidden', !on);
  show('.tabs button[data-tab="new"]',  !isStoreMgr);
  show('.tabs button[data-tab="hist"]', true);
  show('.tabs button[data-tab="sum"]',  true);
  show('.tabs button[data-tab="mon"]',  !isStoreMgr);
  show('.tabs button[data-tab="scheck"]', isStoreMgr);
}

// Slot windows: earliest .. deadline (local time hours, 24h)
const SLOT_WINDOWS = { '8AM': [7,9], '12PM': [11,13], '3PM': [14,16] };
function slotOpen(slot){
  const now = new Date();
  const mins = now.getHours()*60 + now.getMinutes();
  const [s,e] = SLOT_WINDOWS[slot];
  return mins >= s*60 && mins < e*60;
}
function autoSlot(){
  // Pick the slot whose window is currently open; fallback to nearest by time
  for (const s of ['8AM','12PM','3PM']) if (slotOpen(s)) return s;
  const h = new Date().getHours();
  if (h < 7) return '8AM';
  if (h < 11) return '8AM';
  if (h < 14) return '12PM';
  return '3PM';
}
function highlightSlotBtn(){
  document.querySelectorAll('#tabSCheck button[data-slot]').forEach(b => {
    const open = slotOpen(b.dataset.slot);
    b.classList.toggle('active', b.dataset.slot === S.scSlot);
    b.style.background = b.dataset.slot === S.scSlot ? '#1f7a3a' : '';
    b.style.color = b.dataset.slot === S.scSlot ? '#fff' : '';
    b.disabled = !open;
    b.style.opacity = open ? '1' : '0.4';
    b.style.cursor = open ? 'pointer' : 'not-allowed';
    b.title = open ? '' : ('Opens ' + SLOT_WINDOWS[b.dataset.slot][0] + ':00, closes ' + SLOT_WINDOWS[b.dataset.slot][1] + ':00');
  });
  // Update submit button + status message
  const anyOpen = ['8AM','12PM','3PM'].some(slotOpen);
  const canSubmit = anyOpen && slotOpen(S.scSlot);
  const btn = $('#scSubmit');
  if (btn){ btn.disabled = !canSubmit; btn.style.opacity = canSubmit?'1':'0.5'; btn.style.cursor = canSubmit?'pointer':'not-allowed'; }
  const msg = $('#scWindowMsg');
  if (msg){
    if (!anyOpen) msg.innerHTML = '<span style="color:#c33;font-weight:600">No slot window is currently open. Windows: 8AM 07:00-09:00, 12PM 11:00-13:00, 3PM 14:00-16:00.</span>';
    else if (!slotOpen(S.scSlot)) msg.innerHTML = '<span style="color:#c33;font-weight:600">Selected slot is not open now. Switch to the highlighted slot.</span>';
    else msg.innerHTML = '<span style="color:#1f7a3a">Slot ' + S.scSlot + ' is open. Deadline ' + SLOT_WINDOWS[S.scSlot][1] + ':00.</span>';
  }
}
document.querySelectorAll('#tabSCheck button[data-slot]').forEach(b => b.onclick = () => {
  if (b.disabled) return;
  S.scSlot = b.dataset.slot; $('#scSlotLbl').textContent = S.scSlot; highlightSlotBtn();
});
// Re-evaluate slot state every 60s so the UI updates when windows open/close
setInterval(() => { if (!$('#tabSCheck').classList.contains('hidden')) { const auto=autoSlot(); if (slotOpen(auto)) { S.scSlot=auto; $('#scSlotLbl').textContent=S.scSlot; } highlightSlotBtn(); } }, 60000);

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
  $('#tabMon').classList.toggle('hidden', t!=='mon');
  $('#tabSCheck').classList.toggle('hidden', t!=='scheck');
  if (t==='hist') loadHistory();
  if (t==='sum') { if(!$('#sumFrom').value){ const d=new Date(); const to=d.toISOString().slice(0,10); d.setDate(d.getDate()-30); $('#sumFrom').value=d.toISOString().slice(0,10); $('#sumTo').value=to; } loadSummary(); }
  if (t==='mon') { if(!$('#monFrom').value){ const d=new Date(); const to=d.toISOString().slice(0,10); d.setDate(d.getDate()-14); $('#monFrom').value=d.toISOString().slice(0,10); $('#monTo').value=to; } loadMonitor(); }
});

// Sub-tabs within Store Check
document.querySelectorAll('#tabSCheck .tabs button[data-subtab]').forEach(b => b.onclick = () => {
  document.querySelectorAll('#tabSCheck .tabs button[data-subtab]').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
  const st = b.dataset.subtab;
  $('#scSubNew').classList.toggle('hidden', st!=='new');
  $('#scSubHist').classList.toggle('hidden', st!=='hist');
  $('#scSubClog').classList.toggle('hidden', st!=='clog');
  if (st==='hist') loadStoreCheckHistory();
  if (st==='clog') loadCompliance();
});

async function loadStoreCheckHistory(){
  $('#schList').textContent = 'Loading...';
  const r = await api('/api/store-history?store=' + encodeURIComponent(S.storeName||''));
  if (!r.ok){ $('#schList').innerHTML = '<div class="err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  if (!r.audits.length){ $('#schList').textContent = 'No store checks yet.'; return; }
  const bg = p => p>=80?'#1f7a3a':p>=50?'#e0a020':'#c33';
  $('#schList').innerHTML = r.audits.map(a => \`<div class="hist" style="align-items:flex-start">
    <div style="flex:1">
      <div><b>\${escapeHtml(a.date)}</b> - <span class="pill" style="background:#334;font-size:11px">\${escapeHtml(a.slot||'')}</span></div>
      <div class="meta">\${new Date(a.timestamp).toLocaleString()} - Pass \${a.y}/\${a.total}, Fail \${a.n}</div>
      <div id="det_\${a.auditId}" style="margin-top:8px;display:none"></div>
    </div>
    <div style="text-align:right">
      <span class="pill" style="background:\${bg(a.pass)}">\${a.pass}%</span>
      <div style="margin-top:6px"><button class="sm ghost" onclick="toggleStoreAudit('\${a.auditId}')">View</button></div>
    </div>
  </div>\`).join('');
}
$('#schReload') && ($('#schReload').onclick = loadStoreCheckHistory);

// ---- Summary ----
let SUM = null;
async function loadSummary(){
  $('#sumOut').innerHTML = '<div class="card muted">Loading...</div>';
  const qs = 'manager=' + encodeURIComponent(S.manager) + '&level=' + encodeURIComponent(S.level||'') +
             '&from=' + encodeURIComponent($('#sumFrom').value||'') + '&to=' + encodeURIComponent($('#sumTo').value||'') +
             '&area=' + encodeURIComponent($('#sumArea').value||'') +
             '&store=' + encodeURIComponent(((S.level||'').toLowerCase()==='store manager' && S.storeName) ? S.storeName : ($('#sumStore').value||''));
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
    <thead><tr style="background:#eef"><th style="padding:6px;text-align:left">Name</th><th style="padding:6px;text-align:center;width:50px">0</th><th style="padding:6px;text-align:center;width:50px">1</th><th style="padding:6px;text-align:center;width:50px">2</th><th style="padding:6px;text-align:center;width:60px">Total</th><th style="padding:6px;text-align:right;width:80px">Score</th></tr></thead>
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
  const storeQ = ((S.level||'').toLowerCase()==='store manager' && S.storeName) ? '&store=' + encodeURIComponent(S.storeName) : '';
  const r = await api('/api/history?manager=' + encodeURIComponent(S.manager) + '&level=' + encodeURIComponent(S.level||'') + storeQ);
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
        <div style="margin-top:6px" class="\${(S.level||'').toLowerCase()==='store manager'?'hidden':''}"><button class="sm ghost" onclick="editAudit('\${a.auditId}')">Edit</button></div>
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

// ---- Store Check (Y/N) ----
function renderStoreCheck(){
  const groups = {};
  S.particulars.forEach((p,i) => { (groups[p.category] = groups[p.category] || []).push({...p,i}); });
  const html = Object.keys(groups).map(cat => {
    const items = groups[cat].map(it => {
      const key = 'k'+it.i;
      const r = S.scResults[key];
      return \`<div class="item">
        <div class="t">\${escapeHtml(it.item)}</div>
        <div class="rate" style="grid-template-columns:1fr 1fr">
          <button class="r2 \${r==='Y'?'on':''}" onclick="setResult('\${key}','Y')"><span class="num">&#10004;</span><span class="lbl">Pass</span></button>
          <button class="r0 \${r==='N'?'on':''}" onclick="setResult('\${key}','N')"><span class="num">&#10008;</span><span class="lbl">Fail</span></button>
        </div>
        <textarea placeholder="Remarks (optional)" oninput="S.scRemarks['\${key}']=this.value">\${escapeHtml(S.scRemarks[key]||'')}</textarea>
      </div>\`;
    }).join('');
    return \`<div class="cat">\${escapeHtml(cat)}</div>\${items}\`;
  }).join('');
  $('#scChecklist').innerHTML = html || '<div class="muted">No items.</div>';
  updateScScore();
}
function setResult(key, val){ S.scResults[key] = val; renderStoreCheck(); }
function updateScScore(){
  let y=0, total=0;
  Object.values(S.scResults).forEach(v => { if(v==='Y'){y++;total++;} else if(v==='N'){total++;} });
  const pct = total ? Math.round(y/total*100) : 0;
  $('#scScore').textContent = pct + '%';
  $('#scScoreDetail').textContent = \` (\${total}/\${S.particulars.length} rated)\`;
}
$('#scSubmit').onclick = async () => {
  $('#scErr').textContent = '';
  const date = $('#scDate').value;
  if (!date || !S.scSlot) { $('#scErr').textContent = 'Date and slot required'; return; }
  const entries = S.particulars.map((p,i) => ({ category:p.category, item:p.item, result:S.scResults['k'+i]||'', remarks:S.scRemarks['k'+i]||'' }));
  const btn = $('#scSubmit'); btn.disabled = true; btn.textContent = 'Uploading...';
  const r = await api('/api/store-submit', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ login:S.manager, store:S.storeName, date, slot:S.scSlot, entries, auditId:S.scEditingId, generalNotes:$('#scNotes').value })});
  btn.disabled = false; btn.textContent = 'Upload Store Check';
  if (!r.ok) { $('#scErr').textContent = r.error||'Failed'; return; }
  alert('Store check saved. ID: ' + r.auditId);
  scResetForm();
};
$('#scReset').onclick = scResetForm;
function scResetForm(){
  S.scResults = {}; S.scRemarks = {}; S.scEditingId = null;
  $('#scNotes').value = '';
  renderStoreCheck();
}

// ---- Compliance Log ----
async function loadCompliance(){
  $('#clOut').innerHTML = '<div class="card muted">Loading...</div>';
  const r = await api('/api/store-compliance?store=' + encodeURIComponent(S.storeName||''));
  if (!r.ok){ $('#clOut').innerHTML = '<div class="card err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  // Compute local "today"
  const now = new Date();
  const today = now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(now.getDate()).padStart(2,'0');
  const mins = now.getHours()*60 + now.getMinutes();
  // Ensure today is included even if no submissions
  const daysMap = new Map();
  r.days.forEach(d => daysMap.set(d.date, d));
  if (!daysMap.has(today)) daysMap.set(today, { date: today, slots: ['8AM','12PM','3PM'].map(s => ({slot:s, done:false})) });
  const days = [...daysMap.values()].sort((a,b) => b.date.localeCompare(a.date));
  const slotDeadline = { '8AM':9*60, '12PM':13*60, '3PM':16*60 };
  const rows = days.map(d => {
    let expected = 0, doneCount = 0;
    const cells = d.slots.map(s => {
      const isToday = d.date === today;
      const deadlinePassed = isToday ? (mins >= slotDeadline[s.slot]) : (d.date < today);
      if (s.done) { doneCount++; expected++; const bg = s.pass>=80?'#e8f5ec':s.pass>=50?'#fff5e0':'#fee'; const col = s.pass>=80?'#1f7a3a':s.pass>=50?'#b8860b':'#c33';
        return \`<td style="text-align:center;background:\${bg};color:\${col};font-weight:700;padding:8px;border:1px solid #eee">\${s.pass}% (\${s.y}/\${s.total})</td>\`;
      }
      if (deadlinePassed) { expected++; return \`<td style="text-align:center;background:#fee;color:#c33;font-weight:700;padding:8px;border:1px solid #eee">MISSED</td>\`; }
      return \`<td style="text-align:center;background:#f2f2f2;color:#789;font-weight:600;padding:8px;border:1px solid #eee">PENDING</td>\`;
    }).join('');
    const slotPct = expected ? Math.round((doneCount/expected)*100) : 0;
    const compBg = expected===0 ? '#789' : (doneCount===expected ? '#1f7a3a' : doneCount>0 ? '#e0a020' : '#c33');
    const compTxt = expected===0 ? '-' : (slotPct + '%');
    return \`<tr>
      <td style="padding:8px;border:1px solid #eee;font-weight:600">\${d.date}\${d.date===today?' <span class="muted">(today)</span>':''}</td>
      \${cells}
      <td style="text-align:center;padding:8px;border:1px solid #eee"><span class="pill" style="background:\${compBg}">\${compTxt}</span></td>
    </tr>\`;
  }).join('');
  $('#clOut').innerHTML = \`<div class="card"><div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="background:#eef"><th style="padding:8px;text-align:left">Date</th><th style="padding:8px">8AM</th><th style="padding:8px">12PM</th><th style="padding:8px">3PM</th><th style="padding:8px">Slot %</th></tr></thead>
    <tbody>\${rows}</tbody></table></div></div>\`;
}
$('#clReload').onclick = loadCompliance;

// ---- Store Checks Monitor (Area/Regional) ----
let MON = null;
async function loadMonitor(){
  $('#monOut').innerHTML = '<div class="card muted">Loading...</div>';
  const qs = 'manager=' + encodeURIComponent(S.manager) + '&level=' + encodeURIComponent(S.level||'') +
             '&from=' + encodeURIComponent($('#monFrom').value||'') + '&to=' + encodeURIComponent($('#monTo').value||'') +
             '&area=' + encodeURIComponent($('#monArea').value||'') + '&store=' + encodeURIComponent($('#monStore').value||'');
  const r = await api('/api/store-checks-monitor?' + qs);
  if (!r.ok){ $('#monOut').innerHTML = '<div class="card err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  MON = r;
  const curA = $('#monArea').value;
  $('#monArea').innerHTML = '<option value="">All</option>' + r.areas.map(a=>\`<option value="\${escapeHtml(a)}" \${a===curA?'selected':''}>\${escapeHtml(a)}</option>\`).join('');
  const curS = $('#monStore').value;
  const validStore = r.stores.includes(curS) ? curS : '';
  if (!validStore && curS) $('#monStore').value = '';
  $('#monStore').innerHTML = '<option value="">All</option>' + r.stores.map(s=>\`<option value="\${escapeHtml(s)}" \${s===validStore?'selected':''}>\${escapeHtml(s)}</option>\`).join('');
  $('#monMeta').textContent = \`\${r.auditCount} store checks\`;
  const bg = p => p>=80?'#1f7a3a':p>=50?'#e0a020':'#c33';
  const storeRows = r.perStore.map(x => \`<tr>
    <td style="padding:6px 8px;border:1px solid #eee">\${escapeHtml(x.name)} <span class="muted">(\${escapeHtml(x.area||'')})</span></td>
    <td style="padding:6px;border:1px solid #eee;text-align:center">\${x.slotsDone}/\${x.dates*3} <span class="pill" style="background:\${bg(x.slotCompliance)};margin-left:4px">\${x.slotCompliance}%</span></td>
    <td style="padding:6px;border:1px solid #eee;text-align:center;color:#1f7a3a;font-weight:700">\${x.y}</td>
    <td style="padding:6px;border:1px solid #eee;text-align:center;color:#c33;font-weight:700">\${x.n}</td>
    <td style="padding:6px;border:1px solid #eee;text-align:center">\${x.total}</td>
    <td style="padding:6px;border:1px solid #eee;text-align:right"><span class="pill" style="background:\${bg(x.pass)}">\${x.pass}%</span></td>
  </tr>\`).join('');
  const itemRows = r.perItem.map(x => \`<tr>
    <td style="padding:6px 8px;border:1px solid #eee">\${escapeHtml(x.name)}</td>
    <td style="padding:6px;border:1px solid #eee;text-align:center;color:#1f7a3a;font-weight:700">\${x.y}</td>
    <td style="padding:6px;border:1px solid #eee;text-align:center;color:#c33;font-weight:700">\${x.n}</td>
    <td style="padding:6px;border:1px solid #eee;text-align:center">\${x.total}</td>
    <td style="padding:6px;border:1px solid #eee;text-align:right"><span class="pill" style="background:\${bg(x.pass)}">\${x.pass}%</span></td>
  </tr>\`).join('');
  // Per-store detail sections (only when a store is filtered)
  let detailHtml = '';
  const selStore = $('#monStore').value;
  if (selStore) {
    detailHtml = \`<div id="monRecent" class="card"><h3 style="margin:0 0 8px;color:#1f7a3a">Recent Submissions - \${escapeHtml(selStore)}</h3><div class="muted">Loading...</div></div>\`;
  }
  // Consolidated Compliance Log (all stores in scope, per day)
  const nowM = new Date();
  const todayM = nowM.getFullYear()+'-'+String(nowM.getMonth()+1).padStart(2,'0')+'-'+String(nowM.getDate()).padStart(2,'0');
  const minsM = nowM.getHours()*60 + nowM.getMinutes();
  const slotDeadlineM = { '8AM':9*60, '12PM':13*60, '3PM':16*60 };
  const perDayRows = (r.perDay||[]).map(d => {
    let expected=0, doneCount=0;
    const cells = d.slots.map(s => {
      const isToday = d.date === todayM;
      const deadlinePassed = isToday ? (minsM >= slotDeadlineM[s.slot]) : (d.date < todayM);
      if (s.done){ doneCount++; expected++; const cbg=s.pass>=80?'#e8f5ec':s.pass>=50?'#fff5e0':'#fee'; const col=s.pass>=80?'#1f7a3a':s.pass>=50?'#b8860b':'#c33';
        return \`<td style="text-align:center;background:\${cbg};color:\${col};font-weight:700;padding:6px;border:1px solid #eee">\${s.pass}% (\${s.y}/\${s.total})</td>\`;
      }
      if (deadlinePassed){ expected++; return \`<td style="text-align:center;background:#fee;color:#c33;font-weight:700;padding:6px;border:1px solid #eee">MISSED</td>\`; }
      return \`<td style="text-align:center;background:#f2f2f2;color:#789;font-weight:600;padding:6px;border:1px solid #eee">PENDING</td>\`;
    }).join('');
    const pct = expected ? Math.round((doneCount/expected)*100) : 0;
    const compBg = expected===0 ? '#789' : (doneCount===expected ? '#1f7a3a' : doneCount>0 ? '#e0a020' : '#c33');
    const compTxt = expected===0 ? '-' : (pct + '%');
    return \`<tr><td style="padding:6px;border:1px solid #eee;font-weight:600">\${escapeHtml(d.store)}</td><td style="padding:6px;border:1px solid #eee">\${d.date}\${d.date===todayM?' <span class="muted">(today)</span>':''}</td>\${cells}<td style="text-align:center;padding:6px;border:1px solid #eee"><span class="pill" style="background:\${compBg}">\${compTxt}</span></td></tr>\`;
  }).join('');
  const compLogCard = \`<div class="card"><h3 style="margin:0 0 8px;color:#1f7a3a">Compliance Log</h3>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="background:#eef"><th style="padding:6px;text-align:left">Store</th><th style="padding:6px;text-align:left">Date</th><th style="padding:6px;text-align:center">8AM</th><th style="padding:6px;text-align:center">12PM</th><th style="padding:6px;text-align:center">3PM</th><th style="padding:6px;text-align:center;width:70px">Slot %</th></tr></thead>
      <tbody>\${perDayRows||'<tr><td colspan="6" style="padding:10px;text-align:center;color:#789">No submissions in this range</td></tr>'}</tbody></table></div></div>\`;
  $('#monOut').innerHTML = compLogCard +
    \`<div class="card"><h3 style="margin:0 0 8px;color:#1f7a3a">Store Compliance</h3>
      <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr style="background:#eef"><th style="padding:6px;text-align:left">Store</th><th style="padding:6px;text-align:center;width:140px">Slots Done</th><th style="padding:6px;text-align:center;width:60px">Pass</th><th style="padding:6px;text-align:center;width:60px">Fail</th><th style="padding:6px;text-align:center;width:60px">Total</th><th style="padding:6px;text-align:right;width:80px">Pass %</th></tr></thead>
        <tbody>\${storeRows||'<tr><td colspan="6" style="padding:10px;text-align:center;color:#789">No data</td></tr>'}</tbody></table></div></div>\`
    +
    \`<div class="card"><h3 style="margin:0 0 8px;color:#1f7a3a">Items Most Failed</h3>
      <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr style="background:#eef"><th style="padding:6px;text-align:left">Item</th><th style="padding:6px;text-align:center;width:60px">Pass</th><th style="padding:6px;text-align:center;width:60px">Fail</th><th style="padding:6px;text-align:center;width:60px">Total</th><th style="padding:6px;text-align:right;width:80px">Pass %</th></tr></thead>
        <tbody>\${itemRows||'<tr><td colspan="5" style="padding:10px;text-align:center;color:#789">No data</td></tr>'}</tbody></table></div></div>\`
    + detailHtml;
  if (selStore) { loadMonRecent(selStore); }
}

async function loadMonComplog(store){
  const r = await api('/api/store-compliance?store=' + encodeURIComponent(store));
  const box = $('#monCompLog'); if (!box) return;
  if (!r.ok){ box.innerHTML = '<h3 style="margin:0 0 8px;color:#1f7a3a">Compliance Log - '+escapeHtml(store)+'</h3><div class="err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  const now = new Date();
  const today = now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(now.getDate()).padStart(2,'0');
  const mins = now.getHours()*60 + now.getMinutes();
  const daysMap = new Map();
  r.days.forEach(d => daysMap.set(d.date, d));
  if (!daysMap.has(today)) daysMap.set(today, { date: today, slots: ['8AM','12PM','3PM'].map(s => ({slot:s, done:false})) });
  const days = [...daysMap.values()].sort((a,b) => b.date.localeCompare(a.date));
  const slotDeadline = { '8AM':9*60, '12PM':13*60, '3PM':16*60 };
  const rows = days.map(d => {
    let expected=0, doneCount=0;
    const cells = d.slots.map(s => {
      const isToday = d.date === today;
      const deadlinePassed = isToday ? (mins >= slotDeadline[s.slot]) : (d.date < today);
      if (s.done){ doneCount++; expected++; const bg=s.pass>=80?'#e8f5ec':s.pass>=50?'#fff5e0':'#fee'; const col=s.pass>=80?'#1f7a3a':s.pass>=50?'#b8860b':'#c33';
        return \`<td style="text-align:center;background:\${bg};color:\${col};font-weight:700;padding:6px;border:1px solid #eee">\${s.pass}% (\${s.y}/\${s.total})</td>\`;
      }
      if (deadlinePassed){ expected++; return \`<td style="text-align:center;background:#fee;color:#c33;font-weight:700;padding:6px;border:1px solid #eee">MISSED</td>\`; }
      return \`<td style="text-align:center;background:#f2f2f2;color:#789;font-weight:600;padding:6px;border:1px solid #eee">PENDING</td>\`;
    }).join('');
    const pct = expected ? Math.round((doneCount/expected)*100) : 0;
    const compBg = expected===0 ? '#789' : (doneCount===expected ? '#1f7a3a' : doneCount>0 ? '#e0a020' : '#c33');
    const compTxt = expected===0 ? '-' : (pct + '%');
    return \`<tr><td style="padding:6px;border:1px solid #eee;font-weight:600">\${d.date}\${d.date===today?' <span class="muted">(today)</span>':''}</td>\${cells}<td style="text-align:center;padding:6px;border:1px solid #eee"><span class="pill" style="background:\${compBg}">\${compTxt}</span></td></tr>\`;
  }).join('');
  box.innerHTML = '<h3 style="margin:0 0 8px;color:#1f7a3a">Compliance Log - '+escapeHtml(store)+'</h3>'
    + '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">'
    + '<thead><tr style="background:#eef"><th style="padding:6px;text-align:left">Date</th><th style="padding:6px;text-align:center">8AM</th><th style="padding:6px;text-align:center">12PM</th><th style="padding:6px;text-align:center">3PM</th><th style="padding:6px;text-align:center;width:70px">Slot %</th></tr></thead>'
    + '<tbody>' + (rows || '<tr><td colspan="5" style="padding:10px;text-align:center;color:#789">No submissions</td></tr>') + '</tbody></table></div>';
}

async function loadMonRecent(store){
  const from = $('#monFrom').value || '';
  const to = $('#monTo').value || '';
  const qs = 'store=' + encodeURIComponent(store) + (from?'&from='+encodeURIComponent(from):'') + (to?'&to='+encodeURIComponent(to):'');
  const r = await api('/api/store-history?' + qs);
  const box = $('#monRecent'); if (!box) return;
  if (!r.ok){ box.innerHTML = '<h3 style="margin:0 0 8px;color:#1f7a3a">Recent Submissions - '+escapeHtml(store)+'</h3><div class="err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  if (!r.audits.length){ box.innerHTML = '<h3 style="margin:0 0 8px;color:#1f7a3a">Recent Submissions - '+escapeHtml(store)+'</h3><div class="muted">No submissions in this range.</div>'; return; }
  const bg = p => p>=80?'#1f7a3a':p>=50?'#e0a020':'#c33';
  const items = r.audits.map(a => \`<div class="hist" style="align-items:flex-start">
    <div style="flex:1">
      <div><b>\${escapeHtml(a.date)}</b> - <span class="pill" style="background:#334;font-size:11px">\${escapeHtml(a.slot||'')}</span> <span class="muted">by \${escapeHtml(a.login||'')}</span></div>
      <div class="meta">\${new Date(a.timestamp).toLocaleString()} - Pass \${a.y}/\${a.total}, Fail \${a.n}</div>
      <div id="det_\${a.auditId}" style="margin-top:8px;display:none"></div>
    </div>
    <div style="text-align:right">
      <span class="pill" style="background:\${bg(a.pass)}">\${a.pass}%</span>
      <div style="margin-top:6px"><button class="sm ghost" onclick="toggleStoreAudit('\${a.auditId}')">View</button></div>
    </div>
  </div>\`).join('');
  box.innerHTML = '<h3 style="margin:0 0 8px;color:#1f7a3a">Recent Submissions - '+escapeHtml(store)+'</h3>' + items;
}

async function toggleStoreAudit(id){
  const el = document.getElementById('det_' + id);
  if (!el) return;
  if (el.style.display !== 'none' && el.innerHTML.trim()) { el.style.display = 'none'; return; }
  el.style.display = 'block';
  if (!el.innerHTML.trim()) el.innerHTML = '<div class="muted">Loading...</div>';
  const r = await api('/api/store-audit/' + encodeURIComponent(id));
  if (!r.ok){ el.innerHTML = '<div class="err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  const groups = {};
  r.items.forEach(it => { if (it.category==='AUDIT NOTES') return; (groups[it.category]=groups[it.category]||[]).push(it); });
  const noteRow = r.items.find(it => it.category==='AUDIT NOTES');
  let html = Object.keys(groups).map(cat => {
    const rows = groups[cat].map(it => {
      const isY = String(it.result||'').toUpperCase()==='Y';
      const isN = String(it.result||'').toUpperCase()==='N';
      const badge = isY ? '<span style="color:#1f7a3a;font-weight:700">&#10004; Pass</span>'
                        : isN ? '<span style="color:#c33;font-weight:700">&#10008; Fail</span>'
                              : '<span class="muted">-</span>';
      return \`<tr><td style="padding:4px 6px;border-bottom:1px solid #eee">\${escapeHtml(it.item)}</td><td style="padding:4px 6px;border-bottom:1px solid #eee;text-align:center;width:80px">\${badge}</td><td style="padding:4px 6px;border-bottom:1px solid #eee;color:#456;font-size:12px">\${escapeHtml(it.remarks||'')}</td></tr>\`;
    }).join('');
    return \`<div style="margin-top:8px"><div style="font-weight:700;color:#1f7a3a;font-size:13px">\${escapeHtml(cat)}</div><table style="width:100%;border-collapse:collapse;font-size:13px">\${rows}</table></div>\`;
  }).join('');
  if (noteRow && noteRow.remarks) html += \`<div style="margin-top:8px;padding:8px;background:#eef7ff;border-left:3px solid #1f7a3a;font-size:13px"><b>General Notes:</b><br>\${escapeHtml(noteRow.remarks)}</div>\`;
  el.innerHTML = html || '<div class="muted">No items.</div>';
}
$('#monApply').onclick = loadMonitor;
$('#monFrom').onchange = loadMonitor;
$('#monTo').onchange = loadMonitor;
$('#monArea').onchange = () => { $('#monStore').value=''; loadMonitor(); };
$('#monStore').onchange = loadMonitor;
$('#monExport').onclick = () => {
  if (!MON) { alert('Load monitor first'); return; }
  const store = $('#monStore').value || 'All Stores';
  const area  = $('#monArea').value  || 'All Areas';
  const from  = $('#monFrom').value, to = $('#monTo').value;
  const dateStr = (from && to) ? (from === to ? from : from + ' to ' + to) : (from || to || 'All dates');
  const bg = p => p>=80?'#1f7a3a':p>=50?'#e0a020':'#c33';
  const storeRows = MON.perStore.map(x => \`<tr>
    <td style="border:1px solid #b0b0b0;padding:6px 8px"><b>\${escapeHtml(x.name)}</b> <span style="color:#789">(\${escapeHtml(x.area||'')})</span></td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center">\${x.slotsDone}/\${x.dates*3} (\${x.slotCompliance}%)</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#1f7a3a;font-weight:bold">\${x.y}</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#c33;font-weight:bold">\${x.n}</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center">\${x.total}</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;background:\${bg(x.pass)};color:#fff;font-weight:bold">\${x.pass}%</td>
  </tr>\`).join('');
  const itemRows = MON.perItem.map(x => \`<tr>
    <td style="border:1px solid #b0b0b0;padding:6px 8px">\${escapeHtml(x.name)}</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#1f7a3a;font-weight:bold">\${x.y}</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#c33;font-weight:bold">\${x.n}</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center">\${x.total}</td>
    <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;background:\${bg(x.pass)};color:#fff;font-weight:bold">\${x.pass}%</td>
  </tr>\`).join('');
  const html = \`<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>Store Checks</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml></head>
<body style="font-family:Calibri,Arial,sans-serif">
  <h1 style="color:#1f7a3a;text-align:center;margin:0 0 12px">Fresh Compliance Result - Store Checks</h1>
  <table style="margin-bottom:14px;font-size:13px">
    <tr><td style="padding:2px 8px;font-weight:bold">Store:</td><td style="padding:2px 8px">\${escapeHtml(store)}</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Area:</td><td style="padding:2px 8px">\${escapeHtml(area)}</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Date:</td><td style="padding:2px 8px">\${escapeHtml(dateStr)}</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Reviewed by:</td><td style="padding:2px 8px">\${escapeHtml(S.manager)} (\${escapeHtml(S.level)})</td></tr>
    <tr><td style="padding:2px 8px;font-weight:bold">Generated:</td><td style="padding:2px 8px">\${new Date().toLocaleString()}</td></tr>
  </table>
  <h2 style="color:#1f7a3a">Store Compliance</h2>
  <table style="border-collapse:collapse;font-size:12px;margin-bottom:14px">
    <thead><tr style="background:#1f7a3a;color:#fff"><th style="border:1px solid #b0b0b0;padding:8px;text-align:left">Store</th><th style="border:1px solid #b0b0b0;padding:8px">Slots Done</th><th style="border:1px solid #b0b0b0;padding:8px">Pass</th><th style="border:1px solid #b0b0b0;padding:8px">Fail</th><th style="border:1px solid #b0b0b0;padding:8px">Total</th><th style="border:1px solid #b0b0b0;padding:8px">Pass %</th></tr></thead>
    <tbody>\${storeRows}</tbody></table>
  <h2 style="color:#1f7a3a">Items Most Failed</h2>
  <table style="border-collapse:collapse;font-size:12px">
    <thead><tr style="background:#1f7a3a;color:#fff"><th style="border:1px solid #b0b0b0;padding:8px;text-align:left">Item</th><th style="border:1px solid #b0b0b0;padding:8px">Pass</th><th style="border:1px solid #b0b0b0;padding:8px">Fail</th><th style="border:1px solid #b0b0b0;padding:8px">Total</th><th style="border:1px solid #b0b0b0;padding:8px">Pass %</th></tr></thead>
    <tbody>\${itemRows}</tbody></table>
</body></html>\`;
  const blob = new Blob(['\\ufeff'+html], {type:'application/vnd.ms-excel'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'Fresh_Compliance_StoreChecks_' + new Date().toISOString().slice(0,10) + '.xls';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// Auto-login if remembered
const remembered = localStorage.getItem('ff5_mgr');
if (remembered) {
  S.manager = remembered;
  S.level = localStorage.getItem('ff5_lvl') || 'Area Manager';
  S.storeId = localStorage.getItem('ff5_sid') || null;
  S.storeName = localStorage.getItem('ff5_sname') || null;
  enterApp();
}
</script>
</body></html>`;

app.get('/', (req, res) => res.type('html').send(HTML));

app.listen(PORT, () => console.log('Fresh Focus 5 Checklist listening on', PORT));
