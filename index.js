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
// Google Sheets may auto-format "8AM"/"12PM"/"3PM" as time cells ("8:00 AM"). Normalize on read.
function normalizeSlot(raw) {
  const s = String(raw || '').trim().toUpperCase();
  if (s === '8AM'  || /^0?8:00(:00)?\s*(AM)?$/.test(s)) return '8AM';
  if (s === '12PM' || /^12:00(:00)?\s*(PM)?$/.test(s)) return '12PM';
  if (s === '3PM'  || /^0?3:00(:00)?\s*PM$|^15:00(:00)?$/.test(s)) return '3PM';
  return s;
}
async function markStoreEdited(auditId, store, date, slot, newId) {
  const rows = await sheetsGet('StoreChecklistData!A2:K');
  const data = [];
  rows.forEach((r, i) => {
    const isActive = (r[10] || 'ACTIVE') === 'ACTIVE';
    if (!isActive) return;
    if (newId && r[1] === newId) return; // never mark the row we just appended
    // Match by auditId OR by same store+date+slot (replace prior slot submission)
    const match = auditId
      ? r[1] === auditId
      : ((r[3] || '').trim() === store && r[4] === date && normalizeSlot(r[5]) === slot);
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
    // Reject back-dated submissions (client sends its local date; allow only that same date server-observed, or today)
    // Compare loosely: accept if client date >= yesterday PH-ish (2-day window covers timezone drift). Reject anything older.
    const twoDaysAgo = new Date(Date.now() - 2*86400*1000).toISOString().slice(0,10);
    if (date < twoDaysAgo) return res.json({ ok:false, error:'Back-dated checklists are not allowed' });
    const ts = new Date().toISOString();
    const id = auditId || 'S' + Date.now();
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
    // Append the new ACTIVE rows FIRST — only then supersede prior rows. If the append fails,
    // the sheet is left untouched so we never orphan data (old ACTIVE remains, no MISSED).
    await sheetsAppend('StoreChecklistData!A1:K1', rows);
    try { await markStoreEdited(auditId, store, date, slot, id); } catch (_) { /* non-fatal — new rows already written */ }
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
        map.set(id, { auditId: id, timestamp: r[0], login: r[2], store: r[3], date: r[4], slot: normalizeSlot(r[5]), y: 0, n: 0, total: 0 });
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
    const meta = { auditId: id, login: entries[0][2], store: entries[0][3], date: entries[0][4], slot: normalizeSlot(entries[0][5]) };
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
      const slot = normalizeSlot(r[5]);
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
      const store = (r[3] || '(unknown)').trim();
      const areaOfRow = (storeMap[store] || {}).area || '(unknown)';
      const d = r[4] || '', slot = normalizeSlot(r[5]);
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

    const perItemArr = Object.entries(perItem).map(([name, v]) => ({
      name, y: v.y, n: v.n, total: v.total, pass: v.total ? Math.round((v.y / v.total) * 100) : 0,
    })).sort((a, b) => a.pass - b.pass);

    // Authorized store-manager stores (in scope) — used to ensure every store appears in today's log
    const smRows = await sheetsGet('StoreManagers!A2:C');
    const smStoreIds = new Set(smRows.map((r) => String(r[0] || '').trim()).filter(Boolean));
    const authorizedStores = stores
      .filter((r) => {
        const storeName = r[4], storeId = String(r[3] || '').trim(), areaName = r[2] || '(no area)';
        if (!storeName || !storeId) return false;
        if (!smStoreIds.has(storeId)) return false;
        if (!isRegional && !managerAreas.has(areaName)) return false;
        if (areaFilter && areaName !== areaFilter) return false;
        if (storeFilter && storeName !== storeFilter) return false;
        return true;
      })
      .map((r) => (r[4] || '').trim());

    // Per-store per-day slot breakdown for consolidated Compliance Log
    const todayLocal = (() => { const d = new Date(); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); })();
    const byStoreDate = {}; // "store||date" -> { store, date, slots:{8AM:{y,total},...} }
    rows.forEach((r) => {
      const store = (r[3] || '(unknown)').trim();
      const d = r[4] || '', slot = normalizeSlot(r[5]);
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
    // Ensure every authorized store has an entry for EVERY day in the filter range,
    // so days when the store submitted nothing still count in the Days / Missed columns.
    const areaOf = (name) => (storeMap[name] || {}).area || '(unknown)';
    const rangeDates = [];
    if (from && to) {
      // Iterate calendar dates from `from` to min(to, today)
      const dFrom = new Date(from + 'T00:00:00');
      const dTo   = new Date(to   + 'T00:00:00');
      const dCap  = new Date(todayLocal + 'T00:00:00');
      const dEnd  = dTo < dCap ? dTo : dCap;
      for (let d = new Date(dFrom); d <= dEnd; d.setDate(d.getDate()+1)) {
        rangeDates.push(d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'));
      }
    }
    if (!rangeDates.length) rangeDates.push(todayLocal);
    authorizedStores.forEach((s) => {
      rangeDates.forEach((dt) => {
        const k = s + '||' + dt;
        if (!byStoreDate[k]) byStoreDate[k] = { store: s, date: dt, slots: {} };
      });
      if (!perStore[s]) perStore[s] = { y: 0, n: 0, total: 0, area: areaOf(s) };
    });
    const perStoreArr = Object.entries(perStore).map(([name, v]) => {
      const dates = dateSet[name] ? dateSet[name].size : 0;
      const slotsDone = slotSet[name] ? slotSet[name].size : 0;
      const slotCompliance = dates ? Math.round((slotsDone / (dates * 3)) * 100) : 0;
      const pass = v.total ? Math.round((v.y / v.total) * 100) : 0;
      return { name, area: v.area, y: v.y, n: v.n, total: v.total, slotCompliance, pass, dates, slotsDone };
    }).sort((a, b) => (a.area || '').localeCompare(b.area || '') || a.name.localeCompare(b.name));

    const perDay = Object.values(byStoreDate).map((d) => ({
      store: d.store,
      area: (storeMap[d.store] || {}).area || '(unknown)',
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

// ---------- Focus 5 Stock Status ----------
const STOCK_CATEGORIES = ['Rice','Eggs','Poultry','Meat','Sugar'];
const STOCK_STATUSES   = ['OOS','Critical','Healthy'];
// Days BEFORE this date are ignored by streak, on-time/late/missed counts, and KPIs.
// Change this value to reset the rollout, or set to '' to disable.
const STOCK_ROLLOUT = process.env.STOCK_ROLLOUT || '2026-09-05';

async function markStockEdited(manager, date, newId) {
  const rows = await sheetsGet('StockStatus!A2:I');
  const data = [];
  rows.forEach((r, i) => {
    if ((r[8] || 'ACTIVE') !== 'ACTIVE') return;
    if (newId && r[1] === newId) return;
    if ((r[2] || '').trim().toLowerCase() === manager.trim().toLowerCase() && r[3] === date) {
      data.push({ range: `StockStatus!I${i + 2}`, values: [['EDITED']] });
    }
  });
  if (data.length) await sheetsBatchUpdateValues(data);
}

app.post('/api/stock-submit', async (req, res) => {
  try {
    const { manager, date, entries } = req.body || {};
    if (!manager || !date || !Array.isArray(entries) || !entries.length) {
      return res.json({ ok: false, error: 'Missing fields' });
    }
    for (const e of entries) {
      if (!STOCK_CATEGORIES.includes(e.category)) return res.json({ ok:false, error:'Invalid category: ' + e.category });
      if (!STOCK_STATUSES.includes(e.status)) return res.json({ ok:false, error:'Invalid status for ' + e.category + '/' + (e.store||'') });
      if (!e.store) return res.json({ ok:false, error:'Store required for ' + e.category });
    }
    const ts = new Date().toISOString();
    const id = 'K' + Date.now();
    const rows = entries.map((e) => [ts, id, manager, date, e.store, e.category, e.status, e.remarks || '', 'ACTIVE']);
    await sheetsAppend('StockStatus!A1:I1', rows);
    try { await markStockEdited(manager, date, id); } catch(_){}
    res.json({ ok: true, reportId: id });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/stock-latest', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    const date = (req.query.date || '').trim();
    if (!manager || !date) return res.json({ ok: false, error: 'manager and date required' });
    const rows = await sheetsGet('StockStatus!A2:I');
    const filtered = rows.filter(r =>
      (r[8]||'ACTIVE') === 'ACTIVE'
      && (r[2]||'').trim().toLowerCase() === manager
      && r[3] === date
    );
    if (!filtered.length) return res.json({ ok:true, entries: [] });
    const latestId = filtered.reduce((max,r) => r[1] > max ? r[1] : max, '');
    const latest = filtered.filter(r => r[1] === latestId);
    res.json({ ok:true, reportId: latestId, date, timestamp: latest[0][0],
      entries: latest.map(r => ({ store: r[4], category: r[5], status: r[6], remarks: r[7] })) });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/stock-monitor', async (req, res) => {
  try {
    const level = (req.query.level || '').trim().toLowerCase();
    const manager = (req.query.manager || '').trim().toLowerCase();
    const from = (req.query.from || '').trim();
    const to = (req.query.to || '').trim();
    const isRegional = level === 'regional manager';

    const rows = await sheetsGet('StockStatus!A2:I');
    const amRows = await sheetsGet('AreaManagers!A2:C');
    const allAMs = amRows.filter(r => (r[2] || '').trim().toLowerCase() === 'area manager').map(r => r[0]);

    const filtered = rows.filter(r => {
      if ((r[8] || 'ACTIVE') !== 'ACTIVE') return false;
      if (from && (r[3] || '') < from) return false;
      if (to && (r[3] || '') > to) return false;
      if (!isRegional && (r[2] || '').trim().toLowerCase() !== manager) return false;
      return true;
    });

    // Latest ReportID per (AM, date)
    const map = {};
    filtered.forEach(r => {
      const k = r[2] + '||' + r[3];
      if (!map[k] || r[1] > map[k].id) map[k] = { id: r[1], rows: [] };
      if (r[1] === map[k].id) map[k].rows.push(r);
    });
    const reports = [];
    Object.entries(map).forEach(([k, obj]) => {
      const [am, date] = k.split('||');
      const rowsForId = filtered.filter(r => r[2] === am && r[3] === date && r[1] === obj.id);
      // Grouped: categories[cat] = [{ store, status, remarks }, ...]
      const catMap = {};
      rowsForId.forEach(r => {
        const cat = r[5];
        if (!catMap[cat]) catMap[cat] = [];
        catMap[cat].push({ store: r[4] || '(all stores)', status: r[6], remarks: r[7] });
      });
      const timestamp = rowsForId[0][0];
      const submitted = new Date(timestamp);
      const phHour = (submitted.getUTCHours() + 8) % 24;
      const submittedDatePH = new Date(submitted.getTime() + 8*3600*1000).toISOString().slice(0,10);
      const onTime = (submittedDatePH < date) || (submittedDatePH === date && phHour < 10);
      reports.push({ manager: am, date, reportId: obj.id, timestamp, categories: catMap, onTime });
    });
    reports.sort((a,b) => b.date.localeCompare(a.date) || a.manager.localeCompare(b.manager));

    // Today (PH)
    const nowPH = new Date(Date.now() + 8*3600*1000);
    const todayPH = nowPH.toISOString().slice(0,10);
    const todayReports = reports.filter(r => r.date === todayPH);
    const submittedTodayAMs = new Set(todayReports.map(r => r.manager));
    const scopeAMs = isRegional ? allAMs : [manager];
    const totalAMs = scopeAMs.length;
    const submittedToday = submittedTodayAMs.size;
    const complianceRate = totalAMs ? Math.round((submittedToday / totalAMs) * 100) : 0;
    const onTimeToday = todayReports.filter(r => r.onTime).length;

    let oosCount = 0, critCount = 0, healthyCount = 0;
    todayReports.forEach(r => Object.values(r.categories).forEach(arr => arr.forEach(c => {
      if (c.status === 'OOS') oosCount++;
      else if (c.status === 'Critical') critCount++;
      else if (c.status === 'Healthy') healthyCount++;
    })));

    const catBreakdown = {};
    STOCK_CATEGORIES.forEach(c => catBreakdown[c] = { OOS: 0, Critical: 0, Healthy: 0 });
    todayReports.forEach(r => Object.entries(r.categories).forEach(([cat, arr]) => {
      if (!catBreakdown[cat]) return;
      arr.forEach(c => { if (catBreakdown[cat][c.status] !== undefined) catBreakdown[cat][c.status]++; });
    }));

    // Suppress "missing today" if today is before rollout
    const missingAMs = (STOCK_ROLLOUT && todayPH < STOCK_ROLLOUT)
      ? []
      : scopeAMs.filter(am => !submittedTodayAMs.has(am));

    // Per-AM streaks: consecutive days going back from yesterday where the AM was Late OR Missed.
    // Uses all reports in the filtered range (bounded by from/to).
    const reportsByAMDate = {};
    reports.forEach(r => { reportsByAMDate[r.manager + '||' + r.date] = r; });
    const yesterdayPH = new Date(nowPH.getTime() - 86400*1000).toISOString().slice(0,10);
    // Effective start = later of (query from) and (rollout date). Days before rollout are ignored entirely.
    const effectiveStart = STOCK_ROLLOUT && (from || todayPH) < STOCK_ROLLOUT
      ? STOCK_ROLLOUT
      : (from || todayPH);
    const amStats = {};
    scopeAMs.forEach(am => {
      let streak = 0, onTimeDays = 0, lateDays = 0, missedDays = 0;
      const cursor = new Date(yesterdayPH + 'T00:00:00');
      const stopAt = new Date(effectiveStart + 'T00:00:00');
      let streakLive = true;
      while (cursor >= stopAt) {
        const dStr = cursor.getFullYear() + '-' + String(cursor.getMonth()+1).padStart(2,'0') + '-' + String(cursor.getDate()).padStart(2,'0');
        const rep = reportsByAMDate[am + '||' + dStr];
        if (!rep) { if (streakLive) streak++; missedDays++; }
        else if (rep.onTime) { streakLive = false; onTimeDays++; }
        else { if (streakLive) streak++; lateDays++; }
        cursor.setDate(cursor.getDate() - 1);
      }
      amStats[am] = { streak, onTimeDays, lateDays, missedDays };
    });

    res.json({ ok: true, reports, kpis: { complianceRate, submittedToday, totalAMs, oosCount, critCount, healthyCount, onTimeToday }, catBreakdown, missingAMs, amStats, scopeAMs, todayPH });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/am-stores', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    if (!manager) return res.json({ ok:false, error:'manager required' });
    const rows = await sheetsGet('ListOfStores!A2:G');
    const stores = rows
      .filter(r => (r[6] || '').trim().toLowerCase() === manager)
      .map(r => r[4])
      .filter(Boolean);
    res.json({ ok: true, stores });
  } catch (e) { res.status(500).json({ ok:false, error: e.message }); }
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
.noScroll::-webkit-scrollbar{display:none;width:0;height:0}
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
    <button data-tab="stock">Focus 5 Stock Status</button>
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

  <div id="tabStock" class="hidden">
    <div id="stockOut"><div class="card muted">Loading...</div></div>
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
        <div><label>Date</label><input id="scDate" type="date" readonly style="background:#f2f2f2;color:#556;cursor:not-allowed"/></div>
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

// ---- Rollout configuration ----
// Compliance tracking starts from this date+slot. Earlier slots are shown as '—' and NOT counted
// in Submitted/Missed totals. Format: 'YYYY-MM-DD#RANK' where RANK: 1=8AM, 2=12PM, 3=3PM.
// Set to null to auto-detect from the earliest submission in the data.
const ROLLOUT_START = '2026-08-07#2'; // 12PM on 2026-08-07 = rollout time

// Local date as YYYY-MM-DD (uses browser timezone — NOT UTC — so PH mornings don't get tagged yesterday)
function todayStr(offsetDays){
  const d = new Date();
  if (offsetDays) d.setDate(d.getDate() + offsetDays);
  return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0');
}

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
  $('#date').value = todayStr();
  applyRoleUI();
  await loadParticulars();
  const isStoreMgr = (S.level||'').toLowerCase() === 'store manager';
  if (isStoreMgr) {
    $('#scStoreLbl').textContent = S.storeName || '';
    $('#clStoreLbl').textContent = S.storeName || '';
    $('#scDate').value = todayStr();
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
  show('.tabs button[data-tab="stock"]', !isStoreMgr);
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
  $('#tabStock').classList.toggle('hidden', t!=='stock');
  if (t==='stock') loadStockTab();
  if (t==='hist') loadHistory();
  if (t==='sum') { if(!$('#sumFrom').value){ $('#sumFrom').value = todayStr(-30); $('#sumTo').value = todayStr(); } loadSummary(); }
  if (t==='mon') { if(!$('#monFrom').value){ $('#monFrom').value = todayStr(-14); $('#monTo').value = todayStr(); } loadMonitor(); }
  if (t==='scheck') { $('#scDate').value = todayStr(); S.scSlot = autoSlot(); $('#scSlotLbl').textContent = S.scSlot; if (typeof highlightSlotBtn === 'function') highlightSlotBtn(); }
});

// Sub-tabs within Store Check
document.querySelectorAll('#tabSCheck .tabs button[data-subtab]').forEach(b => b.onclick = () => {
  document.querySelectorAll('#tabSCheck .tabs button[data-subtab]').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
  const st = b.dataset.subtab;
  $('#scSubNew').classList.toggle('hidden', st!=='new');
  $('#scSubHist').classList.toggle('hidden', st!=='hist');
  $('#scSubClog').classList.toggle('hidden', st!=='clog');
  if (st==='new') { $('#scDate').value = todayStr(); S.scSlot = autoSlot(); $('#scSlotLbl').textContent = S.scSlot; highlightSlotBtn(); }
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
  a.download = 'Fresh_Compliance_Result_' + todayStr() + '.xls';
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
  if (date !== todayStr()) { $('#scErr').textContent = 'Back-dated checklists are not allowed. Refreshing to today.'; $('#scDate').value = todayStr(); return; }
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
  const slotStart = { '8AM':7*60, '12PM':11*60, '3PM':14*60 };
  const slotDeadline = { '8AM':9*60, '12PM':13*60, '3PM':16*60 };
  // Rollout cutoff for this store's own log
  const slotRankSm = { '8AM':1, '12PM':2, '3PM':3 };
  const keyOfSm = (dt, sl) => dt + '#' + slotRankSm[sl];
  let earliestKeySm = ROLLOUT_START;
  if (!earliestKeySm) {
    days.forEach(d => d.slots.forEach(s => { if (s.done) { const k = keyOfSm(d.date, s.slot); if (!earliestKeySm || k < earliestKeySm) earliestKeySm = k; } }));
  }
  const preRolloutSm = (dt, sl) => !!(earliestKeySm && keyOfSm(dt, sl) < earliestKeySm);
  const rows = days.map(d => {
    let expected = 0, doneCount = 0;
    const cells = d.slots.map(s => {
      const isToday = d.date === today;
      const deadlinePassed = isToday ? (mins >= slotDeadline[s.slot]) : (d.date < today);
      const windowOpen  = isToday && mins >= slotStart[s.slot] && mins < slotDeadline[s.slot];
      const preRollout  = preRolloutSm(d.date, s.slot);
      if (s.done) { doneCount++; expected++; const bg = s.pass>=80?'#e8f5ec':s.pass>=50?'#fff5e0':'#fee'; const col = s.pass>=80?'#1f7a3a':s.pass>=50?'#b8860b':'#c33';
        return \`<td style="text-align:center;background:\${bg};color:\${col};font-weight:700;padding:8px;border:1px solid #eee">\${s.pass}% (\${s.y}/\${s.total})</td>\`;
      }
      if (preRollout) { return \`<td style="text-align:center;background:#f7f7f7;color:#bbb;font-weight:600;padding:8px;border:1px solid #eee" title="Before rollout">&mdash;</td>\`; }
      if (deadlinePassed) { expected++; return \`<td style="text-align:center;background:#fee;color:#c33;font-weight:700;padding:8px;border:1px solid #eee">MISSED</td>\`; }
      if (windowOpen) { return \`<td style="text-align:center;background:#fff5e0;color:#b8860b;font-weight:700;padding:8px;border:1px solid #eee">OPEN</td>\`; }
      return \`<td style="text-align:center;background:#f7f7f7;color:#bbb;font-weight:600;padding:8px;border:1px solid #eee">&mdash;</td>\`;
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
  const slotStartM    = { '8AM':7*60, '12PM':11*60, '3PM':14*60 };
  const slotDeadlineM = { '8AM':9*60, '12PM':13*60, '3PM':16*60 };
  // Rollout cutoff (must be declared before it's used in the map below)
  const slotRank = { '8AM': 1, '12PM': 2, '3PM': 3 };
  const keyOf = (date, slot) => date + '#' + slotRank[slot];
  let earliestKey = ROLLOUT_START;
  if (!earliestKey) {
    (r.perDay || []).forEach(d => d.slots.forEach(s => {
      if (s.done) { const k = keyOf(d.date, s.slot); if (!earliestKey || k < earliestKey) earliestKey = k; }
    }));
  }
  const beforeRollout = (date, slot) => !!(earliestKey && keyOf(date, slot) < earliestKey);
  const perDayRows = (r.perDay||[]).map(d => {
    let expected=0, doneCount=0;
    const cells = d.slots.map(s => {
      const isToday = d.date === todayM;
      const deadlinePassed = isToday ? (minsM >= slotDeadlineM[s.slot]) : (d.date < todayM);
      const windowOpen     = isToday && minsM >= slotStartM[s.slot] && minsM < slotDeadlineM[s.slot];
      const preRollout     = beforeRollout(d.date, s.slot);
      if (s.done){ doneCount++; expected++; const cbg=s.pass>=80?'#e8f5ec':s.pass>=50?'#fff5e0':'#fee'; const col=s.pass>=80?'#1f7a3a':s.pass>=50?'#b8860b':'#c33';
        return \`<td style="text-align:center;background:\${cbg};color:\${col};font-weight:700;padding:6px;border:1px solid #eee">\${s.pass}% (\${s.y}/\${s.total})</td>\`;
      }
      if (preRollout) { return \`<td style="text-align:center;background:#f7f7f7;color:#bbb;font-weight:600;padding:6px;border:1px solid #eee" title="Before rollout">&mdash;</td>\`; }
      if (deadlinePassed){ expected++; return \`<td style="text-align:center;background:#fee;color:#c33;font-weight:700;padding:6px;border:1px solid #eee">MISSED</td>\`; }
      if (windowOpen){ return \`<td style="text-align:center;background:#fff5e0;color:#b8860b;font-weight:700;padding:6px;border:1px solid #eee">OPEN</td>\`; }
      return \`<td style="text-align:center;background:#f7f7f7;color:#bbb;font-weight:600;padding:6px;border:1px solid #eee">&mdash;</td>\`;
    }).join('');
    const pct = expected ? Math.round((doneCount/expected)*100) : 0;
    const compBg = expected===0 ? '#789' : (doneCount===expected ? '#1f7a3a' : doneCount>0 ? '#e0a020' : '#c33');
    const compTxt = expected===0 ? '-' : (pct + '%');
    return \`<tr><td style="padding:6px;border:1px solid #eee;font-weight:600">\${escapeHtml(d.store)}</td><td style="padding:6px;border:1px solid #eee">\${d.date}\${d.date===todayM?' <span class="muted">(today)</span>':''}</td>\${cells}<td style="text-align:center;padding:6px;border:1px solid #eee"><span class="pill" style="background:\${compBg}">\${compTxt}</span></td></tr>\`;
  }).join('');

  // ---- Dynamic "Stores Without Checklist Submitted" alert card ----
  // Determine most recently ENDED slot today (deadline passed)
  let recentSlot = null;
  if (minsM >= 16*60) recentSlot = '3PM';
  else if (minsM >= 13*60) recentSlot = '12PM';
  else if (minsM >= 9*60) recentSlot = '8AM';
  let missCard = '';
  if (recentSlot && !beforeRollout(todayM, recentSlot)) {
    const missed = (r.perDay || []).filter(d => d.date === todayM).map(d => {
      const s = d.slots.find(x => x.slot === recentSlot);
      return { store: d.store, missed: !s || !s.done };
    }).filter(x => x.missed);
    const count = missed.length;
    const total = (r.perDay || []).filter(d => d.date === todayM).length;
    if (count === 0) {
      missCard = \`<div class="card" style="border-left:6px solid #1f7a3a;background:#f0faf3">
        <div style="display:flex;align-items:center;gap:10px">
          <div style="font-size:26px">&#9989;</div>
          <div style="flex:1">
            <div style="color:#1f7a3a;font-weight:700;font-size:16px">All stores submitted the \${recentSlot} checklist</div>
            <div class="muted" style="margin-top:2px">\${total}/\${total} stores compliant for \${recentSlot} on \${todayM}</div>
          </div>
        </div></div>\`;
    } else {
      const chips = missed.map(m => \`<span style="display:inline-block;background:#fff;color:#c33;border:1px solid #f5b1b1;padding:6px 10px;border-radius:20px;margin:3px 4px 3px 0;font-weight:600;font-size:13px">&#9888; \${escapeHtml(m.store)}</span>\`).join('');
      missCard = \`<div class="card" style="border-left:6px solid #c33;background:linear-gradient(135deg,#fff5f5 0%,#ffe8e8 100%);box-shadow:0 2px 8px rgba(200,50,50,.15)">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
          <div style="font-size:32px;line-height:1">&#128680;</div>
          <div style="flex:1">
            <div style="color:#c33;font-weight:800;font-size:17px;letter-spacing:.3px">STORES WITHOUT CHECKLIST SUBMITTED at \${recentSlot} time slot</div>
            <div style="color:#a00;font-size:13px;margin-top:3px"><b>\${count}</b> of \${total} store\${total===1?'':'s'} missed the \${recentSlot} deadline for \${todayM}</div>
          </div>
          <div style="text-align:center;padding:8px 14px;background:#c33;color:#fff;border-radius:8px;font-weight:800;font-size:20px;min-width:60px">\${count}</div>
        </div>
        <div style="padding-top:8px;border-top:1px dashed #f0b0b0">\${chips}</div>
      </div>\`;
    }
  }
  // ---- Per-Store Submission Summary (across the whole date range) ----
  const storeAgg = {};
  (r.perDay || []).forEach(d => {
    const isToday = d.date === todayM;
    d.slots.forEach(s => {
      if (beforeRollout(d.date, s.slot)) return; // exclude pre-rollout slots
      const deadlinePassed = isToday ? (minsM >= slotDeadlineM[s.slot]) : (d.date < todayM);
      if (!deadlinePassed) return; // only count slots whose deadline has passed
      const key = d.store;
      if (!storeAgg[key]) storeAgg[key] = { store: key, submitted: 0, missed: 0, days: new Set() };
      storeAgg[key].days.add(d.date);
      if (s.done) storeAgg[key].submitted++;
      else storeAgg[key].missed++;
    });
  });
  const aggRows = Object.values(storeAgg).map(x => {
    const total = x.submitted + x.missed;
    const rate = total ? Math.round((x.submitted / total) * 100) : 0;
    return { store: x.store, days: x.days.size, submitted: x.submitted, missed: x.missed, total, rate };
  }).sort((a, b) => b.missed - a.missed || a.rate - b.rate || a.store.localeCompare(b.store));
  const summaryRowHtml = aggRows.map(x => {
    const pillBg = x.rate >= 90 ? '#1f7a3a' : x.rate >= 60 ? '#e0a020' : '#c33';
    const rowBg = x.missed === 0 ? '' : (x.missed >= 3 ? 'background:#fff5f5' : 'background:#fffcf0');
    return \`<tr style="\${rowBg}">
      <td style="padding:6px 8px;border:1px solid #eee;font-weight:600">\${escapeHtml(x.store)}</td>
      <td style="padding:6px;border:1px solid #eee;text-align:center">\${x.days}</td>
      <td style="padding:6px;border:1px solid #eee;text-align:center;color:#1f7a3a;font-weight:700">\${x.submitted}</td>
      <td style="padding:6px;border:1px solid #eee;text-align:center;color:#c33;font-weight:700">\${x.missed}</td>
      <td style="padding:6px;border:1px solid #eee;text-align:center">\${x.total}</td>
      <td style="padding:6px;border:1px solid #eee;text-align:right"><span class="pill" style="background:\${pillBg}">\${x.rate}%</span></td>
    </tr>\`;
  }).join('');
  const rangeFrom = $('#monFrom').value || '';
  const rangeTo   = $('#monTo').value   || '';
  const rangeLbl  = (rangeFrom && rangeTo) ? (rangeFrom === rangeTo ? rangeFrom : rangeFrom + ' to ' + rangeTo) : (rangeFrom || rangeTo || 'All dates');
  // ---- Weekly Ranking (Mon-Sun weeks, ranked by average pass %) ----
  const weekOf = (dateStr) => {
    const dt = new Date(dateStr + 'T00:00:00');
    dt.setDate(dt.getDate() - ((dt.getDay() + 6) % 7));
    return dt.getFullYear()+'-'+String(dt.getMonth()+1).padStart(2,'0')+'-'+String(dt.getDate()).padStart(2,'0');
  };
  const MONTHS_S = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const fmtWeek = (mondayStr) => {
    const mon = new Date(mondayStr + 'T00:00:00');
    const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
    return mon.getMonth() === sun.getMonth()
      ? \`\${MONTHS_S[mon.getMonth()]} \${mon.getDate()}-\${sun.getDate()}\`
      : \`\${MONTHS_S[mon.getMonth()]} \${mon.getDate()} - \${MONTHS_S[sun.getMonth()]} \${sun.getDate()}\`;
  };
  const weekSetR = new Set();
  const storeWeek = {}; // "store||weekKey" -> { submitted, expected }
  const areaWeek  = {}; // "area||weekKey"  -> { submitted, expected }
  const storesInScope = new Set();
  const areasInScope  = new Set();
  const storeArea = {}; // store -> area (for display)
  (r.perDay || []).forEach(d => {
    weekSetR.add(weekOf(d.date));
    storesInScope.add(d.store);
    const areaName = d.area || '(unknown)';
    areasInScope.add(areaName);
    storeArea[d.store] = areaName;
    const isTodayR = d.date === todayM;
    d.slots.forEach(s => {
      if (beforeRollout(d.date, s.slot)) return;
      const deadlinePassedR = isTodayR ? (minsM >= slotDeadlineM[s.slot]) : (d.date < todayM);
      if (!deadlinePassedR) return;
      const wk = weekOf(d.date);
      const sk = d.store + '||' + wk;
      if (!storeWeek[sk]) storeWeek[sk] = { submitted: 0, expected: 0 };
      storeWeek[sk].expected += 1;
      if (s.done) storeWeek[sk].submitted += 1;
      const ak = areaName + '||' + wk;
      if (!areaWeek[ak]) areaWeek[ak] = { submitted: 0, expected: 0 };
      areaWeek[ak].expected += 1;
      if (s.done) areaWeek[ak].submitted += 1;
    });
  });
  const weeksR = [...weekSetR].sort();
  const isPartial = (wk) => {
    const mon = new Date(wk + 'T00:00:00');
    const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
    const rangeStart = rangeFrom ? new Date(rangeFrom + 'T00:00:00') : null;
    const rangeEnd = rangeTo ? new Date(rangeTo + 'T00:00:00') : null;
    const todayD = new Date(todayM + 'T00:00:00');
    const effectiveEnd = (rangeEnd && rangeEnd < todayD) ? rangeEnd : todayD;
    return (rangeStart && rangeStart > mon) || (effectiveEnd < sun);
  };
  const rankData = [...storesInScope].map(store => {
    const weekPcts = weeksR.map(w => {
      const rec = storeWeek[store + '||' + w];
      if (!rec || rec.expected === 0) return null;
      return Math.round((rec.submitted / rec.expected) * 100);
    });
    const valid = weekPcts.filter(v => v !== null);
    const avg = valid.length ? Math.round(valid.reduce((a,b) => a+b, 0) / valid.length) : null;
    return { store, weekPcts, avg };
  }).sort((a, b) => {
    if (a.avg === null && b.avg === null) return a.store.localeCompare(b.store);
    if (a.avg === null) return 1;
    if (b.avg === null) return -1;
    return a.avg - b.avg || a.store.localeCompare(b.store);
  });
  const cellBg  = p => p===null ? '#f7f7f7' : (p >= 90 ? '#e8f5ec' : p >= 60 ? '#fff5e0' : '#fee');
  const cellCol = p => p===null ? '#bbb'    : (p >= 90 ? '#1f7a3a' : p >= 60 ? '#b8860b' : '#c33');
  const medal   = i => i < 3 ? '#c33' : i < 6 ? '#e0a020' : '#1f7a3a';

  // Compact styling so the table fits without a scrollbar
  const wkColW = Math.max(48, Math.floor(460 / Math.max(1, weeksR.length))); // shared budget across week cols
  const wkHeaders = weeksR.map(w => \`<th style="padding:4px 2px;text-align:center;width:\${wkColW}px;font-weight:500;font-size:11px;line-height:1.15">\${fmtWeek(w)}\${isPartial(w) ? '<div style="font-size:9px;color:#a55;font-weight:400">(partial)</div>' : ''}</th>\`).join('');
  const wkRows = rankData.map((rd, i) => {
    const cells = rd.weekPcts.map(p => \`<td style="padding:4px 2px;text-align:center;background:\${cellBg(p)};color:\${cellCol(p)};font-weight:700;border:1px solid #eee;font-size:12px">\${p===null?'&mdash;':(p+'%')}</td>\`).join('');
    return \`<tr>
      <td style="padding:4px 2px;text-align:center;background:\${medal(i)};color:#fff;font-weight:700;border:1px solid #eee;font-size:12px">\${i+1}</td>
      <td style="padding:4px 6px;font-weight:600;border:1px solid #eee;font-size:12px;line-height:1.2;word-break:break-word">\${escapeHtml(rd.store)}</td>
      \${cells}
      <td style="padding:4px 2px;text-align:center;background:\${cellBg(rd.avg)};color:\${cellCol(rd.avg)};font-weight:800;border:1px solid #eee;font-size:12px">\${rd.avg===null?'&mdash;':(rd.avg+'%')}</td>
    </tr>\`;
  }).join('');
  const weeklyRankCard = (weeksR.length && rankData.length) ? \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px">
      <h3 style="margin:0;color:#1f7a3a">Weekly Ranking - Per Store</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">Lowest &rarr; Highest by Avg</span>
    </div>
    <div style="margin-bottom:10px;padding:10px 12px;background:#fff8e1;border-left:4px solid #e0a020;border-radius:4px;font-size:13px;line-height:1.55;color:#5a4300">
      <b style="color:#a06800">NOTE TO ALL STORES:</b>
      This ranking reflects how consistently your store completes the 3 daily checklists.
      Please make sure each check is submitted within its window:
      <b>8AM (07:00-09:00)</b>, <b>12PM (11:00-13:00)</b>, <b>3PM (14:00-16:00)</b>.
      Target is <b>100% every week</b>. Stores at the top of this list (red rank) need immediate action -
      brief your team, set alarms per slot, and ensure the app is opened and submitted before the deadline.
      Late or missed checks affect your store's overall performance and area standing.
    </div>
    <table style="width:100%;border-collapse:collapse;table-layout:fixed">
      <thead><tr style="background:#eef"><th style="padding:4px;width:36px;text-align:center;font-size:11px">Rank</th><th style="padding:4px 6px;text-align:left;width:90px;font-size:11px">Store</th>\${wkHeaders}<th style="padding:4px;text-align:center;width:52px;font-size:11px">Avg</th></tr></thead>
      <tbody>\${wkRows}</tbody></table>
  </div>\` : '';

  // ---- Per-Area weekly ranking ----
  const areaRankData = [...areasInScope].map(area => {
    const weekPcts = weeksR.map(w => {
      const rec = areaWeek[area + '||' + w];
      if (!rec || rec.expected === 0) return null;
      return Math.round((rec.submitted / rec.expected) * 100);
    });
    const valid = weekPcts.filter(v => v !== null);
    const avg = valid.length ? Math.round(valid.reduce((a,b) => a+b, 0) / valid.length) : null;
    return { area, weekPcts, avg };
  }).sort((a, b) => {
    if (a.avg === null && b.avg === null) return a.area.localeCompare(b.area);
    if (a.avg === null) return 1;
    if (b.avg === null) return -1;
    return a.avg - b.avg || a.area.localeCompare(b.area);
  });
  const areaWkRows = areaRankData.map((rd, i) => {
    const cells = rd.weekPcts.map(p => \`<td style="padding:4px 2px;text-align:center;background:\${cellBg(p)};color:\${cellCol(p)};font-weight:700;border:1px solid #eee;font-size:12px">\${p===null?'&mdash;':(p+'%')}</td>\`).join('');
    return \`<tr>
      <td style="padding:4px 2px;text-align:center;background:\${medal(i)};color:#fff;font-weight:700;border:1px solid #eee;font-size:12px">\${i+1}</td>
      <td style="padding:4px 6px;font-weight:600;border:1px solid #eee;font-size:12px;line-height:1.2;word-break:break-word">\${escapeHtml(rd.area)}</td>
      \${cells}
      <td style="padding:4px 2px;text-align:center;background:\${cellBg(rd.avg)};color:\${cellCol(rd.avg)};font-weight:800;border:1px solid #eee;font-size:12px">\${rd.avg===null?'&mdash;':(rd.avg+'%')}</td>
    </tr>\`;
  }).join('');
  const areaRankCard = (weeksR.length && areaRankData.length) ? \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px">
      <h3 style="margin:0;color:#1f7a3a">Weekly Ranking - Per Area</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">Lowest &rarr; Highest by Avg</span>
    </div>
    <div class="muted" style="margin-bottom:8px;font-size:12px">Same metric aggregated at the area level. All stores in that area contribute to the area's weekly slot compliance %.</div>
    <table style="width:100%;border-collapse:collapse;table-layout:fixed">
      <thead><tr style="background:#eef"><th style="padding:4px;width:36px;text-align:center;font-size:11px">Rank</th><th style="padding:4px 6px;text-align:left;width:130px;font-size:11px">Area</th>\${wkHeaders}<th style="padding:4px;text-align:center;width:52px;font-size:11px">Avg</th></tr></thead>
      <tbody>\${areaWkRows}</tbody></table>
  </div>\` : '';

  const submissionSummaryCard = aggRows.length ? \`<div class="card"><div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px"><h3 style="margin:0;color:#1f7a3a">Store Submission Summary</h3><span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${escapeHtml(rangeLbl)}</span></div>
    <div class="muted" style="margin-bottom:8px;font-size:12px">Aggregated across all days in the filter range - sorted by most missed first. Only counts slots whose deadline has passed.</div>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="background:#eef"><th style="padding:6px;text-align:left">Store</th><th style="padding:6px;text-align:center;width:60px">Days</th><th style="padding:6px;text-align:center;width:80px">Submitted</th><th style="padding:6px;text-align:center;width:70px">Missed</th><th style="padding:6px;text-align:center;width:60px">Total</th><th style="padding:6px;text-align:right;width:90px">Compliance %</th></tr></thead>
      <tbody>\${summaryRowHtml}</tbody></table></div></div>\` : '';
  const compLogCard = missCard + submissionSummaryCard + weeklyRankCard + areaRankCard + \`<div class="card"><h3 style="margin:0 0 8px;color:#1f7a3a">Compliance Log</h3>
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
  a.download = 'Fresh_Compliance_StoreChecks_' + todayStr() + '.xls';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// ---- Focus 5 Stock Status ----
const STOCK_CATS = [
  { name: 'Rice',    icon: '&#127834;' },
  { name: 'Eggs',    icon: '&#129370;' },
  { name: 'Poultry', icon: '&#128020;' },
  { name: 'Meat',    icon: '&#129385;' },
  { name: 'Sugar',   icon: '&#129474;' },
];
const STOCK_OPTS = [
  { v: 'OOS',      lbl: 'OOS',      bg: '#c33',    fg: '#fff' },
  { v: 'Critical', lbl: 'Critical', bg: '#e0a020', fg: '#fff' },
  { v: 'Healthy',  lbl: 'Healthy',  bg: '#1f7a3a', fg: '#fff' },
];
let STOCK_STATE = { entries: {}, from: null, to: null, expanded: {}, lastData: null, amStores: [], singleDate: null, wFrom: null, wTo: null };

async function loadStockTab(){
  const level = (S.level||'').toLowerCase();
  const isAM = level === 'area manager';
  const isRM = level === 'regional manager';
  $('#stockOut').innerHTML = '<div class="card muted">Loading...</div>';
  const today = todayStr();
  if (!STOCK_STATE.from) STOCK_STATE.from = todayStr(-29);
  if (!STOCK_STATE.to)   STOCK_STATE.to   = today;
  const [monRes, latestRes, storesRes] = await Promise.all([
    api('/api/stock-monitor?manager=' + encodeURIComponent(S.manager) + '&level=' + encodeURIComponent(S.level||'') + '&from=' + STOCK_STATE.from + '&to=' + STOCK_STATE.to),
    isAM ? api('/api/stock-latest?manager=' + encodeURIComponent(S.manager) + '&date=' + today) : Promise.resolve({ ok:true, entries: [] }),
    isAM ? api('/api/am-stores?manager=' + encodeURIComponent(S.manager)) : Promise.resolve({ ok:true, stores: [] })
  ]);
  STOCK_STATE.amStores = (storesRes.stores || []);
  if (!monRes.ok){ $('#stockOut').innerHTML = '<div class="card err">'+escapeHtml(monRes.error||'Failed')+'</div>'; return; }
  STOCK_STATE.lastData = monRes;
  const k = monRes.kpis;
  const filterCard = \`<div class="card">
    <div class="row">
      <div><label>From</label><input id="stockFrom" type="date" value="\${STOCK_STATE.from}"/></div>
      <div><label>To</label><input id="stockTo" type="date" value="\${STOCK_STATE.to}"/></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <button id="stockApplyBtn">Apply</button>
      <button id="stockExportBtn" class="ghost">Export to Excel</button>
    </div>
    <div class="muted" style="margin-top:6px;font-size:12px">History and streak use this range. KPIs and today's chart always reflect today only.</div>
  </div>\`;

  // KPI cards row
  const kpi = (icon, num, lbl, bg, sub) => \`<div style="flex:1 1 140px;min-width:0;background:\${bg};color:#fff;padding:14px;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
    <div style="font-size:20px;opacity:.9;line-height:1">\${icon}</div>
    <div style="font-size:28px;font-weight:800;margin-top:6px;line-height:1">\${num}</div>
    <div style="font-size:12px;opacity:.95;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:.4px">\${lbl}</div>
    \${sub ? '<div style="font-size:11px;opacity:.85;margin-top:2px">'+sub+'</div>' : ''}
  </div>\`;
  const complianceCard = kpi('&#128202;', k.complianceRate + '%', 'Compliance', k.complianceRate>=100?'#1f7a3a':k.complianceRate>=50?'#e0a020':'#c33', k.submittedToday + ' of ' + k.totalAMs + ' AM(s) today');
  const oosCard      = kpi('&#128308;', k.oosCount,      'OOS today',     '#c33');
  const critCard     = kpi('&#128993;', k.critCount,     'Critical today','#e0a020');
  const healthyCard  = kpi('&#128994;', k.healthyCount,  'Healthy today', '#1f7a3a');
  const onTimeCard   = kpi('&#9200;',    k.onTimeToday,  'On time (< 10AM)','#345');
  const kpiRow = \`<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">\${complianceCard}\${oosCard}\${critCard}\${healthyCard}\${onTimeCard}</div>\`;

  // Category breakdown chart (stacked bars)
  const catBars = STOCK_CATS.map(c => {
    const b = monRes.catBreakdown[c.name] || { OOS:0, Critical:0, Healthy:0 };
    const total = b.OOS + b.Critical + b.Healthy;
    if (!total) {
      return \`<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        <div style="width:100px;font-size:13px;font-weight:600">\${c.icon} \${c.name}</div>
        <div style="flex:1;height:22px;background:#f2f2f2;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#aaa;font-size:11px">No data yet</div>
      </div>\`;
    }
    const seg = (v, bg, lbl) => v ? '<div style="width:'+(v/total*100)+'%;background:'+bg+';color:#fff;font-weight:700;font-size:11px;display:flex;align-items:center;justify-content:center">'+v+'</div>' : '';
    return \`<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
      <div style="width:100px;font-size:13px;font-weight:600">\${c.icon} \${c.name}</div>
      <div style="flex:1;height:22px;background:#eee;border-radius:6px;overflow:hidden;display:flex">
        \${seg(b.OOS,'#c33','OOS')}\${seg(b.Critical,'#e0a020','Critical')}\${seg(b.Healthy,'#1f7a3a','Healthy')}
      </div>
      <div style="width:50px;text-align:right;font-size:12px;color:#556">\${total}</div>
    </div>\`;
  }).join('');
  const chartCard = \`<div class="card"><h3 style="margin:0 0 10px;color:#1f7a3a">Stock Status by Category - Today</h3>
    <div style="display:flex;gap:12px;margin-bottom:10px;font-size:11px;font-weight:600">
      <span><span style="display:inline-block;width:10px;height:10px;background:#c33;border-radius:2px;vertical-align:middle;margin-right:4px"></span>OOS</span>
      <span><span style="display:inline-block;width:10px;height:10px;background:#e0a020;border-radius:2px;vertical-align:middle;margin-right:4px"></span>Critical</span>
      <span><span style="display:inline-block;width:10px;height:10px;background:#1f7a3a;border-radius:2px;vertical-align:middle;margin-right:4px"></span>Healthy</span>
    </div>
    \${catBars}
  </div>\`;

  // AM Submission Form (only for AM)
  let formCard = '';
  if (isAM) {
    const stores = STOCK_STATE.amStores;
    // Preload existing submission if any
    const existing = {}; // { category: { store: {status, remarks} } }
    (latestRes.entries || []).forEach(e => {
      if (!existing[e.category]) existing[e.category] = {};
      existing[e.category][e.store] = { status: e.status, remarks: e.remarks || '' };
    });
    STOCK_STATE.entries = {};
    STOCK_CATS.forEach(c => {
      STOCK_STATE.entries[c.name] = {};
      stores.forEach(s => {
        STOCK_STATE.entries[c.name][s] = (existing[c.name] && existing[c.name][s]) || { status: '', remarks: '' };
      });
    });
    const hasExisting = (latestRes.entries || []).length > 0;
    const noStoresMsg = !stores.length ? '<div style="padding:12px;background:#fee;color:#c33;border-radius:6px;font-size:13px">No stores assigned to your account. Contact admin to update ListOfStores column G.</div>' : '';
    formCard = \`<div class="card">
      <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:10px">
        <h3 style="margin:0;color:#1f7a3a">\${hasExisting?'Update':'Submit'} Stock Status Report</h3>
        <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${today}</span>
        <span style="background:#eef;color:#334;font-weight:600;font-size:11px;padding:3px 10px;border-radius:12px">\${stores.length} store\${stores.length===1?'':'s'}</span>
        \${hasExisting?'<span style="background:#fff8e1;color:#a06800;font-weight:600;font-size:11px;padding:3px 10px;border-radius:12px;border:1px solid #f0d78a">Already submitted - resubmit to update</span>':''}
      </div>
      <div style="margin-bottom:12px;padding:10px 12px;background:#fff8e1;border-left:4px solid #e0a020;border-radius:4px;font-size:12px;color:#5a4300">
        <b style="color:#a06800">DEADLINE:</b> Submit before <b>10:00 AM</b> daily. Late submissions count against your compliance.
      </div>
      \${noStoresMsg}
      <div id="stockForm">\${stores.length ? STOCK_CATS.map(c => stockCategoryHTML(c, stores)).join('') : ''}</div>
      \${stores.length ? '<div style="margin-top:12px"><button id="stockSubmitBtn">'+(hasExisting?'Update Report':'Submit Report')+'</button></div>' : ''}
      <div id="stockErr" class="err"></div>
    </div>\`;
  }

  // Reports table (RM sees all, AM sees their own history)
  const worstOf = (arr) => {
    if (arr.some(x => x.status === 'OOS')) return 'OOS';
    if (arr.some(x => x.status === 'Critical')) return 'Critical';
    if (arr.some(x => x.status === 'Healthy')) return 'Healthy';
    return '';
  };
  // Available dates (newest first) and default singleDate to the most recent
  const availableDates = [...new Set(monRes.reports.map(r => r.date))].sort().reverse();
  if (!STOCK_STATE.singleDate && availableDates.length) STOCK_STATE.singleDate = availableDates[0];
  if (STOCK_STATE.singleDate && !availableDates.includes(STOCK_STATE.singleDate)) STOCK_STATE.singleDate = availableDates[0] || '';
  const displayDate = STOCK_STATE.singleDate || 'All in range';
  const filteredReports = STOCK_STATE.singleDate
    ? monRes.reports.filter(r => r.date === STOCK_STATE.singleDate)
    : monRes.reports;
  const reportsHtml = filteredReports.length ? filteredReports.slice(0,100).map(r => {
    const cats = STOCK_CATS.map(c => {
      const arr = r.categories[c.name] || [];
      if (!arr.length) return \`<td style="padding:4px;text-align:center;background:#f7f7f7;color:#bbb">-</td>\`;
      const worst = worstOf(arr);
      const opt = STOCK_OPTS.find(o => o.v === worst) || { bg:'#789', fg:'#fff' };
      const countAtWorst = arr.filter(x => x.status === worst).length;
      const totalStores = arr.length;
      return \`<td style="padding:4px;text-align:center;background:\${opt.bg};color:\${opt.fg};font-weight:700;font-size:11px">\${worst}<br><span style="font-size:9px;opacity:.9">\${countAtWorst}/\${totalStores}</span></td>\`;
    }).join('');
    const badge = r.onTime ? '<span class="pill" style="background:#1f7a3a;font-size:10px">ON TIME</span>' : '<span class="pill" style="background:#c33;font-size:10px">LATE</span>';
    // Per-category × per-store breakdown in expansion
    const remarkPanels = STOCK_CATS.map(c => {
      const arr = r.categories[c.name] || [];
      if (!arr.length) return '';
      const rows = arr.map(e => {
        const opt = STOCK_OPTS.find(o => o.v === e.status) || { bg:'#789', fg:'#fff' };
        return \`<div style="display:flex;gap:8px;padding:4px 0;font-size:12px;align-items:baseline">
          <span style="min-width:130px;font-weight:600;color:#334">\${escapeHtml(e.store)}</span>
          <span style="background:\${opt.bg};color:\${opt.fg};padding:2px 8px;border-radius:6px;font-weight:700;font-size:11px">\${e.status}</span>
          <span style="color:#456;flex:1">\${escapeHtml(e.remarks||'')}</span>
        </div>\`;
      }).join('');
      return \`<div style="margin-bottom:8px">
        <div style="font-weight:700;color:#1f7a3a;font-size:13px;margin-bottom:2px">\${c.icon} \${c.name}</div>
        \${rows}
      </div>\`;
    }).join('');
    const remarkContent = remarkPanels || '<div style="color:#789;padding:6px;font-size:12px;font-style:italic">No detail</div>';
    return \`<tr onclick="toggleReportRemarks('\${r.reportId}')" style="cursor:pointer" onmouseover="this.style.background='#f4faf6'" onmouseout="this.style.background=''">
      <td style="padding:4px 8px;font-weight:600;font-size:12px">\${escapeHtml(r.manager)}</td>
      <td style="padding:4px 8px;font-size:12px">\${escapeHtml(r.date)}</td>
      <td style="padding:4px;text-align:center">\${badge}</td>
      \${cats}
      <td style="padding:4px 8px;font-size:11px;color:#789">\${new Date(r.timestamp).toLocaleString()}</td>
      <td style="padding:4px 6px;text-align:center;color:#1f7a3a;font-size:14px" title="Click to view remarks">&#9660;</td>
    </tr>
    <tr id="rpt_\${r.reportId}" style="display:none;background:#fbfcfa">
      <td colspan="\${4+STOCK_CATS.length+1}" style="padding:8px 12px">\${remarkContent}</td>
    </tr>\`;
  }).join('') : '';
  const streakChip = (am) => {
    const s = (monRes.amStats||{})[am];
    if (!s || !s.streak) return '';
    return '<span style="display:inline-block;background:#c33;color:#fff;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:700;margin-left:6px">' + s.streak + 'd streak</span>';
  };
  const missingHtml = (monRes.missingAMs && monRes.missingAMs.length) ? \`<div class="card" style="border-left:6px solid #c33;background:linear-gradient(135deg,#fff5f5 0%,#ffe8e8 100%)">
    <div style="display:flex;align-items:center;gap:12px">
      <div style="font-size:28px">&#9888;</div>
      <div style="flex:1">
        <div style="color:#c33;font-weight:800;font-size:15px">NOT YET SUBMITTED TODAY</div>
        <div style="margin-top:6px">\${monRes.missingAMs.map(m => '<span style="display:inline-block;background:#fff;color:#c33;border:1px solid #f5b1b1;padding:4px 10px;border-radius:20px;margin:2px;font-weight:600;font-size:12px">&#9888; '+escapeHtml(m)+streakChip(m)+'</span>').join('')}</div>
      </div>
    </div></div>\` : '';

  // ---- Per-AM history (all reports in range grouped by AM) ----
  const historyByAM = {};
  (monRes.scopeAMs || []).forEach(am => historyByAM[am] = []);
  monRes.reports.forEach(r => { (historyByAM[r.manager] = historyByAM[r.manager] || []).push(r); });
  const historyCard = \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0;color:#1f7a3a">Per-AM History</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${STOCK_STATE.from} to \${STOCK_STATE.to}</span>
    </div>
    <div class="muted" style="font-size:12px;margin-bottom:10px">Click an AM to expand daily reports. Streak = consecutive Late-or-Missed days ending yesterday.</div>
    \${(monRes.scopeAMs||[]).map(am => {
      const s = (monRes.amStats||{})[am] || { streak:0, onTimeDays:0, lateDays:0, missedDays:0 };
      const list = historyByAM[am] || [];
      const streakBg = s.streak >= 3 ? '#c33' : s.streak >= 1 ? '#e0a020' : '#1f7a3a';
      const expanded = STOCK_STATE.expanded[am];
      const rowsHtml = expanded ? (list.length ? list.slice(0,60).map(r => {
        const cats = STOCK_CATS.map(c => {
          const arr = r.categories[c.name] || [];
          if (!arr.length) return '<td style="padding:3px;text-align:center;background:#f7f7f7;color:#bbb;font-size:11px">-</td>';
          const worst = (arr.some(x=>x.status==='OOS')?'OOS':arr.some(x=>x.status==='Critical')?'Critical':'Healthy');
          const opt = STOCK_OPTS.find(o => o.v === worst) || { bg:'#789', fg:'#fff' };
          const tip = arr.map(e => e.store + ': ' + e.status + (e.remarks?' - '+e.remarks:'')).join('\\n');
          return '<td style="padding:3px;text-align:center;background:'+opt.bg+';color:'+opt.fg+';font-weight:700;font-size:11px" title="'+escapeHtml(tip)+'">'+worst+'</td>';
        }).join('');
        const badge = r.onTime ? '<span class="pill" style="background:#1f7a3a;font-size:10px">ON TIME</span>' : '<span class="pill" style="background:#c33;font-size:10px">LATE</span>';
        return \`<tr>
          <td style="padding:3px 8px;font-size:12px">\${escapeHtml(r.date)}</td>
          <td style="padding:3px;text-align:center">\${badge}</td>
          \${cats}
          <td style="padding:3px 8px;font-size:11px;color:#789">\${new Date(r.timestamp).toLocaleString()}</td>
        </tr>\`;
      }).join('') : '<tr><td colspan="'+(3+STOCK_CATS.length)+'" style="padding:8px;text-align:center;color:#789;font-size:12px">No reports in range</td></tr>') : '';
      const tableHtml = expanded ? \`<div style="margin-top:8px;overflow-x:auto"><table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#eef"><th style="padding:4px 8px;text-align:left;font-size:11px">Date</th><th style="padding:4px;text-align:center;font-size:11px">Status</th>\${STOCK_CATS.map(c => '<th style="padding:4px;text-align:center;width:60px;font-size:11px">'+c.icon+' '+c.name+'</th>').join('')}<th style="padding:4px 8px;text-align:left;font-size:11px">Submitted</th></tr></thead>
        <tbody>\${rowsHtml}</tbody></table></div>\` : '';
      return \`<div style="padding:10px;border:1px solid #eee;border-radius:8px;margin-bottom:6px;background:\${expanded?'#f8fcf9':'#fff'}">
        <div style="display:flex;align-items:center;gap:10px;cursor:pointer" onclick="toggleAMHistory('\${am}')">
          <div style="flex:1;font-weight:700;color:#1f7a3a">\${escapeHtml(am)}</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;font-size:11px">
            <span style="background:\${streakBg};color:#fff;padding:2px 8px;border-radius:10px;font-weight:700">Streak \${s.streak}d</span>
            <span style="background:#e8f5ec;color:#1f7a3a;padding:2px 8px;border-radius:10px;font-weight:600">On-time \${s.onTimeDays}</span>
            <span style="background:#fff5e0;color:#b8860b;padding:2px 8px;border-radius:10px;font-weight:600">Late \${s.lateDays}</span>
            <span style="background:#fee;color:#c33;padding:2px 8px;border-radius:10px;font-weight:600">Missed \${s.missedDays}</span>
          </div>
          <div style="color:#789;font-size:14px">\${expanded?'&#9660;':'&#9654;'}</div>
        </div>
        \${tableHtml}
      </div>\`;
    }).join('')}
  </div>\`;
  const dateOptions = availableDates.map(d => \`<option value="\${d}" \${d===STOCK_STATE.singleDate?'selected':''}>\${d}\${d===availableDates[0]?' (most recent)':''}</option>\`).join('');
  const tableCard = \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0;color:#1f7a3a">Reports</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${displayDate}</span>
      <label style="font-size:12px;color:#334;display:flex;align-items:center;gap:6px">
        Show:
        <select id="stockSingleDate" style="padding:6px 8px;border:1px solid #ccd;border-radius:6px;font-size:12px">\${dateOptions || '<option>No data</option>'}</select>
      </label>
    </div>
    <div class="muted" style="font-size:12px;margin-bottom:10px">Click any row to view the remarks for each category.</div>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#eef">
        <th style="padding:6px 8px;text-align:left">Area Manager</th>
        <th style="padding:6px 8px;text-align:left">Date</th>
        <th style="padding:6px;text-align:center">Status</th>
        \${STOCK_CATS.map(c => '<th style="padding:6px;text-align:center;width:70px">'+c.icon+' '+c.name+'</th>').join('')}
        <th style="padding:6px 8px;text-align:left">Submitted At</th>
        <th style="padding:6px;text-align:center;width:30px"></th>
      </tr></thead>
      <tbody>\${reportsHtml || '<tr><td colspan="'+(5+STOCK_CATS.length)+'" style="padding:12px;text-align:center;color:#789">No reports for \${displayDate}</td></tr>'}</tbody>
    </table></div></div>\`;

  // ---- Urgent Stores table (OOS + Critical only, for the selected date) ----
  const urgent = [];
  filteredReports.forEach(r => {
    STOCK_CATS.forEach(c => {
      (r.categories[c.name] || []).forEach(e => {
        if (e.status === 'OOS' || e.status === 'Critical') {
          urgent.push({ store: e.store, category: c.name, catIcon: c.icon, status: e.status, remarks: e.remarks, manager: r.manager, timestamp: r.timestamp });
        }
      });
    });
  });
  // Count issues per store (for priority indicator)
  const perStoreCount = {}; const perStoreOOS = {};
  urgent.forEach(u => {
    perStoreCount[u.store] = (perStoreCount[u.store]||0) + 1;
    if (u.status === 'OOS') perStoreOOS[u.store] = (perStoreOOS[u.store]||0) + 1;
  });
  urgent.sort((a,b) => {
    // Priority: more OOS first, then more total issues, then store name, OOS before Critical within
    const oosDiff = (perStoreOOS[b.store]||0) - (perStoreOOS[a.store]||0);
    if (oosDiff !== 0) return oosDiff;
    const cntDiff = (perStoreCount[b.store]||0) - (perStoreCount[a.store]||0);
    if (cntDiff !== 0) return cntDiff;
    if (a.store !== b.store) return a.store.localeCompare(b.store);
    if (a.status !== b.status) return a.status === 'OOS' ? -1 : 1;
    return a.category.localeCompare(b.category);
  });
  const oosTotal = urgent.filter(u => u.status === 'OOS').length;
  const critTotal = urgent.filter(u => u.status === 'Critical').length;
  const storesAffected = Object.keys(perStoreCount).length;
  const urgentRows = urgent.map((u, i) => {
    const isFirstOfStore = i === 0 || urgent[i-1].store !== u.store;
    const priorityChip = isFirstOfStore ? (
      (perStoreOOS[u.store]||0) >= 2 ? '<span style="background:#c33;color:#fff;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:800;margin-left:6px">HIGH</span>'
      : (perStoreCount[u.store]||0) >= 3 ? '<span style="background:#e0a020;color:#fff;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:800;margin-left:6px">MED</span>'
      : ''
    ) : '';
    const opt = STOCK_OPTS.find(o => o.v === u.status);
    return \`<tr style="\${isFirstOfStore && i>0 ? 'border-top:2px solid #ddd' : ''}">
      <td style="padding:6px 8px;font-weight:\${isFirstOfStore?'700':'400'};font-size:13px">\${isFirstOfStore ? escapeHtml(u.store)+priorityChip : ''}</td>
      <td style="padding:6px 8px;color:#556;font-size:12px">\${isFirstOfStore ? escapeHtml(u.manager) : ''}</td>
      <td style="padding:6px 8px;font-size:13px">\${u.catIcon} \${u.category}</td>
      <td style="padding:6px 8px;text-align:center"><span style="background:\${opt.bg};color:\${opt.fg};padding:3px 10px;border-radius:12px;font-weight:700;font-size:11px">\${u.status}</span></td>
      <td style="padding:6px 8px;color:#456;font-size:12px">\${escapeHtml(u.remarks||'')||'<span class="muted">-</span>'}</td>
    </tr>\`;
  }).join('');
  // ---- Merchandising Watchlist (chronic issues) ----
  // Watchlist has its OWN date range that defaults to the full monRes range.
  const allWatchDates = [...new Set(monRes.reports.map(r => r.date))].sort();
  const defaultWFrom = allWatchDates[0] || STOCK_STATE.from;
  const defaultWTo   = allWatchDates[allWatchDates.length-1] || STOCK_STATE.to;
  const wFrom = STOCK_STATE.wFrom || defaultWFrom;
  const wTo   = STOCK_STATE.wTo   || defaultWTo;
  const wReports = monRes.reports.filter(r => (!wFrom || r.date >= wFrom) && (!wTo || r.date <= wTo));
  const perStoreIssue = {};
  // Track per-category status day sets so we can compute OOS/Critical/Healthy day counts per category
  wReports.forEach(r => {
    STOCK_CATS.forEach(c => {
      (r.categories[c.name] || []).forEach(e => {
        const s = perStoreIssue[e.store] = perStoreIssue[e.store] || {
          store: e.store, manager: r.manager,
          daysReported: new Set(), daysWithOOS: new Set(), daysWithCrit: new Set(),
          oosCount: 0, critCount: 0, catBreakdown: {},
          perCat: {} // { Rice: { oosDays:Set, critDays:Set, healthyDays:Set, allDays:Set } }
        };
        s.daysReported.add(r.date);
        const pc = s.perCat[c.name] = s.perCat[c.name] || { oosDays:new Set(), critDays:new Set(), healthyDays:new Set(), allDays:new Set(), byDate:{} };
        pc.allDays.add(r.date);
        pc.byDate[r.date] = e.status; // for sparkline
        if (e.status === 'OOS')      { s.daysWithOOS.add(r.date);  s.oosCount++;  s.catBreakdown[c.name] = (s.catBreakdown[c.name]||0) + 1; pc.oosDays.add(r.date); }
        else if (e.status === 'Critical') { s.daysWithCrit.add(r.date); s.critCount++; s.catBreakdown[c.name] = (s.catBreakdown[c.name]||0) + 1; pc.critDays.add(r.date); }
        else if (e.status === 'Healthy')  { pc.healthyDays.add(r.date); }
      });
    });
  });
  const watchlist = Object.values(perStoreIssue).map(s => {
    const daysReported = s.daysReported.size;
    const problemDays  = new Set([...s.daysWithOOS, ...s.daysWithCrit]).size;
    const rate = daysReported ? Math.round((problemDays / daysReported) * 100) : 0;
    const topCat = Object.entries(s.catBreakdown).sort((a,b) => b[1] - a[1])[0];
    // Per-category summary: { Rice: {oos, crit, healthy, total}, ... }
    const catSummary = {};
    STOCK_CATS.forEach(c => {
      const pc = s.perCat[c.name] || { oosDays:new Set(), critDays:new Set(), healthyDays:new Set(), allDays:new Set(), byDate:{} };
      catSummary[c.name] = { oos: pc.oosDays.size, crit: pc.critDays.size, healthy: pc.healthyDays.size, total: pc.allDays.size, byDate: pc.byDate };
    });
    return {
      store: s.store, manager: s.manager,
      daysReported, problemDays,
      oosDays: s.daysWithOOS.size, critDays: s.daysWithCrit.size,
      oosCount: s.oosCount, critCount: s.critCount,
      rate,
      topCategory: topCat ? topCat[0] + ' (' + topCat[1] + 'x)' : '-',
      catSummary
    };
  }).filter(s => s.problemDays > 0)
    .sort((a,b) => b.rate - a.rate || b.problemDays - a.problemDays || b.oosCount - a.oosCount || a.store.localeCompare(b.store));

  // Flag stores that need HQ escalation: rate >= 50% OR problemDays >= 3
  const flaggedStores = watchlist.filter(s => s.rate >= 50 || s.problemDays >= 3);
  STOCK_STATE.watchlist = watchlist;
  STOCK_STATE.flaggedStores = flaggedStores;
  STOCK_STATE.wReports = wReports;
  STOCK_STATE.wFromEffective = wFrom;
  STOCK_STATE.wToEffective = wTo;

  // Insert extra KPI tile into KPI row
  const chronicCard = kpi('&#127919;', flaggedStores.length, 'Chronic Stores', flaggedStores.length ? '#c33' : '#345', 'flag for HQ merch');
  // Replace kpiRow to include the chronic card at the end
  const kpiRow2 = \`<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">\${complianceCard}\${oosCard}\${critCard}\${healthyCard}\${onTimeCard}\${chronicCard}</div>\`;

  const rankMedal = (i) => i < 3 ? '#c33' : i < 6 ? '#e0a020' : '#345';
  const watchRows = watchlist.slice(0, 30).map((s, i) => {
    const flagged = s.rate >= 50 || s.problemDays >= 3;
    return \`<tr \${flagged ? 'style="background:#fff5f5"' : ''}>
      <td style="padding:6px;text-align:center;background:\${rankMedal(i)};color:#fff;font-weight:700;font-size:12px">\${i+1}</td>
      <td style="padding:6px 8px;font-weight:700;font-size:13px">\${escapeHtml(s.store)}\${flagged ? ' <span style="background:#c33;color:#fff;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:800;margin-left:4px">FLAG HQ</span>' : ''}</td>
      <td style="padding:6px 8px;color:#556;font-size:12px">\${escapeHtml(s.manager||'')}</td>
      <td style="padding:6px;text-align:center;font-size:12px">\${s.daysReported}</td>
      <td style="padding:6px;text-align:center;color:#c33;font-weight:700;font-size:12px">\${s.problemDays}</td>
      <td style="padding:6px;text-align:center;color:#c33;font-weight:700;font-size:12px">\${s.oosCount}</td>
      <td style="padding:6px;text-align:center;color:#b8860b;font-weight:700;font-size:12px">\${s.critCount}</td>
      <td style="padding:6px 8px;font-size:12px">\${escapeHtml(s.topCategory)}</td>
      <td style="padding:6px;text-align:right"><span style="background:\${s.rate>=70?'#c33':s.rate>=40?'#e0a020':'#345'};color:#fff;padding:3px 10px;border-radius:12px;font-weight:700;font-size:12px">\${s.rate}%</span></td>
    </tr>\`;
  }).join('');
  const watchCard = \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0;color:#c33">&#128204; Merchandising Watchlist - Chronic OOS &amp; Critical</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${wFrom} to \${wTo}</span>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px;padding:8px 10px;background:#f4faf6;border-radius:6px">
      <div><label style="display:block;font-size:11px;color:#556;margin-bottom:2px">Watchlist From</label><input id="wFromIn" type="date" value="\${wFrom}" style="padding:6px 8px;border:1px solid #ccd;border-radius:6px;font-size:12px"/></div>
      <div><label style="display:block;font-size:11px;color:#556;margin-bottom:2px">Watchlist To</label><input id="wToIn" type="date" value="\${wTo}" style="padding:6px 8px;border:1px solid #ccd;border-radius:6px;font-size:12px"/></div>
      <button id="wApplyBtn" style="padding:8px 14px">Apply</button>
      <button id="wResetBtn" class="ghost" style="padding:8px 14px">Reset (all dates)</button>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:8px">
      <div class="muted" style="font-size:12px;flex:1;min-width:200px">Ranked by problem rate across the whole date range. <b>FLAG HQ</b> = 50%+ of reported days had issues, OR 3+ problem days.</div>
      <button id="watchExportBtn" style="background:#c33">&#128228; Export Flagged Stores to HQ</button>
    </div>
    \${watchlist.length ? \`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#eef">
        <th style="padding:6px;width:40px;text-align:center">Rank</th>
        <th style="padding:6px 8px;text-align:left">Store</th>
        <th style="padding:6px 8px;text-align:left">Area Manager</th>
        <th style="padding:6px;text-align:center;width:70px">Days Reported</th>
        <th style="padding:6px;text-align:center;width:70px">Problem Days</th>
        <th style="padding:6px;text-align:center;width:60px">OOS Instances</th>
        <th style="padding:6px;text-align:center;width:70px">Critical Instances</th>
        <th style="padding:6px 8px;text-align:left">Top Category</th>
        <th style="padding:6px;text-align:right;width:80px">Problem Rate</th>
      </tr></thead>
      <tbody>\${watchRows}</tbody></table></div>\` : '<div style="padding:12px;text-align:center;background:#e8f5ec;color:#1f7a3a;font-weight:700;border-radius:6px">No stores with chronic issues in this range.</div>'}
  </div>\`;

  const urgentCard = \`<div class="card" \${urgent.length ? 'style="border-left:6px solid #c33"' : ''}>
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0;color:#c33">&#128680; Stores Needing Urgent Attention</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${displayDate}</span>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">
      <span style="background:#c33;color:#fff;padding:4px 12px;border-radius:8px;font-weight:700;font-size:13px">\${oosTotal} OOS</span>
      <span style="background:#e0a020;color:#fff;padding:4px 12px;border-radius:8px;font-weight:700;font-size:13px">\${critTotal} Critical</span>
      <span style="background:#345;color:#fff;padding:4px 12px;border-radius:8px;font-weight:700;font-size:13px">\${storesAffected} store\${storesAffected===1?'':'s'} affected</span>
    </div>
    \${urgent.length ? \`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#eef">
        <th style="padding:6px 8px;text-align:left">Store</th>
        <th style="padding:6px 8px;text-align:left">Area Manager</th>
        <th style="padding:6px 8px;text-align:left">Category</th>
        <th style="padding:6px 8px;text-align:center;width:90px">Status</th>
        <th style="padding:6px 8px;text-align:left">Remarks</th>
      </tr></thead>
      <tbody>\${urgentRows}</tbody></table></div>\` : '<div style="padding:14px;text-align:center;background:#e8f5ec;color:#1f7a3a;font-weight:700;border-radius:6px">All stores healthy for \${displayDate}. No urgent action needed.</div>'}
  </div>\`;

  $('#stockOut').innerHTML = kpiRow2 + filterCard + missingHtml + chartCard + formCard + tableCard + urgentCard + watchCard + historyCard;

  $('#stockApplyBtn').onclick = () => { STOCK_STATE.from = $('#stockFrom').value; STOCK_STATE.to = $('#stockTo').value; STOCK_STATE.singleDate = null; loadStockTab(); };
  $('#stockExportBtn').onclick = exportStockExcel;
  const sdSel = $('#stockSingleDate'); if (sdSel) sdSel.onchange = () => { STOCK_STATE.singleDate = sdSel.value; loadStockTab(); };
  const wexp = $('#watchExportBtn'); if (wexp) wexp.onclick = exportWatchlistHQ;
  const wApply = $('#wApplyBtn'); if (wApply) wApply.onclick = () => { STOCK_STATE.wFrom = $('#wFromIn').value; STOCK_STATE.wTo = $('#wToIn').value; loadStockTab(); };
  const wReset = $('#wResetBtn'); if (wReset) wReset.onclick = () => { STOCK_STATE.wFrom = null; STOCK_STATE.wTo = null; loadStockTab(); };

  // Wire up form buttons
  if (isAM && STOCK_STATE.amStores.length) {
    document.querySelectorAll('[data-stockcat]').forEach(btn => btn.onclick = () => {
      const cat = btn.dataset.stockcat, store = btn.dataset.stockstore, val = btn.dataset.stockval;
      if (!STOCK_STATE.entries[cat][store]) STOCK_STATE.entries[cat][store] = { status:'', remarks:'' };
      STOCK_STATE.entries[cat][store].status = val;
      renderStockForm();
    });
    document.querySelectorAll('[data-stockremarks]').forEach(ta => ta.oninput = () => {
      const cat = ta.dataset.stockremarks, store = ta.dataset.storeremarks;
      if (!STOCK_STATE.entries[cat][store]) STOCK_STATE.entries[cat][store] = { status:'', remarks:'' };
      STOCK_STATE.entries[cat][store].remarks = ta.value;
    });
    const sb = $('#stockSubmitBtn'); if (sb) sb.onclick = submitStock;
  }
}

function stockCategoryHTML(c, stores){
  const storeRows = stores.map(store => {
    const st = (STOCK_STATE.entries[c.name] && STOCK_STATE.entries[c.name][store]) || { status:'', remarks:'' };
    const btns = STOCK_OPTS.map(o => {
      const on = st.status === o.v;
      return \`<button type="button" data-stockcat="\${c.name}" data-stockstore="\${escapeHtml(store)}" data-stockval="\${o.v}" style="flex:1;background:\${on?o.bg:'#eef'};color:\${on?o.fg:'#334'};border:0;border-radius:6px;padding:8px 4px;font-weight:700;cursor:pointer;font-size:12px;min-width:70px">\${o.lbl}</button>\`;
    }).join('');
    return \`<div style="padding:10px 0;border-bottom:1px dashed #eee">
      <div style="font-weight:600;color:#334;font-size:13px;margin-bottom:6px">\${escapeHtml(store)}</div>
      <div style="display:flex;gap:6px;margin-bottom:6px;flex-wrap:wrap">\${btns}</div>
      <textarea data-stockremarks="\${c.name}" data-storeremarks="\${escapeHtml(store)}" placeholder="Remarks (optional)" style="min-height:36px;font-size:13px">\${escapeHtml(st.remarks||'')}</textarea>
    </div>\`;
  }).join('');
  return \`<div style="padding:12px 0;border-bottom:2px solid #1f7a3a;margin-bottom:6px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <div style="font-size:26px">\${c.icon}</div>
      <div style="font-weight:800;font-size:17px;color:#1f7a3a">\${c.name}</div>
    </div>
    <div style="padding-left:6px">\${storeRows}</div>
  </div>\`;
}

function renderStockForm(){
  document.querySelectorAll('[data-stockcat]').forEach(btn => {
    const cat = btn.dataset.stockcat, store = btn.dataset.stockstore, val = btn.dataset.stockval;
    const on = STOCK_STATE.entries[cat][store] && STOCK_STATE.entries[cat][store].status === val;
    const opt = STOCK_OPTS.find(o => o.v === val);
    btn.style.background = on ? opt.bg : '#eef';
    btn.style.color      = on ? opt.fg : '#334';
  });
}

function toggleAMHistory(am){
  STOCK_STATE.expanded[am] = !STOCK_STATE.expanded[am];
  loadStockTab();
}

function toggleReportRemarks(id){
  const el = document.getElementById('rpt_' + id);
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
}

function exportStockExcel(){
  const data = STOCK_STATE.lastData;
  if (!data) { alert('Load first'); return; }
  const scopeAMs = data.scopeAMs || [];
  const stats = data.amStats || {};
  const scoreBg = p => p>=80 ? '#1f7a3a' : p>=50 ? '#e0a020' : '#c33';
  const statusColor = (st) => st==='OOS' ? '#c33' : st==='Critical' ? '#e0a020' : st==='Healthy' ? '#1f7a3a' : '#789';
  const k = data.kpis;

  const summaryHtml = \`
    <table style="border-collapse:collapse;margin-bottom:14px">
      <tr><td style="padding:6px 12px;background:#\${(k.complianceRate>=80?'1f7a3a':k.complianceRate>=50?'e0a020':'c33')};color:#fff;font-weight:bold;width:120px;text-align:center">Compliance</td><td style="padding:6px 12px;font-weight:bold;font-size:18px">\${k.complianceRate}%</td><td style="padding:6px 12px;color:#789">\${k.submittedToday} of \${k.totalAMs} AMs today</td></tr>
      <tr><td style="padding:6px 12px;background:#c33;color:#fff;font-weight:bold;text-align:center">OOS</td><td style="padding:6px 12px;font-weight:bold">\${k.oosCount}</td><td style="padding:6px 12px;color:#789">categories out of stock today</td></tr>
      <tr><td style="padding:6px 12px;background:#e0a020;color:#fff;font-weight:bold;text-align:center">Critical</td><td style="padding:6px 12px;font-weight:bold">\${k.critCount}</td><td style="padding:6px 12px;color:#789">categories at critical today</td></tr>
      <tr><td style="padding:6px 12px;background:#1f7a3a;color:#fff;font-weight:bold;text-align:center">Healthy</td><td style="padding:6px 12px;font-weight:bold">\${k.healthyCount}</td><td style="padding:6px 12px;color:#789">categories healthy today</td></tr>
      <tr><td style="padding:6px 12px;background:#345;color:#fff;font-weight:bold;text-align:center">On Time</td><td style="padding:6px 12px;font-weight:bold">\${k.onTimeToday}</td><td style="padding:6px 12px;color:#789">AM reports submitted before 10AM</td></tr>
    </table>\`;

  const streakRows = scopeAMs.map(am => {
    const s = stats[am] || { streak:0, onTimeDays:0, lateDays:0, missedDays:0 };
    const total = s.onTimeDays + s.lateDays + s.missedDays;
    const rate = total ? Math.round((s.onTimeDays / total) * 100) : 0;
    const streakColor = s.streak >= 3 ? '#c33' : s.streak >= 1 ? '#e0a020' : '#1f7a3a';
    return \`<tr>
      <td style="border:1px solid #b0b0b0;padding:6px 8px;font-weight:bold">\${escapeHtml(am)}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;background:\${streakColor};color:#fff;font-weight:bold">\${s.streak}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#1f7a3a;font-weight:bold">\${s.onTimeDays}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#b8860b;font-weight:bold">\${s.lateDays}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;color:#c33;font-weight:bold">\${s.missedDays}</td>
      <td style="border:1px solid #b0b0b0;padding:6px;text-align:center;background:\${scoreBg(rate)};color:#fff;font-weight:bold">\${rate}%</td>
    </tr>\`;
  }).join('');

  // One row per (report × store) so Excel shows the per-store detail flat
  const reportRows = data.reports.slice(0, 500).flatMap(r => {
    const badge = r.onTime ? '<span style="background:#1f7a3a;color:#fff;padding:2px 8px;border-radius:8px;font-weight:bold;font-size:11px">ON TIME</span>' : '<span style="background:#c33;color:#fff;padding:2px 8px;border-radius:8px;font-weight:bold;font-size:11px">LATE</span>';
    // Collect the set of all stores present in this report across categories
    const storeSet = new Set();
    STOCK_CATS.forEach(c => (r.categories[c.name]||[]).forEach(e => storeSet.add(e.store)));
    const stores = [...storeSet];
    if (!stores.length) return [];
    return stores.map((store, idx) => {
      const cats = STOCK_CATS.map(c => {
        const e = (r.categories[c.name]||[]).find(x => x.store === store);
        if (!e) return '<td style="border:1px solid #b0b0b0;padding:5px;text-align:center;color:#bbb">-</td>';
        return '<td style="border:1px solid #b0b0b0;padding:5px;text-align:center;background:'+statusColor(e.status)+';color:#fff;font-weight:bold">'+e.status+'</td>';
      }).join('');
      const remarks = STOCK_CATS.map(c => {
        const e = (r.categories[c.name]||[]).find(x => x.store === store);
        return '<td style="border:1px solid #b0b0b0;padding:5px;font-size:11px">'+escapeHtml((e&&e.remarks)||'')+'</td>';
      }).join('');
      return \`<tr>
        <td style="border:1px solid #b0b0b0;padding:5px 8px;font-weight:bold">\${idx===0?escapeHtml(r.manager):''}</td>
        <td style="border:1px solid #b0b0b0;padding:5px 8px">\${idx===0?escapeHtml(r.date):''}</td>
        <td style="border:1px solid #b0b0b0;padding:5px 8px;font-weight:600">\${escapeHtml(store)}</td>
        <td style="border:1px solid #b0b0b0;padding:5px;text-align:center">\${idx===0?badge:''}</td>
        \${cats}
        \${remarks}
        <td style="border:1px solid #b0b0b0;padding:5px 8px;font-size:11px;color:#789">\${idx===0?new Date(r.timestamp).toLocaleString():''}</td>
      </tr>\`;
    });
  }).join('');

  const html = \`<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>Stock Status</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml></head>
<body style="font-family:Calibri,Arial,sans-serif">
  <h1 style="color:#1f7a3a;text-align:center;margin:0 0 8px">Focus 5 Stock Status Report</h1>
  <div style="text-align:center;color:#789;margin-bottom:14px">\${STOCK_STATE.from} to \${STOCK_STATE.to} - Generated \${new Date().toLocaleString()}</div>
  <h2 style="color:#1f7a3a">Summary - Today</h2>
  \${summaryHtml}
  <h2 style="color:#1f7a3a">Per-AM Statistics (\${STOCK_STATE.from} to \${STOCK_STATE.to})</h2>
  <table style="border-collapse:collapse;font-size:12px;margin-bottom:14px">
    <thead><tr style="background:#1f7a3a;color:#fff"><th style="border:1px solid #b0b0b0;padding:8px;text-align:left">Area Manager</th><th style="border:1px solid #b0b0b0;padding:8px">Current Streak (days)</th><th style="border:1px solid #b0b0b0;padding:8px">On Time</th><th style="border:1px solid #b0b0b0;padding:8px">Late</th><th style="border:1px solid #b0b0b0;padding:8px">Missed</th><th style="border:1px solid #b0b0b0;padding:8px">On-Time %</th></tr></thead>
    <tbody>\${streakRows}</tbody>
  </table>
  <h2 style="color:#1f7a3a">All Reports</h2>
  <table style="border-collapse:collapse;font-size:11px">
    <thead><tr style="background:#1f7a3a;color:#fff"><th style="border:1px solid #b0b0b0;padding:6px 8px;text-align:left">Area Manager</th><th style="border:1px solid #b0b0b0;padding:6px 8px;text-align:left">Date</th><th style="border:1px solid #b0b0b0;padding:6px 8px;text-align:left">Store</th><th style="border:1px solid #b0b0b0;padding:6px">Status</th>\${STOCK_CATS.map(c => '<th style="border:1px solid #b0b0b0;padding:6px">'+c.name+'</th>').join('')}\${STOCK_CATS.map(c => '<th style="border:1px solid #b0b0b0;padding:6px">'+c.name+' Remarks</th>').join('')}<th style="border:1px solid #b0b0b0;padding:6px 8px">Submitted At</th></tr></thead>
    <tbody>\${reportRows}</tbody>
  </table>
</body></html>\`;
  const blob = new Blob(['\\ufeff'+html], {type:'application/vnd.ms-excel'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'Focus5_Stock_Status_' + todayStr() + '.xls';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportWatchlistHQ(){
  const data = STOCK_STATE.lastData;
  const flagged = STOCK_STATE.flaggedStores || [];
  const wReports = STOCK_STATE.wReports || (data && data.reports) || [];
  if (!data) { alert('Load first'); return; }
  if (!flagged.length) { alert('No stores flagged for HQ escalation in this range.'); return; }

  const DARK = '#1f7a3a', DARKER = '#155a2b', LIGHT_BG = '#e8f5ec', LIGHTER = '#f4faf6';
  const OOS_C = '#c33', CRIT_C = '#e0a020';

  // Build per-store detailed incident list from reports in the watchlist range
  const incidentsByStore = {};
  wReports.forEach(r => {
    STOCK_CATS.forEach(c => {
      (r.categories[c.name]||[]).forEach(e => {
        if (e.status !== 'OOS' && e.status !== 'Critical') return;
        if (!incidentsByStore[e.store]) incidentsByStore[e.store] = [];
        incidentsByStore[e.store].push({ date: r.date, manager: r.manager, category: c.name, status: e.status, remarks: e.remarks || '' });
      });
    });
  });
  Object.values(incidentsByStore).forEach(list => list.sort((a,b) => b.date.localeCompare(a.date) || (a.status==='OOS'?-1:1)));

  // Cover header
  const headerBlock = \`
    <div style="background:\${DARK};color:#fff;padding:18px 24px;margin:0 0 4px">
      <div style="font-size:22px;font-weight:bold;letter-spacing:.5px">MERCHANDISING ESCALATION REPORT</div>
      <div style="font-size:14px;opacity:.92;margin-top:4px">Focus 5 Stock Status - Stores Flagged for HQ Review</div>
    </div>
    <table style="border-collapse:collapse;margin:0 0 18px;font-size:12px">
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Reporting Period</td><td style="padding:6px 12px">\${STOCK_STATE.wFromEffective || STOCK_STATE.from} to \${STOCK_STATE.wToEffective || STOCK_STATE.to}</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Prepared By</td><td style="padding:6px 12px">\${escapeHtml(S.manager)} (\${escapeHtml(S.level)})</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Generated</td><td style="padding:6px 12px">\${new Date().toLocaleString()}</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Flag Criteria</td><td style="padding:6px 12px">Problem rate &ge; 50% OR 3+ problem days in the period</td></tr>
    </table>\`;

  // Executive KPIs
  const totOOS = flagged.reduce((n,s) => n+s.oosCount, 0);
  const totCrit = flagged.reduce((n,s) => n+s.critCount, 0);
  const totProbDays = flagged.reduce((n,s) => n+s.problemDays, 0);
  const kpiBlock = \`
    <table style="border-collapse:collapse;margin-bottom:18px;font-size:13px">
      <tr>
        <td style="padding:14px 20px;background:\${OOS_C};color:#fff;font-weight:bold;text-align:center;min-width:120px">
          <div style="font-size:28px">\${flagged.length}</div>
          <div style="font-size:11px;letter-spacing:.5px">STORES FLAGGED</div>
        </td>
        <td style="padding:14px 20px;background:\${OOS_C};color:#fff;font-weight:bold;text-align:center;min-width:120px">
          <div style="font-size:28px">\${totOOS}</div>
          <div style="font-size:11px;letter-spacing:.5px">OOS INSTANCES</div>
        </td>
        <td style="padding:14px 20px;background:\${CRIT_C};color:#fff;font-weight:bold;text-align:center;min-width:120px">
          <div style="font-size:28px">\${totCrit}</div>
          <div style="font-size:11px;letter-spacing:.5px">CRITICAL INSTANCES</div>
        </td>
        <td style="padding:14px 20px;background:\${DARK};color:#fff;font-weight:bold;text-align:center;min-width:120px">
          <div style="font-size:28px">\${totProbDays}</div>
          <div style="font-size:11px;letter-spacing:.5px">STORE-DAYS AFFECTED</div>
          <div style="font-size:10px;opacity:.85;font-weight:normal;margin-top:2px">sum of problem days across flagged stores</div>
        </td>
      </tr>
    </table>\`;

  // Flagged stores overview - simplified store x category matrix
  const th = (t, w) => \`<th style="background:\${DARK};color:#fff;padding:8px 10px;border:1px solid \${DARKER};font-weight:bold;text-align:left;\${w?'width:'+w:''}">\${t}</th>\`;
  // Build the full ordered date list across the whole watchlist range for sparklines
  const rangeDatesSet = new Set();
  wReports.forEach(r => rangeDatesSet.add(r.date));
  const rangeDatesSorted = [...rangeDatesSet].sort(); // oldest -> newest
  const colorForStatus = (st) => st === 'OOS' ? OOS_C : st === 'Critical' ? CRIT_C : st === 'Healthy' ? DARK : '#dcdcdc';
  const sparkline = (byDate) => {
    if (!rangeDatesSorted.length) return '';
    const bars = rangeDatesSorted.map(d => {
      const st = byDate ? byDate[d] : null;
      return \`<span style="display:inline-block;width:7px;height:8px;background:\${colorForStatus(st)};margin-right:1px"></span>\`;
    }).join('');
    return \`<div style="margin-top:4px;line-height:0;white-space:nowrap">\${bars}</div>\`;
  };
  const catCell = (cs) => {
    if (!cs || cs.total === 0) {
      return \`<td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:#f0f0f0;color:#888;font-style:italic;font-size:11px">No data\${sparkline(null)}</td>\`;
    }
    let label, bg, fg = '#fff';
    if (cs.oos > 0)      { label = 'With OOS ('      + cs.oos     + ' Day' + (cs.oos===1?'':'s')     + ')'; bg = OOS_C; }
    else if (cs.crit > 0){ label = 'With Critical (' + cs.crit    + ' Day' + (cs.crit===1?'':'s')    + ')'; bg = CRIT_C; }
    else                 { label = 'Healthy ('       + cs.healthy + ' Day' + (cs.healthy===1?'':'s') + ')'; bg = DARK; }
    return \`<td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${bg};color:\${fg};font-weight:bold;font-size:11px">\${label}\${sparkline(cs.byDate)}</td>\`;
  };
  const priorityFor = (s) => {
    if (s.oosCount >= 5 || s.rate >= 80) return { label:'HIGH', bg: OOS_C };
    if (s.oosCount >= 2 || s.rate >= 50) return { label:'MED',  bg: CRIT_C };
    return { label:'LOW', bg: DARK };
  };
  const overviewRows = flagged.map((s, i) => {
    const catCells = STOCK_CATS.map(c => catCell(s.catSummary && s.catSummary[c.name])).join('');
    const rateBg = s.rate >= 70 ? OOS_C : s.rate >= 40 ? CRIT_C : DARK;
    const p = priorityFor(s);
    return \`<tr style="background:\${i%2===0?'#ffffff':LIGHTER}">
      <td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${OOS_C};color:#fff;font-weight:bold">\${i+1}</td>
      <td style="border:1px solid #cfd8d3;padding:6px 10px;font-weight:bold;color:\${DARKER};font-size:12px">\${escapeHtml(s.store)}<div style="font-weight:normal;font-size:10px;color:#556;margin-top:2px">\${escapeHtml(s.manager)}</div></td>
      \${catCells}
      <td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${rateBg};color:#fff;font-weight:bold">\${s.rate}%</td>
      <td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${p.bg};color:#fff;font-weight:bold;letter-spacing:.5px">\${p.label}</td>
    </tr>\`;
  }).join('');

  // Store count summary
  const allStoresInScope = new Set();
  wReports.forEach(r => STOCK_CATS.forEach(c => (r.categories[c.name]||[]).forEach(e => allStoresInScope.add(e.store))));
  const totalStoresSeen = allStoresInScope.size;
  const flaggedPct = totalStoresSeen ? Math.round((flagged.length / totalStoresSeen) * 100) : 0;
  const summaryLine = totalStoresSeen ? \`<div style="margin:6px 0 14px;padding:8px 12px;background:\${LIGHT_BG};border-left:4px solid \${DARK};font-size:12px;color:\${DARKER}"><b>\${flagged.length}</b> of <b>\${totalStoresSeen}</b> stores flagged for HQ escalation in this period (<b>\${flaggedPct}%</b>). Remaining \${totalStoresSeen - flagged.length} store(s) either meet compliance or had only isolated issues.</div>\` : '';

  const legendLine = \`<div style="margin:4px 0 6px;font-size:10px;color:#556">Sparkline bars = each reported day in the range, oldest to newest. <span style="display:inline-block;width:8px;height:8px;background:\${OOS_C};vertical-align:-1px;margin:0 3px"></span>OOS <span style="display:inline-block;width:8px;height:8px;background:\${CRIT_C};vertical-align:-1px;margin:0 3px"></span>Critical <span style="display:inline-block;width:8px;height:8px;background:\${DARK};vertical-align:-1px;margin:0 3px"></span>Healthy <span style="display:inline-block;width:8px;height:8px;background:#dcdcdc;vertical-align:-1px;margin:0 3px"></span>No data</div>\`;

  const overviewBlock = \`
    <div style="background:\${DARK};color:#fff;padding:8px 12px;margin-top:6px;font-weight:bold;font-size:14px;letter-spacing:.3px">FLAGGED STORES OVERVIEW</div>
    <div style="color:#556;font-size:11px;margin:4px 0 4px">Each category cell shows the worst status recorded in the period, with the number of days at that status. Priority column combines OOS count and problem rate. Sorted worst first.</div>
    \${legendLine}
    \${summaryLine}
    <table style="border-collapse:collapse;font-size:12px;margin-bottom:22px">
      <thead><tr>\${th('#','40px')}\${th('Store','160px')}\${STOCK_CATS.map(c => th(c.name,'120px')).join('')}\${th('Problem Rate','80px')}\${th('Priority','70px')}</tr></thead>
      <tbody>\${overviewRows}</tbody>
    </table>\`;

  // Detailed findings per store — per-category summary + incident log
  const detailBlocks = flagged.map((s, idx) => {
    const incs = incidentsByStore[s.store] || [];
    // Per-category day-count summary
    const catSumRows = STOCK_CATS.map(c => {
      const cs = (s.catSummary && s.catSummary[c.name]) || { oos:0, crit:0, healthy:0, total:0 };
      const worstBg = cs.oos > 0 ? OOS_C : cs.crit > 0 ? CRIT_C : DARK;
      const isFlagged = cs.oos > 0 || cs.crit > 0;
      return \`<tr style="background:\${isFlagged ? '#fff5f5' : LIGHTER}">
        <td style="border:1px solid #cfd8d3;padding:5px 10px;font-weight:bold">\${c.name}</td>
        <td style="border:1px solid #cfd8d3;padding:5px;text-align:center;\${cs.oos>0?'background:'+OOS_C+';color:#fff;font-weight:bold':'color:#888'}">\${cs.oos}</td>
        <td style="border:1px solid #cfd8d3;padding:5px;text-align:center;\${cs.crit>0?'background:'+CRIT_C+';color:#fff;font-weight:bold':'color:#888'}">\${cs.crit}</td>
        <td style="border:1px solid #cfd8d3;padding:5px;text-align:center;\${cs.healthy>0?'background:'+DARK+';color:#fff;font-weight:bold':'color:#888'}">\${cs.healthy}</td>
        <td style="border:1px solid #cfd8d3;padding:5px;text-align:center;font-weight:bold">\${cs.total}</td>
      </tr>\`;
    }).join('');
    const incRows = incs.map((inc, i) => \`<tr style="background:\${i%2===0?'#ffffff':LIGHTER}">
      <td style="border:1px solid #cfd8d3;padding:5px 10px">\${escapeHtml(inc.date)}</td>
      <td style="border:1px solid #cfd8d3;padding:5px 10px">\${escapeHtml(inc.category)}</td>
      <td style="border:1px solid #cfd8d3;padding:5px 10px;text-align:center;background:\${inc.status==='OOS'?OOS_C:CRIT_C};color:#fff;font-weight:bold;font-size:11px">\${inc.status}</td>
      <td style="border:1px solid #cfd8d3;padding:5px 10px">\${escapeHtml(inc.remarks) || '<span style=\"color:#888;font-style:italic\">no remarks</span>'}</td>
    </tr>\`).join('');
    const noRows = \`<tr><td colspan="4" style="padding:8px 10px;color:#666;font-style:italic;border:1px solid #cfd8d3">No detailed incidents recorded.</td></tr>\`;
    return \`
      <table style="border-collapse:collapse;font-size:12px;margin:18px 0 4px;width:100%">
        <tr>
          <td colspan="5" style="background:\${DARKER};color:#fff;padding:10px 12px;font-weight:bold;font-size:14px;border:1px solid \${DARKER}">
            \${idx+1}. \${escapeHtml(s.store)}
            <span style="opacity:.9;font-weight:normal;font-size:11px;margin-left:10px">
              Area Manager: \${escapeHtml(s.manager)} &nbsp;|&nbsp; \${s.problemDays}/\${s.daysReported} problem days (\${s.rate}%) &nbsp;|&nbsp; OOS \${s.oosCount} &nbsp;|&nbsp; Critical \${s.critCount}
            </span>
          </td>
        </tr>
        <tr>
          <td colspan="5" style="padding:6px 10px;background:#eef;font-weight:bold;font-size:11px;color:\${DARKER};border:1px solid #cfd8d3">CATEGORY SUMMARY (day counts)</td>
        </tr>
        <tr>\${th('Category','110px')}\${th('OOS Days','70px')}\${th('Critical Days','80px')}\${th('Healthy Days','80px')}\${th('Total Days Reported','90px')}</tr>
        \${catSumRows}
      </table>
      <table style="border-collapse:collapse;font-size:12px;margin:2px 0 4px;width:100%">
        <tr>
          <td colspan="4" style="padding:6px 10px;background:#eef;font-weight:bold;font-size:11px;color:\${DARKER};border:1px solid #cfd8d3">INCIDENT LOG (\${incs.length} entries)</td>
        </tr>
        <tr>\${th('Date','90px')}\${th('Category','110px')}\${th('Status','70px')}\${th('Remarks / Details')}</tr>
        \${incRows || noRows}
      </table>\`;
  }).join('');

  const html = \`<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>HQ Escalation</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml></head>
<body style="font-family:Calibri,Arial,sans-serif;padding:0;margin:0">
  \${headerBlock}
  \${kpiBlock}
  \${overviewBlock}
  <div style="background:\${DARK};color:#fff;padding:8px 12px;margin-top:6px;font-weight:bold;font-size:14px;letter-spacing:.3px">DETAILED FINDINGS PER STORE</div>
  <div style="color:#556;font-size:11px;margin:4px 0 8px">Every OOS and Critical incident for each flagged store, newest first. Use these details to drive replenishment and root-cause conversations.</div>
  \${detailBlocks}
  <div style="margin-top:22px;padding:10px 14px;background:\${LIGHT_BG};border-left:4px solid \${DARK};font-size:12px;color:\${DARKER}">
    <b>Requested action:</b> please review flagged stores and confirm replenishment / delivery status. Priority to stores with 70%+ problem rate and highest OOS instances.
  </div>
</body></html>\`;

  const blob = new Blob(['\\ufeff'+html], {type:'application/vnd.ms-excel'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'HQ_Escalation_' + todayStr() + '.xls';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function submitStock(){
  $('#stockErr').textContent = '';
  const entries = [];
  const missing = [];
  STOCK_CATS.forEach(c => {
    STOCK_STATE.amStores.forEach(store => {
      const st = (STOCK_STATE.entries[c.name] && STOCK_STATE.entries[c.name][store]) || { status:'', remarks:'' };
      if (!st.status) missing.push(c.name + ' / ' + store);
      entries.push({ category: c.name, store, status: st.status, remarks: st.remarks });
    });
  });
  if (missing.length) { $('#stockErr').textContent = 'Please select a status for: ' + missing.slice(0,5).join(', ') + (missing.length>5?' and '+(missing.length-5)+' more':''); return; }
  // Warn if past 10 AM AND this is an update (previous submission exists)
  const now = new Date();
  const pastDeadline = (now.getHours() > 10) || (now.getHours() === 10 && now.getMinutes() > 0);
  const isUpdate = ($('#stockSubmitBtn')||{}).textContent === 'Update Report';
  if (pastDeadline && isUpdate) {
    const proceed = confirm('It is already past 10 AM. Updating now will change your badge to LATE. Continue?');
    if (!proceed) return;
  }
  const btn = $('#stockSubmitBtn'); btn.disabled = true; const orig = btn.textContent; btn.textContent = 'Submitting...';
  const r = await api('/api/stock-submit', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ manager: S.manager, date: todayStr(), entries }) });
  btn.disabled = false; btn.textContent = orig;
  if (!r.ok) { $('#stockErr').textContent = r.error || 'Failed'; return; }
  alert('Stock Status Report submitted');
  loadStockTab();
}

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
