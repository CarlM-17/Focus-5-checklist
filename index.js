// Fresh Focus 5 - Fresh Department Checklist (Railway)
// Two-file Node/Express app. Native https + crypto for Google Sheets (no googleapis package).

const express = require('express');
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

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
// ---------- Email-based user accounts (signup / approval / email login) ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return 'scrypt$' + salt + '$' + derived;
}
function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  if (!stored.startsWith('scrypt$')) return false;
  const [, salt, hash] = stored.split('$');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(derived, 'hex'));
}

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, fullName, level, assignedStores } = req.body || {};
    if (!email || !password || !fullName || !level) return res.json({ ok:false, error:'Email, password, full name and position are required' });
    if (!['Regional Manager','Area Manager','Store Manager'].includes(level)) return res.json({ ok:false, error:'Invalid position' });
    if (level === 'Area Manager' && (!Array.isArray(assignedStores) || !assignedStores.length)) return res.json({ ok:false, error:'Area Managers must select at least one store' });
    if (level === 'Store Manager' && (!Array.isArray(assignedStores) || assignedStores.length !== 1)) return res.json({ ok:false, error:'Store Managers must select exactly one store' });
    if (password.length < 6) return res.json({ ok:false, error:'Password must be at least 6 characters' });
    const emailLc = String(email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLc)) return res.json({ ok:false, error:'Invalid email format' });
    const existing = await sheetsGet('UserAccounts!A2:J');
    const dup = existing.some(r => (r[0]||'').trim().toLowerCase() === emailLc);
    if (dup) return res.json({ ok:false, error:'This email is already registered' });
    // Regional Manager is restricted: ONLY allowed for the very first signup (bootstrap). After that, blocked.
    const anyApprovedRM = existing.some(r => (r[5]||'').trim() === 'Approved' && (r[3]||'').trim().toLowerCase() === 'regional manager');
    if (level === 'Regional Manager' && anyApprovedRM) {
      return res.json({ ok:false, error:'Regional Manager signup is disabled. Contact the current Regional Manager.' });
    }
    const autoApprove = (level === 'Regional Manager' && !anyApprovedRM);
    const status = autoApprove ? 'Approved' : 'Pending';
    const approvedBy = autoApprove ? 'bootstrap (first RM)' : '';
    const approvedAt = autoApprove ? new Date().toISOString() : '';
    const storesJson = (level === 'Regional Manager') ? '' : JSON.stringify(assignedStores || []);
    const row = [[emailLc, hashPassword(password), String(fullName).trim(), level, '', status, new Date().toISOString(), approvedBy, approvedAt, storesJson]];
    await sheetsAppend('UserAccounts!A1:J1', row);
    const msg = autoApprove
      ? 'Account created and auto-approved (first Regional Manager). You can now log in.'
      : 'Signup received. Waiting for Regional Manager approval.';
    res.json({ ok:true, message: msg, autoApproved: autoApprove });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/user-directory', async (req, res) => {
  try {
    const dir = {};
    // Primary: approved UserAccounts
    const uaRows = await sheetsGet('UserAccounts!A2:J');
    uaRows.forEach(r => {
      const email = (r[0]||'').trim().toLowerCase();
      if (!email) return;
      const fullName = (r[2]||'').trim();
      const level = (r[3]||'').trim();
      const linked = (r[4]||'').trim();
      const status = (r[5]||'').trim();
      if (status !== 'Approved') return;
      dir[email] = { fullName: fullName || email, level };
      if (linked) dir[linked.toLowerCase()] = { fullName: fullName || linked, level };
    });
    // Fallback: legacy AreaManagers + StoreManagers
    try {
      const am = await sheetsGet('AreaManagers!A2:C');
      am.forEach(r => { const u = (r[0]||'').trim(); if (u && !dir[u.toLowerCase()]) dir[u.toLowerCase()] = { fullName: u, level: (r[2]||'Area Manager').trim() }; });
    } catch (_) {}
    try {
      const sm = await sheetsGet('StoreManagers!A2:C');
      sm.forEach(r => { const u = (r[0]||'').trim(); const n = (r[1]||'').trim(); if (u && !dir[u.toLowerCase()]) dir[u.toLowerCase()] = { fullName: n || u, level: 'Store Manager' }; });
    } catch (_) {}
    res.json({ ok:true, directory: dir });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/has-rm', async (req, res) => {
  try {
    const rows = await sheetsGet('UserAccounts!A2:J');
    const hasRM = rows.some(r => (r[5]||'').trim() === 'Approved' && (r[3]||'').trim().toLowerCase() === 'regional manager');
    res.json({ ok:true, hasRM });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/all-stores', async (req, res) => {
  try {
    const rows = await sheetsGet('ListOfStores!A2:G');
    const stores = rows.map(r => ({ id: String(r[3]||'').trim(), name: String(r[4]||'').trim(), area: String(r[2]||'').trim(), region: String(r[1]||'').trim() })).filter(s => s.name);
    res.json({ ok:true, stores });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.post('/api/login-email', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const emailLc = String(email || '').trim().toLowerCase();
    if (!emailLc || !password) return res.json({ ok:false, error:'Email and password required' });
    const rows = await sheetsGet('UserAccounts!A2:J');
    const user = rows.find(r => (r[0]||'').trim().toLowerCase() === emailLc);
    if (!user) return res.json({ ok:false, error:'Invalid email or password' });
    if (!verifyPassword(password, user[1])) return res.json({ ok:false, error:'Invalid email or password' });
    const status = (user[5] || '').trim();
    if (status === 'Pending')  return res.json({ ok:false, error:'Your account is pending Regional Manager approval' });
    if (status === 'Rejected') return res.json({ ok:false, error:'Your account was rejected. Contact the Regional Manager.' });
    if (status !== 'Approved') return res.json({ ok:false, error:'Account not approved' });
    const level = (user[3] || '').trim();
    const linked = (user[4] || '').trim();
    let assignedStores = [];
    try { assignedStores = JSON.parse(user[9] || '[]'); } catch (_) { assignedStores = []; }
    // Resolve storeName/area for Store Manager — prefer assignedStores[0], fall back to linked
    let storeId = null, storeName = null, area = null;
    if (level.toLowerCase() === 'store manager') {
      const pickedRaw = assignedStores[0] || linked || '';
      const picked = String(pickedRaw).trim();
      const pickedLc = picked.toLowerCase();
      if (picked) {
        const stores = await sheetsGet('ListOfStores!A2:G');
        const storeRow =
          stores.find(r => String(r[4]||'').trim().toLowerCase() === pickedLc)
          || stores.find(r => String(r[3]||'').trim() === picked)
          || stores.find(r => {
              const n = String(r[4]||'').trim().toLowerCase();
              return n && (n === pickedLc || pickedLc.startsWith(n+' ') || n.startsWith(pickedLc+' '));
          });
        if (storeRow) { storeId = String(storeRow[3]||'').trim(); storeName = (storeRow[4] || '').trim(); area = (storeRow[2] || '').trim(); }
      }
    }
    res.json({
      ok: true,
      manager: linked || user[2] || emailLc,
      level,
      storeId, storeName, area,
      email: emailLc,
      fullName: user[2] || '',
      assignedStores
    });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

// Check if a requester is a Regional Manager — accepts either an approved email account OR a legacy AreaManagers row
async function isRegionalManager(email, username) {
  if (email) {
    const rows = await sheetsGet('UserAccounts!A2:J');
    const u = rows.find(r => (r[0]||'').trim().toLowerCase() === String(email).trim().toLowerCase());
    if (u && (u[5]||'').trim() === 'Approved' && (u[3]||'').trim().toLowerCase() === 'regional manager') return true;
  }
  if (username) {
    const am = await sheetsGet('AreaManagers!A2:C');
    const u = am.find(r => (r[0]||'').trim().toLowerCase() === String(username).trim().toLowerCase());
    if (u && (u[2]||'').trim().toLowerCase() === 'regional manager') return true;
  }
  return false;
}

app.get('/api/user-accounts', async (req, res) => {
  try {
    const email = (req.query.email || '').trim().toLowerCase();
    const username = (req.query.username || '').trim();
    if (!(await isRegionalManager(email, username))) {
      return res.json({ ok:false, error:'Only Regional Managers can view accounts' });
    }
    const rows = await sheetsGet('UserAccounts!A2:J');
    const accounts = rows.map((r,i) => {
      let assignedStores = [];
      try { assignedStores = JSON.parse(r[9] || '[]'); } catch (_) {}
      return {
        row: i + 2,
        email: r[0], fullName: r[2], level: r[3], linkedUsername: r[4],
        status: r[5] || 'Pending', submittedAt: r[6], approvedBy: r[7], approvedAt: r[8],
        assignedStores
      };
    });
    res.json({ ok:true, accounts });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

async function requireRegional(req) {
  const email = ((req.body && req.body.requesterEmail) || '').trim().toLowerCase();
  const username = ((req.body && req.body.requesterUsername) || '').trim();
  if (!(await isRegionalManager(email, username))) {
    return { ok:false, error:'Only Regional Managers can perform this action' };
  }
  const rows = await sheetsGet('UserAccounts!A2:J');
  return { ok:true, rows, requester: email || username };
}

app.post('/api/approve-account', async (req, res) => {
  try {
    const check = await requireRegional(req);
    if (!check.ok) return res.json(check);
    const { email } = req.body || {};
    if (!email) return res.json({ ok:false, error:'email required' });
    const rows = check.rows;
    const idx = rows.findIndex(r => (r[0]||'').trim().toLowerCase() === String(email).trim().toLowerCase());
    if (idx === -1) return res.json({ ok:false, error:'Account not found' });
    const rowNum = idx + 2;
    await sheetsBatchUpdateValues([
      { range: 'UserAccounts!F' + rowNum, values: [['Approved']] },
      { range: 'UserAccounts!H' + rowNum, values: [[check.requester]] },
      { range: 'UserAccounts!I' + rowNum, values: [[new Date().toISOString()]] }
    ]);
    res.json({ ok:true });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.post('/api/reject-account', async (req, res) => {
  try {
    const check = await requireRegional(req);
    if (!check.ok) return res.json(check);
    const { email } = req.body || {};
    const idx = check.rows.findIndex(r => (r[0]||'').trim().toLowerCase() === String(email||'').trim().toLowerCase());
    if (idx === -1) return res.json({ ok:false, error:'Account not found' });
    const rowNum = idx + 2;
    await sheetsBatchUpdateValues([
      { range: 'UserAccounts!F' + rowNum, values: [['Rejected']] },
      { range: 'UserAccounts!H' + rowNum, values: [[check.requester]] },
      { range: 'UserAccounts!I' + rowNum, values: [[new Date().toISOString()]] }
    ]);
    res.json({ ok:true });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const check = await requireRegional(req);
    if (!check.ok) return res.json(check);
    const { email, newPassword } = req.body || {};
    if (!email || !newPassword || String(newPassword).length < 6) return res.json({ ok:false, error:'email + newPassword (6+ chars) required' });
    const idx = check.rows.findIndex(r => (r[0]||'').trim().toLowerCase() === String(email).trim().toLowerCase());
    if (idx === -1) return res.json({ ok:false, error:'Account not found' });
    const rowNum = idx + 2;
    await sheetsBatchUpdateValues([
      { range: 'UserAccounts!B' + rowNum, values: [[hashPassword(newPassword)]] }
    ]);
    res.json({ ok:true });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

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

    let assignedList = [];
    try { assignedList = JSON.parse(req.query.assigned || '[]'); } catch(_) { assignedList = []; }
    const assignedSet = new Set(assignedList.map(s => String(s||'').trim().toLowerCase()).filter(Boolean));

    const stores = await sheetsGet('ListOfStores!A2:G');
    const storeMap = {};
    const managerAreas = new Set();
    stores.forEach((r) => {
      const storeName = r[4], areaName = r[2] || '(no area)', mgr = r[6] || '';
      if (!storeName) return;
      storeMap[storeName] = { area: areaName };
      const isMine = mgr.trim().toLowerCase() === manager || assignedSet.has(String(storeName).trim().toLowerCase());
      if (isMine) managerAreas.add(areaName);
    });
    const allowedAreas = isRegional
      ? [...new Set(stores.map((r) => r[2] || '(no area)').filter(Boolean))]
      : [...managerAreas];
    const allowedStores = stores
      .filter((r) => {
        const areaName = r[2] || '(no area)';
        const storeName = r[4];
        const isMine = (r[6] || '').trim().toLowerCase() === manager || (storeName && assignedSet.has(String(storeName).trim().toLowerCase()));
        if (!isRegional && !isMine) return false;
        if (areaFilter && areaName !== areaFilter) return false;
        return !!storeName;
      })
      .map((r) => r[4]);

    const data = await sheetsGet('StoreChecklistData!A2:K');
    const rows = data.filter((r) => {
      if ((r[10] || 'ACTIVE') !== 'ACTIVE') return false;
      if (from && (r[4] || '') < from) return false;
      if (to && (r[4] || '') > to) return false;
      const areaOfRow = (storeMap[r[3]] || {}).area || '(unknown)';
      const rowStore = (r[3]||'').trim();
      if (!isRegional && !isStoreMgr) {
        const inAssigned = assignedSet.size ? assignedSet.has(rowStore.toLowerCase()) : false;
        if (!managerAreas.has(areaOfRow) && !inAssigned) return false;
        if (assignedSet.size && !inAssigned) return false;
      }
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
        if (!isRegional) {
          const inAssigned = assignedSet.has(String(storeName).trim().toLowerCase());
          if (assignedSet.size) {
            if (!inAssigned) return false;
          } else {
            if (!managerAreas.has(areaName)) return false;
          }
        }
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
// Region label used in report titles. Change here or set env REGION_NAME.
const REGION_NAME = process.env.REGION_NAME || 'CAMANAVA';

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

// ---------- Focus 5 SKU Checklist ----------
const SKU_STATUSES = ['Available', 'OOS'];
const SKU_SLOTS = ['AM', 'PM'];
// PH-hour deadlines per slot
const SKU_SLOT_DEADLINE_HR = { AM: 10, PM: 15 };
// Row shape: [0]ts [1]id [2]mgr [3]store [4]date [5]slot [6]cat [7]rank [8]sku [9]desc [10]status [11]remarks [12]recStatus
const skuRowSlot = (r) => ((r[5] || 'AM') + '').trim().toUpperCase();
const skuRowStatus = (r) => (r[10] || '').trim();
const skuRowRecStatus = (r) => (r[12] || 'ACTIVE').trim();

app.get('/api/sku-list', async (req, res) => {
  try {
    const storeId = String(req.query.storeId || '').trim();
    const store = (req.query.store || '').trim();
    if (!storeId && !store) return res.json({ ok:false, error:'storeId or store required' });
    const rows = await sheetsGet('Focus5SummarySKU!A2:H');
    const target = store.trim().toLowerCase();
    let filtered = rows.filter(r => storeId && String(r[0] || '').trim() === storeId);
    // Fallback: tolerant name match if ID yielded nothing (sheet may abbreviate name or use different code)
    if (!filtered.length && target) {
      filtered = rows.filter(r => {
        const n = (r[1] || '').trim().toLowerCase();
        if (!n) return false;
        return n === target || target.startsWith(n + ' ') || n.startsWith(target + ' ');
      });
    }
    if (!filtered.length) {
      const idsInSheet = [...new Set(rows.map(r => String(r[0]||'').trim()).filter(Boolean))].sort().join(', ');
      const namesInSheet = [...new Set(rows.map(r => (r[1]||'').trim()).filter(Boolean))].sort().join(', ');
      return res.json({ ok:true, items:[], diag:{ requestedId:storeId, requestedName:store, idsInSheet, namesInSheet }});
    }
    const items = filtered.map(r => ({
      storeCode: r[0], storeName: r[1], rank: parseInt(r[2]) || 0,
      sku: r[3], description: r[4], supplier: r[5], skuType: r[6], category: (r[7]||'').trim()
    }));
    res.json({ ok:true, items });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

async function markSKUEdited(storeMgr, date, newId) {
  const rows = await sheetsGet('SKUChecklistData!A2:M');
  const data = [];
  rows.forEach((r, i) => {
    if ((r[11] || 'ACTIVE') !== 'ACTIVE') return;
    if (newId && r[1] === newId) return;
    if ((r[2] || '').trim().toLowerCase() === storeMgr.trim().toLowerCase() && r[4] === date) {
      data.push({ range: `SKUChecklistData!L${i + 2}`, values: [['EDITED']] });
    }
  });
  if (data.length) await sheetsBatchUpdateValues(data);
}

app.post('/api/sku-submit', async (req, res) => {
  try {
    const { storeMgr, store, date, slot, entries } = req.body || {};
    if (!storeMgr || !store || !date || !slot || !Array.isArray(entries) || !entries.length) {
      return res.json({ ok:false, error:'Missing fields' });
    }
    if (!SKU_SLOTS.includes(slot)) return res.json({ ok:false, error:'Invalid slot (must be AM or PM)' });
    for (const e of entries) {
      if (!SKU_STATUSES.includes(e.status)) return res.json({ ok:false, error:'Invalid status for SKU ' + (e.sku||'') });
    }
    const twoDaysAgo = new Date(Date.now() - 2*86400*1000).toISOString().slice(0,10);
    if (date < twoDaysAgo) return res.json({ ok:false, error:'Back-dated checklists are not allowed' });
    // Lock per (mgr, date, slot): one submission per slot per day
    const existing = await sheetsGet('SKUChecklistData!A2:M');
    const alreadySubmitted = existing.some(r =>
      skuRowRecStatus(r) === 'ACTIVE' &&
      (r[2] || '').trim().toLowerCase() === storeMgr.trim().toLowerCase() &&
      r[4] === date &&
      skuRowSlot(r) === slot
    );
    if (alreadySubmitted) return res.json({ ok:false, error: slot + ' slot for ' + date + ' is already submitted. Submissions are locked once sent.' });
    const ts = new Date().toISOString();
    const id = 'KS' + Date.now();
    const rows = entries.map(e => [
      ts, id, storeMgr, store, date, slot,
      e.category || '', String(e.rank || ''), e.sku || '', e.description || '',
      e.status || '', e.remarks || '', 'ACTIVE'
    ]);
    await sheetsAppend('SKUChecklistData!A1:M1', rows);
    res.json({ ok:true, reportId: id });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/sku-latest', async (req, res) => {
  try {
    const storeMgr = (req.query.storeMgr || '').trim().toLowerCase();
    const date = (req.query.date || '').trim();
    const slot = (req.query.slot || '').trim().toUpperCase();
    if (!storeMgr || !date) return res.json({ ok:false, error:'storeMgr and date required' });
    const rows = await sheetsGet('SKUChecklistData!A2:M');
    const filtered = rows.filter(r =>
      skuRowRecStatus(r) === 'ACTIVE' &&
      (r[2] || '').trim().toLowerCase() === storeMgr &&
      r[4] === date &&
      (!slot || skuRowSlot(r) === slot)
    );
    if (!filtered.length) return res.json({ ok:true, entries: [] });
    const latestId = filtered.reduce((max, r) => r[1] > max ? r[1] : max, '');
    const latest = filtered.filter(r => r[1] === latestId);
    res.json({ ok:true, reportId: latestId, timestamp: latest[0][0], slot: skuRowSlot(latest[0]),
      entries: latest.map(r => ({ category:r[6], rank:parseInt(r[7])||0, sku:r[8], description:r[9], status:r[10], remarks:r[11] }))
    });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/sku-history', async (req, res) => {
  try {
    const storeMgr = (req.query.storeMgr || '').trim().toLowerCase();
    const from = (req.query.from || '').trim();
    const to = (req.query.to || '').trim();
    if (!storeMgr) return res.json({ ok:false, error:'storeMgr required' });
    const rows = await sheetsGet('SKUChecklistData!A2:M');
    const filtered = rows.filter(r =>
      skuRowRecStatus(r) === 'ACTIVE' &&
      (r[2] || '').trim().toLowerCase() === storeMgr &&
      (!from || (r[4] || '') >= from) &&
      (!to   || (r[4] || '') <= to)
    );
    // Pick latest ReportID per (date, slot)
    const bySlot = {};
    filtered.forEach(r => {
      const date = r[4]; const slot = skuRowSlot(r);
      if (!date) return;
      const k = date + '||' + slot;
      if (!bySlot[k] || r[1] > bySlot[k].id) bySlot[k] = { id: r[1], timestamp: r[0], date, slot };
    });
    // Aggregate per (date, slot)
    const entries = Object.values(bySlot).map(obj => {
      const rowsFor = filtered.filter(r => r[4] === obj.date && skuRowSlot(r) === obj.slot && r[1] === obj.id);
      const avail = rowsFor.filter(r => skuRowStatus(r) === 'Available').length;
      const oos   = rowsFor.filter(r => skuRowStatus(r) === 'OOS').length;
      const total = rowsFor.length;
      const sub = new Date(obj.timestamp);
      const phHour = (sub.getUTCHours() + 8) % 24;
      const subDatePH = new Date(sub.getTime() + 8*3600*1000).toISOString().slice(0,10);
      const deadline = SKU_SLOT_DEADLINE_HR[obj.slot] || 10;
      const onTime = (subDatePH < obj.date) || (subDatePH === obj.date && phHour < deadline);
      return { date: obj.date, slot: obj.slot, total, available: avail, oos, timestamp: obj.timestamp, onTime, reportId: obj.id };
    }).sort((a,b) => b.date.localeCompare(a.date) || a.slot.localeCompare(b.slot));
    res.json({ ok:true, entries });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/sku-rm-monitor', async (req, res) => {
  try {
    const date = (req.query.date || todayLocalPHstr()).trim();
    const todayStr = date;

    // SKU Checklist scope = ALL stores in ListOfStores (not limited to StoreManagers)
    const stores = await sheetsGet('ListOfStores!A2:G');
    const authorizedStores = stores
      .map(r => ({ id: String(r[3]||'').trim(), name: (r[4]||'').trim(), area: (r[2]||'').trim() }))
      .filter(s => s.name);

    const skuRows = await sheetsGet('SKUChecklistData!A2:M');

    // Pick latest ReportID per (store, slot) for TODAY
    const todayLatest = {};
    skuRows.forEach(r => {
      if ((r[12]||'ACTIVE') !== 'ACTIVE') return;
      if (r[4] !== todayStr) return;
      const k = (r[3]||'').trim() + '||' + ((r[5]||'AM')+'').trim().toUpperCase();
      if (!todayLatest[k] || r[1] > todayLatest[k].id) todayLatest[k] = { id: r[1], timestamp: r[0], submittedBy: r[2] };
    });
    // Aggregate stats per slot
    const slotStats = {};
    skuRows.forEach(r => {
      if ((r[12]||'ACTIVE') !== 'ACTIVE') return;
      if (r[4] !== todayStr) return;
      const k = (r[3]||'').trim() + '||' + ((r[5]||'AM')+'').trim().toUpperCase();
      if (!todayLatest[k] || todayLatest[k].id !== r[1]) return;
      const s = slotStats[k] = slotStats[k] || { available:0, oos:0, total:0 };
      s.total++;
      const st = (r[10]||'').trim();
      if (st === 'Available') s.available++;
      else if (st === 'OOS') s.oos++;
    });
    // Compute on-time + merge with latest
    Object.keys(todayLatest).forEach(k => {
      const o = todayLatest[k]; const slot = k.split('||')[1];
      const sub = new Date(o.timestamp);
      const phHour = (sub.getUTCHours() + 8) % 24;
      const subDatePH = new Date(sub.getTime() + 8*3600*1000).toISOString().slice(0,10);
      const dl = slot === 'AM' ? 10 : 15;
      o.onTime = (subDatePH < todayStr) || (subDatePH === todayStr && phHour < dl);
      Object.assign(o, slotStats[k] || { available:0, oos:0, total:0 });
    });

    // Per-store summary row for the grid
    const storeStats = authorizedStores.map(s => {
      const am = todayLatest[s.name + '||AM'];
      const pm = todayLatest[s.name + '||PM'];
      return {
        store: s.name, area: s.area,
        am: am ? { submitted:true, onTime:am.onTime, oos:am.oos, total:am.total, submittedBy:am.submittedBy, timestamp:am.timestamp } : { submitted:false },
        pm: pm ? { submitted:true, onTime:pm.onTime, oos:pm.oos, total:pm.total, submittedBy:pm.submittedBy, timestamp:pm.timestamp } : { submitted:false }
      };
    });

    // KPIs
    const totalStores = authorizedStores.length;
    const expectedSlots = totalStores * 2;
    const submittedSlots = Object.keys(todayLatest).length;
    const onTimeSlots = Object.values(todayLatest).filter(o => o.onTime).length;
    const lateSlots = submittedSlots - onTimeSlots;
    const totalOOS = Object.values(todayLatest).reduce((n,o) => n + (o.oos||0), 0);
    const totalAvailable = Object.values(todayLatest).reduce((n,o) => n + (o.available||0), 0);
    const complianceRate = expectedSlots ? Math.round((submittedSlots / expectedSlots) * 100) : 0;
    const onTimeRate = submittedSlots ? Math.round((onTimeSlots / submittedSlots) * 100) : 0;
    const passRate = (totalAvailable + totalOOS) ? Math.round((totalAvailable / (totalAvailable+totalOOS)) * 100) : 0;

    // Category breakdown (RICE/EGGS/POULTRY/MEAT/SUGAR)
    const groupOf = (c) => { const u=(c||'').toUpperCase(); return (u==='PORK'||u==='BEEF') ? 'MEAT' : u; };
    const CATS = ['RICE','EGGS','POULTRY','MEAT','SUGAR'];
    const categories = {}; CATS.forEach(c => categories[c] = { oos:0, available:0 });
    skuRows.forEach(r => {
      if ((r[12]||'ACTIVE') !== 'ACTIVE') return;
      if (r[4] !== todayStr) return;
      const k = (r[3]||'').trim() + '||' + ((r[5]||'AM')+'').trim().toUpperCase();
      if (!todayLatest[k] || todayLatest[k].id !== r[1]) return;
      const g = groupOf(r[6]);
      if (!categories[g]) return;
      const st = (r[10]||'').trim();
      if (st === 'OOS') categories[g].oos++;
      else if (st === 'Available') categories[g].available++;
    });

    // 14-day trend of OOS + submission count
    const trend = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      const ds = d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
      trend.push({ date: ds, oos: 0, submissions: 0 });
    }
    const trendIdx = {}; trend.forEach(t => trendIdx[t.date] = t);
    const latestPerKey = {};
    skuRows.forEach(r => {
      if ((r[12]||'ACTIVE') !== 'ACTIVE') return;
      const d = r[4];
      if (!trendIdx[d]) return;
      const k = d + '||' + (r[3]||'') + '||' + ((r[5]||'AM')+'').trim().toUpperCase();
      if (!latestPerKey[k] || r[1] > latestPerKey[k]) latestPerKey[k] = r[1];
    });
    const subPerDay = {};
    skuRows.forEach(r => {
      if ((r[12]||'ACTIVE') !== 'ACTIVE') return;
      const d = r[4];
      if (!trendIdx[d]) return;
      const k = d + '||' + (r[3]||'') + '||' + ((r[5]||'AM')+'').trim().toUpperCase();
      if (latestPerKey[k] !== r[1]) return;
      if ((r[10]||'').trim() === 'OOS') trendIdx[d].oos++;
      (subPerDay[d] = subPerDay[d] || new Set()).add(k);
    });
    trend.forEach(t => t.submissions = (subPerDay[t.date] || new Set()).size);

    res.json({ ok:true, date: todayStr,
      kpis: { totalStores, expectedSlots, submittedSlots, onTimeSlots, lateSlots, totalOOS, totalAvailable, complianceRate, onTimeRate, passRate },
      storeStats, categories, trend
    });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

function todayLocalPHstr(){
  const nowPH = new Date(Date.now() + 8*3600*1000);
  return nowPH.toISOString().slice(0,10);
}

app.get('/api/sku-history-detail', async (req, res) => {
  try {
    const storeMgr = (req.query.storeMgr || '').trim().toLowerCase();
    const from = (req.query.from || '').trim();
    const to = (req.query.to || '').trim();
    if (!storeMgr) return res.json({ ok:false, error:'storeMgr required' });
    const rows = await sheetsGet('SKUChecklistData!A2:M');
    const filtered = rows.filter(r =>
      skuRowRecStatus(r) === 'ACTIVE' &&
      (r[2] || '').trim().toLowerCase() === storeMgr &&
      (!from || (r[4] || '') >= from) &&
      (!to   || (r[4] || '') <= to)
    );
    // Pick latest ReportID per (date, slot)
    const bySlot = {};
    filtered.forEach(r => { const d = r[4]; const sl = skuRowSlot(r); if (!d) return; const k = d+'||'+sl; if (!bySlot[k] || r[1] > bySlot[k]) bySlot[k] = r[1]; });
    const entries = [];
    filtered.forEach(r => {
      const d = r[4]; const sl = skuRowSlot(r); const k = d+'||'+sl;
      if (bySlot[k] !== r[1]) return;
      entries.push({ date:d, slot:sl, timestamp:r[0], store:r[3], category:r[6], rank:parseInt(r[7])||0, sku:r[8], description:r[9], status:r[10], remarks:r[11] });
    });
    res.json({ ok:true, entries });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

// ---------- Stock Review (Area Manager validates each store/slot) ----------
const REVIEW_DEADLINE_HR = { AM: 11, PM: 16 }; // PH local

app.post('/api/review-submit', async (req, res) => {
  try {
    const { manager, store, date, slot, confirmedOOS } = req.body || {};
    if (!manager || !store || !date || !slot) return res.json({ ok:false, error:'Missing fields' });
    if (!['AM','PM'].includes(slot)) return res.json({ ok:false, error:'Invalid slot (AM or PM only)' });
    const existing = await sheetsGet('StockReviewData!A2:I');
    const already = existing.some(r =>
      (r[8] || 'ACTIVE') === 'ACTIVE' &&
      (r[2] || '').trim().toLowerCase() === manager.trim().toLowerCase() &&
      (r[3] || '').trim() === store &&
      r[4] === date &&
      (r[5] || '').trim().toUpperCase() === slot
    );
    if (already) return res.json({ ok:false, error: slot + ' review for ' + store + ' on ' + date + ' already recorded' });
    const comments = Array.isArray(confirmedOOS) && confirmedOOS.length
      ? 'Confirmed OOS (' + confirmedOOS.length + '): ' + confirmedOOS.join(', ')
      : 'No OOS to confirm';
    const ts = new Date().toISOString();
    const id = 'RV' + Date.now();
    const row = [[ts, id, manager, store, date, slot, 'Validated', comments, 'ACTIVE']];
    await sheetsAppend('StockReviewData!A1:I1', row);
    res.json({ ok:true, reviewId: id });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/review-pending', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    const date = (req.query.date || '').trim();
    if (!manager || !date) return res.json({ ok:false, error:'manager and date required' });

    // AM's assigned stores
    const stores = await sheetsGet('ListOfStores!A2:G');
    const myStores = stores
      .filter(r => (r[6] || '').trim().toLowerCase() === manager)
      .map(r => ({ name: (r[4]||'').trim(), area: r[2] || '' }))
      .filter(s => s.name);

    // Store Manager SKU Checklist for the date, grouped by (store, slot)
    const skuRows = await sheetsGet('SKUChecklistData!A2:M');
    const skuBySlot = {};
    skuRows.forEach(r => {
      if ((r[12] || 'ACTIVE') !== 'ACTIVE') return;
      if (r[4] !== date) return;
      const store = (r[3] || '').trim();
      const slot = ((r[5] || 'AM') + '').trim().toUpperCase();
      const k = store + '||' + slot;
      if (!skuBySlot[k] || r[1] > skuBySlot[k].id) skuBySlot[k] = { id: r[1], timestamp: r[0] };
    });
    const aggSKU = {};
    skuRows.forEach(r => {
      if ((r[12] || 'ACTIVE') !== 'ACTIVE') return;
      if (r[4] !== date) return;
      const store = (r[3] || '').trim();
      const slot = ((r[5] || 'AM') + '').trim().toUpperCase();
      const k = store + '||' + slot;
      if (!skuBySlot[k] || skuBySlot[k].id !== r[1]) return;
      const submittedBy = (r[2] || '').trim();
      aggSKU[k] = aggSKU[k] || { total:0, available:0, oos:0, timestamp:skuBySlot[k].timestamp, oosList:[], submittedBy };
      aggSKU[k].total++;
      const st = (r[10] || '').trim();
      if (st === 'Available') aggSKU[k].available++;
      else if (st === 'OOS') {
        aggSKU[k].oos++;
        aggSKU[k].oosList.push({ sku: r[8], description: r[9], category: r[6], rank: parseInt(r[7])||0, remarks: r[11] || '' });
      }
    });
    // Compute SKU on-time (SM deadlines 10 / 15)
    Object.keys(aggSKU).forEach(k => {
      const o = aggSKU[k];
      const sub = new Date(o.timestamp);
      const phHour = (sub.getUTCHours() + 8) % 24;
      const subDatePH = new Date(sub.getTime() + 8*3600*1000).toISOString().slice(0,10);
      const slotKey = k.split('||')[1];
      const dl = slotKey === 'AM' ? 10 : 15;
      o.onTime = (subDatePH < date) || (subDatePH === date && phHour < dl);
    });

    // AM's reviews for the date
    const reviewRows = await sheetsGet('StockReviewData!A2:I');
    const reviewByKey = {};
    reviewRows.forEach(r => {
      if ((r[8] || 'ACTIVE') !== 'ACTIVE') return;
      if ((r[2] || '').trim().toLowerCase() !== manager) return;
      if (r[4] !== date) return;
      const k = (r[3] || '').trim() + '||' + ((r[5] || '') + '').trim().toUpperCase();
      const o = { timestamp: r[0] };
      const sub = new Date(r[0]);
      const phHour = (sub.getUTCHours() + 8) % 24;
      const subDatePH = new Date(sub.getTime() + 8*3600*1000).toISOString().slice(0,10);
      const slotKey = k.split('||')[1];
      const dl = REVIEW_DEADLINE_HR[slotKey] || 11;
      o.onTime = (subDatePH < date) || (subDatePH === date && phHour < dl);
      reviewByKey[k] = o;
    });

    const items = [];
    myStores.forEach(s => {
      ['AM','PM'].forEach(slot => {
        const k = s.name + '||' + slot;
        const sku = aggSKU[k];
        const review = reviewByKey[k];
        items.push({
          store: s.name, area: s.area, slot,
          skuSubmitted: !!sku,
          skuAvailable: sku ? sku.available : 0,
          skuOOS:       sku ? sku.oos       : 0,
          skuTotal:     sku ? sku.total     : 0,
          skuOnTime:    sku ? sku.onTime    : null,
          skuTimestamp: sku ? sku.timestamp : null,
          skuSubmittedBy: sku ? sku.submittedBy : null,
          oosList:      sku ? sku.oosList   : [],
          reviewed: !!review,
          reviewTimestamp: review ? review.timestamp : null,
          reviewOnTime:    review ? review.onTime    : null
        });
      });
    });

    res.json({ ok:true, items });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/review-monitor', async (req, res) => {
  try {
    const date = (req.query.date || '').trim();
    const amRows = await sheetsGet('AreaManagers!A2:C');
    const ams = amRows.filter(r => (r[2] || '').trim().toLowerCase() === 'area manager').map(r => (r[0] || '').trim()).filter(Boolean);
    const stores = await sheetsGet('ListOfStores!A2:G');
    const amStores = {};
    stores.forEach(r => {
      const am = (r[6] || '').trim();
      const st = (r[4] || '').trim();
      if (!am || !st) return;
      amStores[am] = amStores[am] || [];
      amStores[am].push(st);
    });

    const reviewRows = await sheetsGet('StockReviewData!A2:I');
    const skuRows    = await sheetsGet('SKUChecklistData!A2:M');

    // Index SKU submissions for date: (store, slot) -> true
    const skuExists = {};
    skuRows.forEach(r => {
      if ((r[12] || 'ACTIVE') !== 'ACTIVE') return;
      if (date && r[4] !== date) return;
      const k = (r[3] || '').trim() + '||' + ((r[5] || 'AM') + '').trim().toUpperCase();
      skuExists[k] = true;
    });

    // Index reviews for date: (am, store, slot) -> { onTime }
    const reviewExists = {};
    reviewRows.forEach(r => {
      if ((r[8] || 'ACTIVE') !== 'ACTIVE') return;
      if (date && r[4] !== date) return;
      const slotKey = ((r[5] || '') + '').trim().toUpperCase();
      const k = (r[2] || '').trim() + '||' + (r[3] || '').trim() + '||' + slotKey;
      const sub = new Date(r[0]);
      const phHour = (sub.getUTCHours() + 8) % 24;
      const subDatePH = new Date(sub.getTime() + 8*3600*1000).toISOString().slice(0,10);
      const dl = REVIEW_DEADLINE_HR[slotKey] || 11;
      const onTime = (subDatePH < (r[4]||date)) || (subDatePH === (r[4]||date) && phHour < dl);
      reviewExists[k] = { onTime };
    });

    const amStats = ams.map(am => {
      const mstores = amStores[am] || [];
      let total = mstores.length * 2; // AM+PM per store
      let reviewed = 0, late = 0;
      const breakdown = [];
      mstores.forEach(st => ['AM','PM'].forEach(slot => {
        const rev = reviewExists[am + '||' + st + '||' + slot];
        const smSubmitted = skuExists[st + '||' + slot];
        if (rev) { reviewed++; if (!rev.onTime) late++; }
        breakdown.push({ store: st, slot, reviewed: !!rev, onTime: rev ? rev.onTime : null, smSubmitted: !!smSubmitted });
      }));
      return {
        manager: am,
        storesCount: mstores.length,
        slotsTotal: total,
        reviewed,
        pending: total - reviewed,
        late,
        rate: total ? Math.round((reviewed / total) * 100) : 0,
        breakdown
      };
    });

    const pendingAMs = amStats.filter(a => a.pending > 0);
    res.json({ ok:true, amStats, pendingAMs });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

app.get('/api/am-stores', async (req, res) => {
  try {
    const manager = (req.query.manager || '').trim().toLowerCase();
    if (!manager) return res.json({ ok:false, error:'manager required' });
    const rows = await sheetsGet('ListOfStores!A2:G');
    const mine = rows.filter(r => (r[6] || '').trim().toLowerCase() === manager);
    const stores = mine.map(r => r[4]).filter(Boolean);
    // Most common area for this AM
    const areaCounts = {};
    mine.forEach(r => { const a = (r[2]||'').trim(); if (a) areaCounts[a] = (areaCounts[a]||0)+1; });
    const primaryArea = Object.entries(areaCounts).sort((a,b) => b[1]-a[1])[0];
    // Most common region for this AM
    const regionCounts = {};
    mine.forEach(r => { const g = (r[1]||'').trim(); if (g) regionCounts[g] = (regionCounts[g]||0)+1; });
    const primaryRegion = Object.entries(regionCounts).sort((a,b) => b[1]-a[1])[0];
    res.json({ ok: true, stores, area: primaryArea ? primaryArea[0] : '', region: primaryRegion ? primaryRegion[0] : REGION_NAME });
  } catch (e) { res.status(500).json({ ok:false, error: e.message }); }
});

// ---------- PWA assets ----------
app.get('/Focus5_icon.png', (req, res) => {
  const p = path.join(__dirname, 'Focus5_icon.png');
  if (fs.existsSync(p)) res.sendFile(p);
  else res.status(404).send('icon missing');
});

app.get('/manifest.json', (req, res) => {
  res.json({
    name: 'Fresh Focus 5 Checklist',
    short_name: 'Focus 5',
    description: 'Fresh Focus 5 Checklist - Stock, SKU and Compliance monitoring',
    start_url: '/',
    scope: '/',
    display: 'standalone',
    orientation: 'any',
    background_color: '#0e3a1c',
    theme_color: '#1f7a3a',
    icons: [
      { src: '/Focus5_icon.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/Focus5_icon.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/Focus5_icon.png', sizes: 'any',    type: 'image/png', purpose: 'maskable' }
    ]
  });
});

app.get('/sw.js', (req, res) => {
  res.type('application/javascript').send(
    "const CACHE='ff5-v1';\n" +
    "self.addEventListener('install', e => { self.skipWaiting(); });\n" +
    "self.addEventListener('activate', e => { e.waitUntil(self.clients.claim()); });\n" +
    "self.addEventListener('fetch', e => {\n" +
    "  const u = e.request.url;\n" +
    "  if (/\\.(png|jpg|svg|ico)$/.test(u) || u.endsWith('/manifest.json')) {\n" +
    "    e.respondWith(caches.open(CACHE).then(c => c.match(e.request).then(r => r || fetch(e.request).then(resp => { c.put(e.request, resp.clone()); return resp; }))));\n" +
    "  }\n" +
    "});\n"
  );
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
<link rel="manifest" href="/manifest.json">
<link rel="icon" type="image/png" href="/Focus5_icon.png">
<link rel="apple-touch-icon" href="/Focus5_icon.png">
<meta name="apple-mobile-web-app-title" content="Focus 5">
<meta name="application-name" content="Focus 5">
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
<style>
*{box-sizing:border-box;-webkit-tap-highlight-color:rgba(0,0,0,0)}
html,body{overscroll-behavior-y:contain}
.noScroll::-webkit-scrollbar{display:none;width:0;height:0}
:root{
  --brand:#1f7a3a; --brand-dark:#155a2b; --brand-darker:#0e3a1c;
  --accent:#FFC107; --accent-dark:#D4A017; --accent-soft:#FFF4CC;
  --bg:#f3f6f3; --surface:#ffffff; --ink:#1a2621; --muted:#5e6b64;
  --border:#dbe3dd;
}
body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:var(--bg);color:var(--ink);padding-bottom:env(safe-area-inset-bottom)}
header{background:linear-gradient(135deg,var(--brand-darker) 0%,var(--brand) 60%,var(--brand-dark) 100%);color:#fff;padding:14px 24px;padding-top:calc(14px + env(safe-area-inset-top));display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;gap:12px;border-bottom:3px solid var(--accent);box-shadow:0 2px 8px rgba(0,0,0,.08)}
header h1{margin:0;font-size:18px;line-height:1.2;font-weight:700;letter-spacing:.3px;display:flex;align-items:center;gap:10px}
header h1::before{content:'';display:inline-block;width:28px;height:28px;background:url('/Focus5_icon.png') center/contain no-repeat;border-radius:6px;background-color:#fff}
header .who{font-size:13px;opacity:.95;text-align:right;display:flex;align-items:center;gap:8px;flex-shrink:0}
header .who button{background:var(--accent);color:var(--brand-darker);border:0;padding:6px 12px;border-radius:6px;font-weight:700;cursor:pointer;font-size:12px;transition:transform .1s}
header .who button:hover{transform:translateY(-1px)}
main{padding:16px 20px;max-width:1800px;margin:0 auto;width:100%}
@media (max-width:600px){main{padding:10px}}
.card{background:var(--surface);border-radius:12px;padding:16px 20px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 4px 16px rgba(10,40,20,.04);border:1px solid var(--border)}
@media (max-width:600px){.card{padding:12px 14px;border-radius:10px}}
label{display:block;font-size:12px;color:#555;margin-bottom:4px;margin-top:8px}
input,select,textarea,button{font:inherit}
/* font-size:16px prevents iOS Safari auto-zoom on focus */
input,select,textarea{width:100%;padding:12px;border:1px solid #ccd;border-radius:8px;background:#fff;font-size:16px;min-height:44px}
textarea{min-height:56px;resize:vertical;font-size:15px}
button{cursor:pointer;border:0;border-radius:8px;padding:12px 18px;background:var(--brand);color:#fff;font-weight:600;min-height:44px;touch-action:manipulation;user-select:none;-webkit-user-select:none;transition:transform .08s,box-shadow .15s;box-shadow:0 1px 2px rgba(0,0,0,.06)}
button:hover{box-shadow:0 2px 8px rgba(31,122,58,.25)}
button:active{transform:scale(.97)}
button.ghost{background:#eef2ee;color:#2b3b32;box-shadow:none}
button.accent{background:var(--accent);color:var(--brand-darker)}
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
.tabs{display:flex;gap:6px;margin-bottom:14px;padding:8px 0;z-index:2;flex-wrap:wrap}
.tabs button{flex:1 1 140px;background:#fff;color:var(--brand-dark);border:1px solid var(--border);box-shadow:0 1px 2px rgba(0,0,0,.03);font-weight:600;min-height:44px;transition:all .15s;padding:10px 14px}
.tabs button:hover{background:var(--accent-soft);border-color:var(--accent)}
.tabs button.active{background:var(--brand);color:#fff;border-color:var(--brand-dark);box-shadow:0 2px 8px rgba(31,122,58,.25);border-bottom:3px solid var(--accent)}
.score{font-size:28px;font-weight:700;color:#1f7a3a}
.hist{padding:12px;border:1px solid #dde;border-radius:8px;margin-bottom:8px;background:#fff;display:flex;justify-content:space-between;align-items:center;gap:8px}
.hist .meta{font-size:12px;color:#456;margin-top:2px}
.pill{display:inline-block;padding:3px 10px;border-radius:99px;background:#1f7a3a;color:#fff;font-size:12px;font-weight:700}
.err{color:#c33;margin-top:8px;font-size:13px}
.hidden{display:none !important}
/* ---------- Split-screen auth ---------- */
.auth-split{display:flex;min-height:100vh;background:#fff;align-items:stretch}
.auth-left{background:linear-gradient(135deg,#082415 0%,#0e3a1c 35%,#1f7a3a 100%);color:#fff;flex:1 1 50%;padding:48px 56px;display:flex;flex-direction:column;justify-content:space-between;gap:40px}
.auth-right{flex:1 1 50%;padding:48px;display:flex;align-items:center;justify-content:center;background:#fff}
.auth-brand{display:flex;align-items:center;gap:12px}
.auth-logo{width:44px;height:44px;background:url('/Focus5_icon.png') center/contain no-repeat;background-color:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.2)}
.auth-brand-name{font-weight:700;font-size:18px;letter-spacing:.3px;line-height:1.1}
.auth-brand-sub{font-size:11px;opacity:.9;color:#FFC107;letter-spacing:.5px;text-transform:uppercase;font-weight:700;margin-top:2px}
.auth-hero{font-size:36px;line-height:1.2;font-weight:700;max-width:460px;margin:0;letter-spacing:-.4px}
.auth-bullets{list-style:none;padding:0;margin:16px 0 0;display:flex;flex-direction:column;gap:14px;max-width:460px}
.auth-bullets li{display:flex;align-items:flex-start;gap:12px;font-size:14px;line-height:1.5;opacity:.95}
.auth-bullets li::before{content:'';display:inline-block;width:22px;height:22px;background:#FFC107;border-radius:50%;flex-shrink:0;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23082415' stroke-width='3.5' stroke-linecap='round' stroke-linejoin='round'><polyline points='20 6 9 17 4 12'/></svg>");background-size:14px;background-position:center;background-repeat:no-repeat}
.auth-foot{font-size:11px;opacity:.65;letter-spacing:.3px}
.auth-card{max-width:420px;width:100%}
.auth-title{font-size:28px;margin:0 0 4px;color:#0e3a1c;letter-spacing:-.3px;font-weight:700}
.auth-sub{font-size:14px;color:#5e6b64;margin:0 0 24px}
.auth-tabs{display:flex;margin-bottom:20px;border-bottom:1px solid #e3eae5}
.auth-tab{flex:1;background:transparent;color:#5e6b64;border:0;border-bottom:3px solid transparent;padding:12px;font-weight:600;cursor:pointer;border-radius:0;box-shadow:none;min-height:auto;font-size:14px}
.auth-tab:hover{color:#1f7a3a}
.auth-tab.active{color:#1f7a3a;border-bottom-color:#FFC107}
.auth-field{margin-top:14px}
.auth-field label{display:block;font-size:12px;color:#5e6b64;margin-bottom:6px;font-weight:500}
.auth-field label .req{color:#c33}
.pw-wrap{position:relative}
.pw-wrap input{padding-right:44px}
.pw-toggle{position:absolute;right:4px;top:50%;transform:translateY(-50%);background:transparent;border:0;padding:8px;cursor:pointer;color:#789;min-height:auto;box-shadow:none;font-size:18px;line-height:1}
.pw-toggle:hover{color:#1f7a3a}
.btn-primary{width:100%;background:#1f7a3a;color:#fff;padding:14px;border:0;border-radius:8px;font-weight:700;font-size:15px;cursor:pointer;margin-top:18px;box-shadow:0 2px 8px rgba(31,122,58,.2)}
.btn-primary:hover{background:#155a2b}
.btn-ghost{width:100%;background:transparent;color:#1f7a3a;border:1px solid #d3dcd5;padding:10px;border-radius:8px;margin-top:10px;font-weight:600;cursor:pointer;box-shadow:none}
.btn-ghost:hover{background:#f4faf6}
.auth-help{margin-top:20px;font-size:12px;color:#5e6b64;text-align:center;line-height:1.5}
.auth-help b{color:#0e3a1c}
@media (max-width:800px){
  .auth-split{flex-direction:column;min-height:auto}
  .auth-left{padding:28px 24px;gap:24px}
  .auth-right{padding:24px}
  .auth-hero{font-size:24px}
  .auth-bullets{font-size:13px}
}
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

<div id="loginScreen" class="auth-split">
  <aside class="auth-left">
    <div class="auth-brand">
      <div class="auth-logo"></div>
      <div>
        <div class="auth-brand-name">Focus 5</div>
        <div class="auth-brand-sub">Checklist &amp; Compliance</div>
      </div>
    </div>
    <div>
      <h1 class="auth-hero">Daily store checklists and stock status, in one place.</h1>
      <ul class="auth-bullets">
        <li>Store Managers submit SKU and stock-status checklists on time</li>
        <li>Area Managers review and validate each store's submission</li>
        <li>Regional Managers see real-time compliance and chronic issues</li>
      </ul>
    </div>
    <div class="auth-foot">Internal business system &middot; Authorized users only</div>
  </aside>
  <section class="auth-right">
    <div class="auth-card">
      <h2 class="auth-title" id="authTitle">Sign in</h2>
      <p class="auth-sub" id="authSubtitle">Use the email and password you registered with.</p>
      <div class="auth-tabs">
        <button id="tabLoginBtn" class="auth-tab active" type="button">Sign in</button>
        <button id="tabSignupBtn" class="auth-tab" type="button">Create account</button>
      </div>
      <div id="authLogin">
        <div class="auth-field"><label>Email <span class="req">*</span></label><input id="lu" type="email" autocomplete="username"/></div>
        <div class="auth-field"><label>Password <span class="req">*</span></label><div class="pw-wrap"><input id="lp" type="password" autocomplete="current-password"/><button type="button" class="pw-toggle" data-pw-target="lp">&#128065;</button></div></div>
        <button id="loginBtn" class="btn-primary" type="button">Sign in</button>
        <div id="loginErr" class="err" style="margin-top:10px"></div>
      </div>
      <div id="authSignup" style="display:none">
        <div class="auth-field"><label>Full name <span class="req">*</span></label><input id="suName" autocomplete="name"/></div>
        <div class="auth-field"><label>Email <span class="req">*</span></label><input id="suEmail" type="email" autocomplete="email"/></div>
        <div class="auth-field"><label>Position <span class="req">*</span></label><select id="suLevel"><option value="">-- select your position --</option><option value="Regional Manager" id="suLevelRM" style="display:none">Regional Manager (bootstrap only)</option><option value="Area Manager">Area Manager</option><option value="Store Manager">Store Manager</option></select></div>
        <div id="suStoreSingle" class="auth-field" style="display:none"><label>Your Store <span class="req">*</span></label><select id="suStoreOne"><option value="">-- select your store --</option></select></div>
        <div id="suStoreMulti" class="auth-field" style="display:none"><label>Your Stores <span class="req">*</span> <span style="color:#789;font-weight:400;font-size:11px">(tick all stores you manage)</span></label><div id="suStoresBox" style="max-height:200px;overflow-y:auto;border:1px solid #d3dcd5;border-radius:8px;padding:8px 10px;background:#fafbfa"></div></div>
        <div class="auth-field"><label>Password <span class="req">*</span> <span style="color:#789;font-weight:400">(6+ characters)</span></label><div class="pw-wrap"><input id="suPass" type="password" autocomplete="new-password"/><button type="button" class="pw-toggle" data-pw-target="suPass">&#128065;</button></div></div>
        <div class="auth-field"><label>Confirm password <span class="req">*</span></label><div class="pw-wrap"><input id="suPass2" type="password" autocomplete="new-password"/><button type="button" class="pw-toggle" data-pw-target="suPass2">&#128065;</button></div></div>
        <button id="signupBtn" class="btn-primary" type="button">Create account</button>
        <div id="signupMsg" style="margin-top:10px;font-size:13px"></div>
      </div>
      <div class="auth-help">Need access? Choose <b>Create account</b> and the Regional Manager will approve it.</div>
    </div>
  </section>
</div>

<div id="appScreen" class="hidden">
  <div class="tabs">
    <button data-tab="new" class="active">New Audit</button>
    <button data-tab="hist">AM Check History</button>
    <button data-tab="sum">AM Check Summary</button>
    <button data-tab="mon">Store Checks</button>
    <button data-tab="stock">Focus 5 Stock Status</button>
    <button data-tab="scheck">Store Check</button>
    <button data-tab="skuchk">Focus 5 SKU Checklist</button>
    <button data-tab="users">User Approvals</button>
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

  <div id="tabSkuChk" class="hidden">
    <div id="skuChkOut"><div class="card muted">Loading...</div></div>
  </div>

  <div id="tabUsers" class="hidden">
    <div id="usersOut"><div class="card muted">Loading...</div></div>
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
// Register service worker for PWA installability
if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js').catch(() => {}); }

const S = { manager:null, level:null, storeId:null, storeName:null, particulars:[], ratings:{}, remarks:{}, editingId:null,
            scResults:{}, scRemarks:{}, scSlot:null, scEditingId:null, userDir:{} };
// Resolve an email/username identifier to the user's full display name
function nameOf(identifier){
  if (!identifier) return '';
  const key = String(identifier).trim().toLowerCase();
  const u = S.userDir && S.userDir[key];
  return (u && u.fullName) ? u.fullName : identifier;
}
async function loadUserDirectory(){
  const r = await api('/api/user-directory');
  if (r && r.ok) S.userDir = r.directory || {};
}

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

// ---- Login (email first, legacy fallback) ----
function showAuthTab(which){
  const isLogin = which === 'login';
  const li = document.getElementById('authLogin');
  const su = document.getElementById('authSignup');
  if (li) li.style.display = isLogin ? 'block' : 'none';
  if (su) su.style.display = isLogin ? 'none' : 'block';
  const lb = document.getElementById('tabLoginBtn');
  const sb = document.getElementById('tabSignupBtn');
  if (lb) lb.classList.toggle('active', isLogin);
  if (sb) sb.classList.toggle('active', !isLogin);
  const title = document.getElementById('authTitle');
  const subt  = document.getElementById('authSubtitle');
  if (title) title.textContent = isLogin ? 'Sign in' : 'Create account';
  if (subt)  subt.textContent  = isLogin ? 'Use the email and password you registered with.' : 'Fill in your details. An administrator will approve your account.';
}
window.showAuthTab = showAuthTab;
$('#tabLoginBtn').onclick = () => showAuthTab('login');
$('#tabSignupBtn').onclick = () => showAuthTab('signup');
// Password visibility toggles
document.querySelectorAll('.pw-toggle').forEach(b => b.onclick = () => {
  const id = b.getAttribute('data-pw-target');
  const el = document.getElementById(id);
  if (!el) return;
  el.type = el.type === 'password' ? 'text' : 'password';
});

async function doLogin(useLegacy){
  const u = $('#lu').value.trim(), p = $('#lp').value;
  $('#loginErr').textContent = '';
  if (!u || !p) { $('#loginErr').textContent = 'Enter email and password'; return; }
  const endpoint = useLegacy ? '/api/login' : '/api/login-email';
  const body = useLegacy ? {username:u, password:p} : {email:u, password:p};
  const r = await api(endpoint, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  if (!r.ok) { $('#loginErr').textContent = r.error || 'Login failed'; return; }
  S.manager = r.manager; S.level = r.level || 'Area Manager';
  S.storeId = r.storeId || null; S.storeName = r.storeName || null;
  S.email = r.email || null; S.fullName = r.fullName || null;
  localStorage.setItem('ff5_mgr', r.manager);
  localStorage.setItem('ff5_lvl', S.level);
  if (S.storeId) localStorage.setItem('ff5_sid', S.storeId); else localStorage.removeItem('ff5_sid');
  if (S.storeName) localStorage.setItem('ff5_sname', S.storeName); else localStorage.removeItem('ff5_sname');
  if (S.email) localStorage.setItem('ff5_email', S.email); else localStorage.removeItem('ff5_email');
  await enterApp();
}
$('#loginBtn').onclick = () => doLogin(false);
const legBtn = $('#loginLegacyBtn'); if (legBtn) legBtn.onclick = () => doLogin(true);

// Load store list for signup form + check if first-ever signup (reveals RM option)
let SIGNUP_STORES = [];
(async () => {
  const rmCheck = await api('/api/has-rm');
  if (rmCheck && rmCheck.ok && !rmCheck.hasRM) {
    const rm = $('#suLevelRM'); if (rm) rm.style.display = '';
  }
  const r = await api('/api/all-stores');
  if (!r.ok) return;
  SIGNUP_STORES = r.stores || [];
  const sel = $('#suStoreOne');
  if (sel) sel.innerHTML = '<option value="">-- select your store --</option>' + SIGNUP_STORES.map(s => '<option value="'+escapeHtml(s.name)+'">'+escapeHtml(s.name)+' ('+escapeHtml(s.area||'')+')</option>').join('');
  const box = $('#suStoresBox');
  if (box) box.innerHTML = SIGNUP_STORES.map(s => '<label style="display:block;padding:4px 2px;font-size:13px;cursor:pointer"><input type="checkbox" class="sm-store-chk" value="'+escapeHtml(s.name)+'" style="margin-right:6px"/>'+escapeHtml(s.name)+' <span style="color:#789;font-size:11px">('+escapeHtml(s.area||'')+')</span></label>').join('');
})();

// Toggle store section visibility by Position
const suLvl = $('#suLevel');
if (suLvl) suLvl.onchange = () => {
  const v = suLvl.value;
  $('#suStoreSingle').style.display = (v === 'Store Manager') ? 'block' : 'none';
  $('#suStoreMulti').style.display  = (v === 'Area Manager')  ? 'block' : 'none';
};
$('#signupBtn').onclick = async () => {
  const name = $('#suName').value.trim(), email = $('#suEmail').value.trim(), level = $('#suLevel').value, p1 = $('#suPass').value, p2 = $('#suPass2').value;
  const msg = $('#signupMsg');
  msg.textContent = ''; msg.style.color = '#c33';
  if (!name || !email || !level || !p1) { msg.textContent = 'All fields required (including Position)'; return; }
  if (p1 !== p2) { msg.textContent = 'Passwords do not match'; return; }
  if (p1.length < 6) { msg.textContent = 'Password must be at least 6 characters'; return; }
  let assignedStores = [];
  if (level === 'Store Manager') {
    const v = ($('#suStoreOne') && $('#suStoreOne').value) || '';
    if (!v) { msg.textContent = 'Store Managers must select their store'; return; }
    assignedStores = [v];
  } else if (level === 'Area Manager') {
    assignedStores = [...document.querySelectorAll('.sm-store-chk:checked')].map(c => c.value);
    if (!assignedStores.length) { msg.textContent = 'Area Managers must select at least one store'; return; }
  }
  const r = await api('/api/signup', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ email, password:p1, fullName:name, level, assignedStores })});
  if (!r.ok) { msg.textContent = r.error || 'Signup failed'; return; }
  msg.style.color = '#1f7a3a';
  msg.textContent = r.autoApproved
    ? 'Account created AND auto-approved as the first Regional Manager. You can log in now.'
    : 'Account created. Waiting for Regional Manager approval. You will be able to log in once approved.';
  $('#suName').value = ''; $('#suEmail').value = ''; $('#suLevel').value = ''; $('#suPass').value = ''; $('#suPass2').value = '';
  if ($('#suStoreOne')) $('#suStoreOne').value = '';
  document.querySelectorAll('.sm-store-chk').forEach(c => c.checked = false);
  $('#suStoreSingle').style.display = 'none'; $('#suStoreMulti').style.display = 'none';
};

$('#logoutBtn').onclick = () => { ['ff5_mgr','ff5_lvl','ff5_sid','ff5_sname','ff5_email'].forEach(k=>localStorage.removeItem(k)); location.reload(); };

async function enterApp(){
  $('#loginScreen').classList.add('hidden');
  $('#appScreen').classList.remove('hidden');
  $('#logoutBtn').classList.remove('hidden');
  await loadUserDirectory();
  const myName = (S.fullName && S.fullName.trim()) || nameOf(S.manager) || S.manager;
  $('#whoName').textContent = myName + ' (' + S.level + ')';
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
  show('.tabs button[data-tab="skuchk"]', isStoreMgr);
  const isRegional = (S.level||'').toLowerCase() === 'regional manager';
  show('.tabs button[data-tab="users"]', isRegional);
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
  $('#tabSkuChk').classList.toggle('hidden', t!=='skuchk');
  $('#tabUsers').classList.toggle('hidden', t!=='users');
  if (t==='stock') { const lvl=(S.level||'').toLowerCase(); if (lvl==='area manager') loadReviewTab(); else if (lvl==='regional manager') loadStockTabRM(); else loadStockTab(); }
  if (t==='skuchk') loadSKUChecklist();
  if (t==='users') loadUserApprovalsTab();
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
             '&area=' + encodeURIComponent($('#monArea').value||'') + '&store=' + encodeURIComponent($('#monStore').value||'') +
             '&assigned=' + encodeURIComponent(JSON.stringify(S.assignedStores||[]));
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
  const weeklyRankCard = (weeksR.length && rankData.length) ? \`<div class="card" id="weeklyRankCard">
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px">
      <h3 style="margin:0;color:#1f7a3a">Weekly Ranking - Per Store</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">Lowest &rarr; Highest by Avg</span>
      <button id="wkRankPngBtn" data-no-png style="margin-left:auto;background:#345;color:#fff;border:0;border-radius:6px;padding:8px 14px;font-weight:600;font-size:13px;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.1)">&#128247; Export PNG</button>
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
  const wkBtn = document.getElementById('wkRankPngBtn'); if (wkBtn) wkBtn.onclick = exportWeeklyRankPNG;
}

async function exportWeeklyRankPNG(){
  const el = document.getElementById('weeklyRankCard');
  if (!el) { alert('Nothing to export'); return; }
  if (typeof html2canvas === 'undefined') { alert('PNG library still loading. Try again in a moment.'); return; }
  const btn = document.getElementById('wkRankPngBtn'); const orig = btn ? btn.textContent : ''; if (btn) { btn.disabled = true; btn.textContent = 'Rendering...'; }
  try {
    const canvas = await html2canvas(el, { scale: 3, backgroundColor: '#ffffff', useCORS: true, logging: false,
      ignoreElements: (n) => n && n.hasAttribute && n.hasAttribute('data-no-png') });
    await new Promise((resolve) => canvas.toBlob((blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'Weekly_Ranking_' + todayStr() + '.png';
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
      resolve();
    }, 'image/png'));
  } catch (e) {
    alert('PNG export failed: ' + (e && e.message || e));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
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
  STOCK_STATE.amArea   = storesRes.area || S.area || '';
  STOCK_STATE.amRegion = storesRes.region || 'CAMANAVA';
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
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <button id="watchExportBtn" style="background:#c33">&#128228; Export to Excel (HQ)</button>
        <button id="watchExportPngBtn" style="background:#345">&#128247; Export Overview PNG</button>
      </div>
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

  const weeklyProgressInAppHTML = buildWeeklyProgressHTML(wReports, flaggedStores);
  const weeklyProgressCard = weeklyProgressInAppHTML ? \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0;color:#1f7a3a">Weekly Progress Report</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${wFrom} to \${wTo}</span>
    </div>
    \${weeklyProgressInAppHTML}
  </div>\` : '';
  // RM-only: full AM Review Dashboard replaces the simple alert
  let amReviewCard = '';
  if ((S.level||'').toLowerCase() === 'regional manager') {
    const rv = await api('/api/review-monitor?date=' + todayStr());
    if (rv.ok) {
      const amStats = rv.amStats || [];
      const totalExpected = amStats.reduce((n,a) => n + a.slotsTotal, 0);
      const totalDone     = amStats.reduce((n,a) => n + a.reviewed, 0);
      const totalLate     = amStats.reduce((n,a) => n + a.late, 0);
      const complianceRate = totalExpected ? Math.round((totalDone / totalExpected) * 100) : 0;
      const nowHr = new Date().getHours();

      const summaryBar = \`<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px">
        <div style="font-size:28px">\${complianceRate===100 ? '&#9989;' : '&#128680;'}</div>
        <div style="flex:1">
          <div style="color:\${complianceRate===100?'#1f7a3a':'#c33'};font-weight:800;font-size:16px">AM REVIEW DASHBOARD - TODAY</div>
          <div style="font-size:13px;color:#345;margin-top:3px">\${totalDone} of \${totalExpected} store/slot reviews done \${totalLate?' - <b style="color:#c33">'+totalLate+' were late</b>':''}</div>
        </div>
        <div style="text-align:center;padding:10px 18px;background:\${complianceRate===100?'#1f7a3a':'#c33'};color:#fff;border-radius:8px;font-weight:800;font-size:22px;min-width:90px">\${complianceRate}%</div>
      </div>\`;

      const amRows = amStats.map(a => {
        const displayName = nameOf(a.manager);
        const amBreakdown = a.breakdown.filter(b => b.slot === 'AM');
        const pmBreakdown = a.breakdown.filter(b => b.slot === 'PM');
        const slotCellsForSlot = (brk, deadlineHr) => {
          const pastDeadline = nowHr >= deadlineHr;
          return brk.map(b => {
            if (b.reviewed) {
              const bg = b.onTime ? '#1f7a3a' : '#c33';
              return '<span style="display:inline-block;background:'+bg+';color:#fff;padding:3px 8px;border-radius:10px;font-size:11px;font-weight:700;margin:1px" title="'+escapeHtml(b.store)+' ('+b.slot+') - '+(b.onTime?'on time':'LATE')+'">'+escapeHtml(b.store)+'</span>';
            }
            if (!b.smSubmitted) {
              return '<span style="display:inline-block;background:#eef;color:#789;padding:3px 8px;border-radius:10px;font-size:11px;font-weight:700;margin:1px" title="'+escapeHtml(b.store)+' - SM has not submitted">'+escapeHtml(b.store)+' (SM&#9888;)</span>';
            }
            const bg = pastDeadline ? '#c33' : '#e0a020';
            const lbl = pastDeadline ? ' LATE' : ' pending';
            return '<span style="display:inline-block;background:'+bg+';color:#fff;padding:3px 8px;border-radius:10px;font-size:11px;font-weight:700;margin:1px" title="'+escapeHtml(b.store)+' - '+(pastDeadline?'past deadline, not reviewed':'awaiting review')+'">'+escapeHtml(b.store)+lbl+'</span>';
          }).join('');
        };
        const rowBg = a.pending > 0 ? '#fff5f5' : '#f0faf3';
        const borderCol = a.late > 0 ? '#c33' : (a.pending > 0 ? '#e0a020' : '#1f7a3a');
        return \`<div style="border-left:4px solid \${borderCol};background:\${rowBg};padding:10px 12px;border-radius:6px;margin-bottom:8px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
            <b style="font-size:14px;color:#223;flex:1">\${escapeHtml(displayName)}\${displayName !== a.manager ? ' <span style="color:#789;font-weight:400;font-size:11px">('+escapeHtml(a.manager)+')</span>' : ''}</b>
            <span style="background:#fff;color:#1f7a3a;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px;border:1px solid #cfd8d3">\${a.reviewed}/\${a.slotsTotal} done</span>
            \${a.late ? '<span style="background:#c33;color:#fff;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px">'+a.late+' LATE</span>' : ''}
            \${a.pending ? '<span style="background:#e0a020;color:#fff;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px">'+a.pending+' pending</span>' : '<span style="background:#1f7a3a;color:#fff;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px">ALL DONE</span>'}
          </div>
          <div style="font-size:11px;color:#789;margin-bottom:2px"><b>AM slot</b> (deadline 11:00):</div>
          <div style="margin-bottom:4px">\${slotCellsForSlot(amBreakdown, 11) || '<span class="muted">no stores</span>'}</div>
          <div style="font-size:11px;color:#789;margin-bottom:2px"><b>PM slot</b> (deadline 16:00):</div>
          <div>\${slotCellsForSlot(pmBreakdown, 16) || '<span class="muted">no stores</span>'}</div>
        </div>\`;
      }).join('');

      amReviewCard = \`<div class="card">
        <h3 style="margin:0 0 6px;color:#1f7a3a">AM Review Dashboard</h3>
        <div class="muted" style="font-size:12px;margin-bottom:10px">Each Area Manager's progress today. Green chip = reviewed on time, red = late or missed, grey = Store Manager has not submitted yet. Click a chip to see details.</div>
        \${summaryBar}
        \${amRows || '<div class="muted">No Area Managers assigned yet.</div>'}
      </div>\`;
    }
  }
  $('#stockOut').innerHTML = kpiRow2 + filterCard + missingHtml + amReviewCard + chartCard + formCard + tableCard + urgentCard + watchCard + weeklyProgressCard + historyCard;

  $('#stockApplyBtn').onclick = () => { STOCK_STATE.from = $('#stockFrom').value; STOCK_STATE.to = $('#stockTo').value; STOCK_STATE.singleDate = null; loadStockTab(); };
  $('#stockExportBtn').onclick = exportStockExcel;
  const sdSel = $('#stockSingleDate'); if (sdSel) sdSel.onchange = () => { STOCK_STATE.singleDate = sdSel.value; loadStockTab(); };
  const wexp = $('#watchExportBtn'); if (wexp) wexp.onclick = exportWatchlistHQ;
  const wexpPng = $('#watchExportPngBtn'); if (wexpPng) wexpPng.onclick = exportWatchlistPNG;
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

async function exportWatchlistPNG(){
  const data = STOCK_STATE.lastData;
  const flagged = STOCK_STATE.flaggedStores || [];
  const wReports = STOCK_STATE.wReports || (data && data.reports) || [];
  if (!data) { alert('Load first'); return; }
  if (!flagged.length) { alert('No stores flagged for HQ escalation.'); return; }
  if (typeof html2canvas === 'undefined') { alert('PNG library still loading. Please try again in a moment.'); return; }
  const btn = $('#watchExportPngBtn'); const orig = btn ? btn.textContent : ''; if (btn){ btn.disabled = true; btn.textContent = 'Rendering...'; }
  try {
    // Build the same overview HTML the Excel export uses, but skipping the detail blocks.
    const html = buildFlaggedOverviewHTML(data, flagged, wReports, { omitStoreProgress: true });
    const container = document.createElement('div');
    // display:inline-block + width:max-content so the box shrinks to fit the widest table (no trailing white space)
    container.style.cssText = 'position:absolute;left:-99999px;top:0;background:#fff;padding:20px;display:inline-block;width:max-content;font-family:Calibri,Arial,sans-serif';
    container.innerHTML = html;
    document.body.appendChild(container);
    await new Promise(r => setTimeout(r, 60));
    // Explicit width/height so html2canvas doesn't grab the whole viewport width
    const rect = container.getBoundingClientRect();
    const canvas = await html2canvas(container, { scale: 3, backgroundColor: '#ffffff', useCORS: true, logging: false, width: Math.ceil(rect.width), height: Math.ceil(rect.height), windowWidth: Math.ceil(rect.width) + 40 });
    document.body.removeChild(container);
    await new Promise((resolve) => canvas.toBlob((blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'HQ_Escalation_Overview_' + todayStr() + '.png';
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
      resolve();
    }, 'image/png'));
  } catch (e) {
    alert('PNG export failed: ' + (e && e.message || e));
  } finally {
    if (btn){ btn.disabled = false; btn.textContent = orig; }
  }
}

// Shared: build a Weekly Progress HTML block used by both the export and the in-app watchlist card
function buildWeeklyProgressHTML(wReports, flagged, opts){
  opts = opts || {};
  const includeStore = opts.omitStoreProgress ? false : true;
  const DARK = '#1f7a3a', DARKER = '#155a2b', LIGHTER = '#f4faf6', OOS_C = '#c33', CRIT_C = '#e0a020';
  const weekOf = (dateStr) => {
    const dt = new Date(dateStr + 'T00:00:00');
    dt.setDate(dt.getDate() - ((dt.getDay() + 6) % 7));
    return dt.getFullYear()+'-'+String(dt.getMonth()+1).padStart(2,'0')+'-'+String(dt.getDate()).padStart(2,'0');
  };
  const MO = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const fmtWeek = (mondayStr) => {
    const mon = new Date(mondayStr + 'T00:00:00');
    const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
    return mon.getMonth() === sun.getMonth() ? MO[mon.getMonth()]+' '+mon.getDate()+'-'+sun.getDate() : MO[mon.getMonth()]+' '+mon.getDate()+' - '+MO[sun.getMonth()]+' '+sun.getDate();
  };
  const weeklyData = {};
  wReports.forEach(r => {
    const wk = weekOf(r.date);
    weeklyData[wk] = weeklyData[wk] || { catCounts: {}, storeCounts: {} };
    STOCK_CATS.forEach(c => {
      (r.categories[c.name] || []).forEach(e => {
        if (e.status !== 'OOS' && e.status !== 'Critical') return;
        const cat = weeklyData[wk].catCounts[c.name] = weeklyData[wk].catCounts[c.name] || { oos:0, crit:0, stores: new Set() };
        if (e.status === 'OOS') cat.oos++; else cat.crit++;
        cat.stores.add(e.store);
        const st = weeklyData[wk].storeCounts[e.store] = weeklyData[wk].storeCounts[e.store] || { oos:0, crit:0 };
        if (e.status === 'OOS') st.oos++; else st.crit++;
      });
    });
  });
  const weeks = Object.keys(weeklyData).sort();
  if (!weeks.length) return '';
  // Detect partial weeks: Sunday hasn't ended yet
  const todayDate = new Date(); todayDate.setHours(23,59,59,999);
  const isPartialWeek = (mondayStr) => {
    const mon = new Date(mondayStr + 'T00:00:00');
    const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
    sun.setHours(23,59,59,999);
    return sun >= todayDate; // Sunday is today or in the future
  };
  const completedWeekIdx = weeks.map((w,i) => ({w, i})).filter(x => !isPartialWeek(x.w)).map(x => x.i);
  // Improving = fewer total issues than previous COMPLETED week. Otherwise (more or equal) = not improving.
  const trendArrow = (totals) => {
    if (completedWeekIdx.length < 2) return { arrow: 'n/a', color: '#888' };
    const lastIdx = completedWeekIdx[completedWeekIdx.length - 1];
    const prevIdx = completedWeekIdx[completedWeekIdx.length - 2];
    const last = totals[lastIdx];
    const prev = totals[prevIdx];
    if (last < prev) return { arrow: '&uarr; Improving', color: DARK };
    return { arrow: '&darr; Not Improving', color: OOS_C };
  };
  const scaleColor = (val, min, max) => {
    if (max === min || val === 0) return val === 0 ? '#e8f5ec' : LIGHTER;
    const norm = (val - min) / (max - min);
    if (norm < 0.34) return '#e8f5ec';
    if (norm < 0.67) return '#fff5e0';
    return '#fee';
  };
  const weekHeaders = weeks.map(w => \`<th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center;font-size:12px">\${fmtWeek(w)}\${isPartialWeek(w) ? '<div style="font-size:10px;font-weight:normal;opacity:.85">(partial)</div>' : ''}</th>\`).join('');
  const catCellHTML = (v, bg) => {
    if (v.oos === 0 && v.crit === 0) return \`<td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${bg};font-size:12px;color:#888">0</td>\`;
    return \`<td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${bg};font-size:12px;line-height:1.35">
      <div><span style="color:\${OOS_C};font-weight:bold">\${v.oos} OOS</span> &nbsp; <span style="color:\${CRIT_C};font-weight:bold">\${v.crit} Crit</span></div>
      <div style="color:#556;font-size:11px">\${v.stores.size} store\${v.stores.size===1?'':'s'}</div>
    </td>\`;
  };
  const storeCellHTML = (v, bg) => {
    if (!v || (v.oos === 0 && v.crit === 0)) return \`<td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${bg};font-size:12px;color:#888">0</td>\`;
    return \`<td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${bg};font-size:12px;line-height:1.35">
      <span style="color:\${OOS_C};font-weight:bold">\${v.oos} OOS</span> &nbsp; <span style="color:\${CRIT_C};font-weight:bold">\${v.crit} Crit</span>
    </td>\`;
  };
  const catWeekRows = STOCK_CATS.map(c => {
    const values = weeks.map(w => weeklyData[w].catCounts[c.name] || { oos:0, crit:0, stores: new Set() });
    const totals = values.map(v => v.oos + v.crit);
    const mn = Math.min.apply(null, totals);
    const mx = Math.max.apply(null, totals);
    const cells = values.map(v => catCellHTML(v, scaleColor(v.oos + v.crit, mn, mx))).join('');
    const trend = trendArrow(totals);
    return \`<tr>
      <td style="border:1px solid #cfd8d3;padding:5px 10px;font-weight:bold;font-size:13px;color:\${DARKER}">\${c.icon} \${c.name}</td>
      \${cells}
      <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;color:\${trend.color};font-weight:bold;font-size:12px">\${trend.arrow}</td>
    </tr>\`;
  }).join('');
  const storeWeekRows = flagged.map(s => {
    const values = weeks.map(w => weeklyData[w].storeCounts[s.store] || { oos:0, crit:0 });
    const totals = values.map(v => v.oos + v.crit);
    const mn = Math.min.apply(null, totals);
    const mx = Math.max.apply(null, totals);
    const cells = values.map(v => storeCellHTML(v, scaleColor(v.oos + v.crit, mn, mx))).join('');
    const trend = trendArrow(totals);
    return \`<tr>
      <td style="border:1px solid #cfd8d3;padding:5px 10px;font-weight:bold;font-size:12px">\${escapeHtml(s.store)}</td>
      \${cells}
      <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;color:\${trend.color};font-weight:bold;font-size:12px">\${trend.arrow}</td>
    </tr>\`;
  }).join('');
  const storeSection = includeStore ? \`
    <div style="background:\${DARKER};color:#fff;padding:6px 12px;font-weight:bold;font-size:12px;letter-spacing:.3px">BY STORE (all flagged)</div>
    <div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:12px;margin-bottom:18px;width:100%">
      <thead><tr>
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:left;min-width:160px">Store</th>
        \${weekHeaders}
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center;min-width:130px">Trend</th>
      </tr></thead>
      <tbody>\${storeWeekRows}</tbody>
    </table></div>\` : '';
  return \`
    <div style="background:\${DARK};color:#fff;padding:8px 12px;margin-top:12px;font-weight:bold;font-size:14px;letter-spacing:.3px">WEEKLY PROGRESS REPORT</div>
    <div style="color:#556;font-size:11px;margin:4px 0 6px">OOS and Critical counts per Mon-Sun week (with distinct stores affected for categories). Row colour scale: green = best week, red = worst week. Trend compares the latest 2 <b>completed</b> weeks only (in-progress weeks marked "partial" are excluded).</div>
    <div style="background:\${DARKER};color:#fff;padding:6px 12px;font-weight:bold;font-size:12px;letter-spacing:.3px">BY CATEGORY</div>
    <div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:12px;margin-bottom:12px;width:100%">
      <thead><tr>
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:left;min-width:140px">Category</th>
        \${weekHeaders}
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center;min-width:130px">Trend</th>
      </tr></thead>
      <tbody>\${catWeekRows}</tbody>
    </table></div>
    \${storeSection}\`;
}

// Shared overview HTML builder — used by both the Excel export (as embedded block) and PNG export
function buildFlaggedOverviewHTML(data, flagged, wReports, opts){
  opts = opts || {};
  const DARK = '#1f7a3a', DARKER = '#155a2b', LIGHT_BG = '#e8f5ec', LIGHTER = '#f4faf6';
  const OOS_C = '#c33', CRIT_C = '#e0a020';
  const isAMRole = (S.level||'').toLowerCase() === 'area manager';
  const areaLabel = STOCK_STATE.amArea || '';
  const regionLabel = STOCK_STATE.amRegion || 'CAMANAVA';
  const titleText = isAMRole
    ? (areaLabel ? areaLabel + ' Area' : regionLabel) + ' Fresh Focus 5 Categories Stock Status Report'
    : regionLabel + ' Fresh Focus 5 Categories Stock Status Report';
  const regionRow = isAMRole ? \`<tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Region</td><td style="padding:6px 12px">\${escapeHtml(regionLabel)}</td></tr>\` : '';
  const totOOS  = flagged.reduce((n,s) => n+s.oosCount, 0);
  const totCrit = flagged.reduce((n,s) => n+s.critCount, 0);
  const reportingDays = new Set(wReports.map(r => r.date)).size;
  const rangeDatesSorted = [...new Set(wReports.map(r => r.date))].sort();
  const colorForStatus = (st) => st === 'OOS' ? OOS_C : st === 'Critical' ? CRIT_C : st === 'Healthy' ? DARK : '#dcdcdc';
  const sparkline = (byDate) => {
    if (!rangeDatesSorted.length) return '';
    return \`<div style="margin-top:4px;line-height:0;white-space:nowrap">\${rangeDatesSorted.map(d => '<span style="display:inline-block;width:7px;height:8px;background:'+colorForStatus(byDate?byDate[d]:null)+';margin-right:1px"></span>').join('')}</div>\`;
  };
  const catCell = (cs) => {
    if (!cs || cs.total === 0) return \`<td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:#f0f0f0;color:#888;font-style:italic;font-size:11px">No data\${sparkline(null)}</td>\`;
    let label, bg;
    if (cs.oos > 0)        { label = 'With OOS (' + cs.oos + ' Day' + (cs.oos===1?'':'s') + ')'; bg = OOS_C; }
    else if (cs.crit > 0)  { label = 'With Critical (' + cs.crit + ' Day' + (cs.crit===1?'':'s') + ')'; bg = CRIT_C; }
    else                   { label = 'Healthy (' + cs.healthy + ' Day' + (cs.healthy===1?'':'s') + ')'; bg = DARK; }
    return \`<td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${bg};color:#fff;font-weight:bold;font-size:11px">\${label}\${sparkline(cs.byDate)}</td>\`;
  };
  const priorityFor = (s) => {
    if (s.oosCount >= 5 || s.rate >= 80) return { label:'HIGH', bg: OOS_C };
    if (s.oosCount >= 2 || s.rate >= 50) return { label:'MED',  bg: CRIT_C };
    return { label:'LOW', bg: DARK };
  };
  const overviewRows = flagged.map((s, i) => {
    const cats = STOCK_CATS.map(c => catCell(s.catSummary && s.catSummary[c.name])).join('');
    const rateBg = s.rate >= 70 ? OOS_C : s.rate >= 40 ? CRIT_C : DARK;
    const p = priorityFor(s);
    return \`<tr style="background:\${i%2===0?'#ffffff':LIGHTER}">
      <td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${OOS_C};color:#fff;font-weight:bold">\${i+1}</td>
      <td style="border:1px solid #cfd8d3;padding:6px 10px;font-weight:bold;color:\${DARKER};font-size:12px">\${escapeHtml(s.store)}<div style="font-weight:normal;font-size:10px;color:#556;margin-top:2px">\${escapeHtml(s.manager)}</div></td>
      \${cats}
      <td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${rateBg};color:#fff;font-weight:bold">\${s.rate}%</td>
      <td style="border:1px solid #cfd8d3;padding:6px 10px;text-align:center;background:\${p.bg};color:#fff;font-weight:bold;letter-spacing:.5px">\${p.label}</td>
    </tr>\`;
  }).join('');
  const allStoresInScope = new Set();
  wReports.forEach(r => STOCK_CATS.forEach(c => (r.categories[c.name]||[]).forEach(e => allStoresInScope.add(e.store))));
  const totalStoresSeen = allStoresInScope.size;
  const flaggedPct = totalStoresSeen ? Math.round((flagged.length / totalStoresSeen) * 100) : 0;

  // ---- Executive Summary analysis ----
  const catAgg = {};
  STOCK_CATS.forEach(c => catAgg[c.name] = { oosStores:new Set(), critStores:new Set(), oosInstances:0, critInstances:0 });
  flagged.forEach(s => {
    STOCK_CATS.forEach(c => {
      const cs = s.catSummary && s.catSummary[c.name];
      if (!cs) return;
      if (cs.oos  > 0) { catAgg[c.name].oosStores.add(s.store);  catAgg[c.name].oosInstances  += cs.oos;  }
      if (cs.crit > 0) { catAgg[c.name].critStores.add(s.store); catAgg[c.name].critInstances += cs.crit; }
    });
  });
  const catRanked = STOCK_CATS.map(c => ({
    name: c.name, icon: c.icon,
    oosStores:  catAgg[c.name].oosStores.size,
    critStores: catAgg[c.name].critStores.size,
    oosInstances:  catAgg[c.name].oosInstances,
    critInstances: catAgg[c.name].critInstances,
    total: catAgg[c.name].oosInstances + catAgg[c.name].critInstances,
    affected: new Set([...catAgg[c.name].oosStores, ...catAgg[c.name].critStores]).size
  })).sort((a,b) => b.total - a.total);
  const topStoresByOOS  = [...flagged].sort((a,b) => b.oosCount - a.oosCount || b.critCount - a.critCount).slice(0, 3);
  const topStoresByRate = [...flagged].sort((a,b) => b.rate - a.rate || b.problemDays - a.problemDays).slice(0, 3);
  const topCat = catRanked[0];
  const catAnalysisRows = catRanked.map((c, i) => \`<tr style="background:\${i%2===0?'#ffffff':LIGHTER}">
    <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${i===0?OOS_C:i===1?CRIT_C:DARK};color:#fff;font-weight:bold;width:36px">\${i+1}</td>
    <td style="border:1px solid #cfd8d3;padding:5px 10px;font-weight:bold;font-size:13px;color:\${DARKER}">\${c.icon} \${c.name}</td>
    <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${c.oosInstances>0?OOS_C:'#fafafa'};color:\${c.oosInstances>0?'#fff':'#aaa'};font-weight:\${c.oosInstances>0?'bold':'normal'};font-size:12px">\${c.oosInstances} inst - \${c.oosStores} store\${c.oosStores===1?'':'s'}</td>
    <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${c.critInstances>0?CRIT_C:'#fafafa'};color:\${c.critInstances>0?'#fff':'#aaa'};font-weight:\${c.critInstances>0?'bold':'normal'};font-size:12px">\${c.critInstances} inst - \${c.critStores} store\${c.critStores===1?'':'s'}</td>
    <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;font-weight:bold">\${c.affected} of \${totalStoresSeen}</td>
  </tr>\`).join('');
  const topStoreItems = topStoresByOOS.map(s => \`<li style="margin:2px 0"><b>\${escapeHtml(s.store)}</b> - <span style="color:\${OOS_C};font-weight:bold">\${s.oosCount} OOS</span>, <span style="color:\${CRIT_C};font-weight:bold">\${s.critCount} Critical</span> in \${s.problemDays}/\${s.daysReported} days (\${s.rate}%)</li>\`).join('');
  const topRateItems  = topStoresByRate.map(s => \`<li style="margin:2px 0"><b>\${escapeHtml(s.store)}</b> - \${s.rate}% problem rate (\${s.problemDays} of \${s.daysReported} days affected)</li>\`).join('');
  const periodText = (STOCK_STATE.wFromEffective || STOCK_STATE.from) + ' to ' + (STOCK_STATE.wToEffective || STOCK_STATE.to);
  const weeklyProgressBlock = buildWeeklyProgressHTML(wReports, flagged, opts);
  /* Old inline computation kept commented out - now handled by helper */
  const _unused_weeklyBlockBuilder = () => {
  const weekOf2 = (dateStr) => {
    const dt = new Date(dateStr + 'T00:00:00');
    dt.setDate(dt.getDate() - ((dt.getDay() + 6) % 7));
    return dt.getFullYear()+'-'+String(dt.getMonth()+1).padStart(2,'0')+'-'+String(dt.getDate()).padStart(2,'0');
  };
  const MONTHS_S2 = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const fmtWeek2 = (mondayStr) => {
    const mon = new Date(mondayStr + 'T00:00:00');
    const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
    return mon.getMonth() === sun.getMonth()
      ? MONTHS_S2[mon.getMonth()] + ' ' + mon.getDate() + '-' + sun.getDate()
      : MONTHS_S2[mon.getMonth()] + ' ' + mon.getDate() + ' - ' + MONTHS_S2[sun.getMonth()] + ' ' + sun.getDate();
  };
  const weeklyData = {};
  wReports.forEach(r => {
    const wk = weekOf2(r.date);
    weeklyData[wk] = weeklyData[wk] || { catCounts: {}, storeCounts: {} };
    STOCK_CATS.forEach(c => {
      (r.categories[c.name] || []).forEach(e => {
        if (e.status !== 'OOS' && e.status !== 'Critical') return;
        const cat = weeklyData[wk].catCounts[c.name] = weeklyData[wk].catCounts[c.name] || { issues: 0, stores: new Set() };
        cat.issues++; cat.stores.add(e.store);
        weeklyData[wk].storeCounts[e.store] = (weeklyData[wk].storeCounts[e.store] || 0) + 1;
      });
    });
  });
  const weeksList = Object.keys(weeklyData).sort();
  const trendArrow = (last, prev) => {
    if (prev === undefined || last === undefined) return { arrow: '-', color: '#888' };
    if (last < prev) return { arrow: '&darr; improving', color: DARK };
    if (last > prev) return { arrow: '&uarr; worsening', color: OOS_C };
    return { arrow: '&rarr; stable', color: '#888' };
  };
  const scaleColor = (val, min, max) => {
    if (max === min || val === 0) return val === 0 ? '#e8f5ec' : LIGHTER;
    const norm = (val - min) / (max - min);
    if (norm < 0.34) return '#e8f5ec';
    if (norm < 0.67) return '#fff5e0';
    return '#fee';
  };
  const weekHeaders = weeksList.map(w => \`<th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center;font-size:12px">\${fmtWeek2(w)}</th>\`).join('');
  const catWeekRows = STOCK_CATS.map(c => {
    const values = weeksList.map(w => weeklyData[w].catCounts[c.name] || { issues: 0, stores: new Set() });
    const issueCounts = values.map(v => v.issues);
    const mn = Math.min.apply(null, issueCounts.length ? issueCounts : [0]);
    const mx = Math.max.apply(null, issueCounts.length ? issueCounts : [0]);
    const cells = values.map(v => \`<td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${scaleColor(v.issues, mn, mx)};font-size:12px">\${v.issues > 0 ? '<b>'+v.issues+'</b> - '+v.stores.size+' store'+(v.stores.size===1?'':'s') : '<span style="color:#888">0</span>'}</td>\`).join('');
    const trend = issueCounts.length >= 2 ? trendArrow(issueCounts[issueCounts.length-1], issueCounts[issueCounts.length-2]) : { arrow: '-', color: '#888' };
    return \`<tr>
      <td style="border:1px solid #cfd8d3;padding:5px 10px;font-weight:bold;font-size:13px;color:\${DARKER}">\${c.icon} \${c.name}</td>
      \${cells}
      <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;color:\${trend.color};font-weight:bold;font-size:12px">\${trend.arrow}</td>
    </tr>\`;
  }).join('');
  const storeWeekRows = flagged.map(s => {
    const values = weeksList.map(w => weeklyData[w].storeCounts[s.store] || 0);
    const mn = Math.min.apply(null, values.length ? values : [0]);
    const mx = Math.max.apply(null, values.length ? values : [0]);
    const cells = values.map(v => \`<td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;background:\${scaleColor(v, mn, mx)};font-size:12px">\${v > 0 ? '<b>'+v+'</b>' : '<span style="color:#888">0</span>'}</td>\`).join('');
    const trend = values.length >= 2 ? trendArrow(values[values.length-1], values[values.length-2]) : { arrow: '-', color: '#888' };
    return \`<tr>
      <td style="border:1px solid #cfd8d3;padding:5px 10px;font-weight:bold;font-size:12px">\${escapeHtml(s.store)}</td>
      \${cells}
      <td style="border:1px solid #cfd8d3;padding:5px 8px;text-align:center;color:\${trend.color};font-weight:bold;font-size:12px">\${trend.arrow}</td>
    </tr>\`;
  }).join('');
  const weeklyProgressBlock = weeksList.length ? \`
    <div style="background:\${DARK};color:#fff;padding:8px 12px;margin-top:12px;font-weight:bold;font-size:14px;letter-spacing:.3px">WEEKLY PROGRESS REPORT</div>
    <div style="color:#556;font-size:11px;margin:4px 0 6px">Values show OOS+Critical instances per Mon-Sun week. Colour scale per row: green = best week, red = worst week. Trend compares latest 2 weeks.</div>
    <div style="background:\${DARKER};color:#fff;padding:6px 12px;font-weight:bold;font-size:12px;letter-spacing:.3px">BY CATEGORY</div>
    <table style="border-collapse:collapse;font-size:12px;margin-bottom:12px;width:100%">
      <thead><tr>
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:left;min-width:140px">Category</th>
        \${weekHeaders}
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center;min-width:110px">Trend</th>
      </tr></thead>
      <tbody>\${catWeekRows}</tbody>
    </table>
    <div style="background:\${DARKER};color:#fff;padding:6px 12px;font-weight:bold;font-size:12px;letter-spacing:.3px">BY STORE (all flagged)</div>
    <table style="border-collapse:collapse;font-size:12px;margin-bottom:18px;width:100%">
      <thead><tr>
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:left;min-width:160px">Store</th>
        \${weekHeaders}
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center;min-width:110px">Trend</th>
      </tr></thead>
      <tbody>\${storeWeekRows}</tbody>
    </table>\` : '';
  }; // end _unused_weeklyBlockBuilder

  const execSummaryBlock = \`
    <div style="background:\${DARK};color:#fff;padding:8px 12px;margin-top:6px;font-weight:bold;font-size:14px;letter-spacing:.3px">KEY INSIGHTS</div>
    <div style="border:1px solid #cfd8d3;border-top:0;padding:12px 14px;background:\${LIGHTER};font-size:12px;line-height:1.6;color:#334;margin-bottom:6px">
      <div style="margin-bottom:8px"><b style="color:\${DARKER}">Reporting Period:</b> \${periodText} &nbsp;|&nbsp; <b style="color:\${DARKER}">Stores Analyzed:</b> \${totalStoresSeen} &nbsp;|&nbsp; <b style="color:\${DARKER}">Flagged:</b> \${flagged.length} (\${flaggedPct}%)</div>
      <div style="margin-bottom:10px">Across the period, the flagged stores logged <b style="color:\${OOS_C}">\${totOOS} OOS instances</b> and <b style="color:\${CRIT_C}">\${totCrit} Critical instances</b>.\${topCat && topCat.total > 0 ? ' <b>' + topCat.icon + ' ' + topCat.name + '</b> is the most problematic category (' + topCat.total + ' combined instances across ' + topCat.affected + ' stores).' : ''}</div>
      <div style="display:flex;gap:14px;flex-wrap:wrap">
        <div style="flex:1;min-width:260px;background:#fff;border:1px solid #e0d0d0;padding:8px 12px;border-radius:4px">
          <div style="font-weight:bold;color:\${OOS_C};font-size:12px;margin-bottom:4px">TOP 3 STORES BY OOS VOLUME</div>
          <ol style="margin:4px 0;padding-left:18px;font-size:12px">\${topStoreItems || '<li>none</li>'}</ol>
        </div>
        <div style="flex:1;min-width:260px;background:#fff;border:1px solid #e0d0d0;padding:8px 12px;border-radius:4px">
          <div style="font-weight:bold;color:\${CRIT_C};font-size:12px;margin-bottom:4px">TOP 3 STORES BY PROBLEM RATE</div>
          <ol style="margin:4px 0;padding-left:18px;font-size:12px">\${topRateItems || '<li>none</li>'}</ol>
        </div>
      </div>
    </div>
    <div style="background:\${DARKER};color:#fff;padding:6px 12px;font-weight:bold;font-size:12px;letter-spacing:.3px">CATEGORY RANKING (most problematic first)</div>
    <table style="border-collapse:collapse;font-size:12px;margin-bottom:18px;width:100%">
      <thead><tr>
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center;width:36px">#</th>
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:left">Category</th>
        <th style="background:\${OOS_C};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center">OOS Frequency</th>
        <th style="background:\${CRIT_C};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center">Critical Frequency</th>
        <th style="background:\${DARK};color:#fff;padding:6px 8px;border:1px solid \${DARKER};font-weight:bold;text-align:center">Stores Affected</th>
      </tr></thead>
      <tbody>\${catAnalysisRows}</tbody>
    </table>\`;
  return \`
    <div style="padding:14px 4px 4px"><div style="font-size:22px;font-weight:bold;color:\${DARKER};letter-spacing:.3px">\${escapeHtml(titleText)}</div></div>
    <table style="border-collapse:collapse;margin:8px 0 18px;font-size:12px">
      \${regionRow}
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Reporting Period</td><td style="padding:6px 12px">\${STOCK_STATE.wFromEffective || STOCK_STATE.from} to \${STOCK_STATE.wToEffective || STOCK_STATE.to}</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Prepared By</td><td style="padding:6px 12px">\${escapeHtml(S.manager)} (\${escapeHtml(S.level)})</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Generated</td><td style="padding:6px 12px">\${new Date().toLocaleString()}</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Flag Criteria</td><td style="padding:6px 12px">Problem rate &ge; 50% OR 3+ problem days in the period</td></tr>
    </table>
    <table style="border-collapse:collapse;margin-bottom:18px;font-size:13px">
      <tr>
        <td style="padding:14px 20px;background:\${OOS_C};color:#fff;font-weight:bold;text-align:center;min-width:120px"><div style="font-size:28px">\${flagged.length}</div><div style="font-size:11px;letter-spacing:.5px">STORES FLAGGED</div></td>
        <td style="padding:14px 20px;background:\${OOS_C};color:#fff;font-weight:bold;text-align:center;min-width:120px"><div style="font-size:28px">\${totOOS}</div><div style="font-size:11px;letter-spacing:.5px">OOS INSTANCES</div></td>
        <td style="padding:14px 20px;background:\${CRIT_C};color:#fff;font-weight:bold;text-align:center;min-width:120px"><div style="font-size:28px">\${totCrit}</div><div style="font-size:11px;letter-spacing:.5px">CRITICAL INSTANCES</div></td>
        <td style="padding:14px 20px;background:\${DARK};color:#fff;font-weight:bold;text-align:center;min-width:120px"><div style="font-size:28px">\${reportingDays}</div><div style="font-size:11px;letter-spacing:.5px">REPORTING DAYS</div><div style="font-size:10px;opacity:.85;font-weight:normal;margin-top:2px">calendar days covered by this report</div></td>
      </tr>
    </table>
    \${execSummaryBlock}
    \${weeklyProgressBlock}
    <div style="background:\${DARK};color:#fff;padding:8px 12px;font-weight:bold;font-size:14px;letter-spacing:.3px">FLAGGED STORES OVERVIEW</div>
    <div style="color:#556;font-size:11px;margin:4px 0 4px">Each category cell shows the worst status recorded in the period, with the number of days at that status. Priority column combines OOS count and problem rate. Sorted worst first.</div>
    <div style="margin:4px 0 6px;font-size:10px;color:#556">Sparkline bars = each reported day in the range, oldest to newest. <span style="display:inline-block;width:8px;height:8px;background:\${OOS_C};vertical-align:-1px;margin:0 3px"></span>OOS <span style="display:inline-block;width:8px;height:8px;background:\${CRIT_C};vertical-align:-1px;margin:0 3px"></span>Critical <span style="display:inline-block;width:8px;height:8px;background:\${DARK};vertical-align:-1px;margin:0 3px"></span>Healthy <span style="display:inline-block;width:8px;height:8px;background:#dcdcdc;vertical-align:-1px;margin:0 3px"></span>No data</div>
    \${totalStoresSeen ? '<div style="margin:6px 0 14px;padding:8px 12px;background:'+LIGHT_BG+';border-left:4px solid '+DARK+';font-size:12px;color:'+DARKER+'"><b>'+flagged.length+'</b> of <b>'+totalStoresSeen+'</b> stores flagged for HQ escalation in this period (<b>'+flaggedPct+'%</b>). Remaining '+(totalStoresSeen - flagged.length)+' store(s) either meet compliance or had only isolated issues.</div>' : ''}
    <table style="border-collapse:collapse;font-size:12px;margin-bottom:22px">
      <thead><tr>
        <th style="background:\${DARKER};color:#fff;padding:10px 8px;border:2px solid \${DARKER};font-weight:bold;text-align:center;width:40px;font-size:13px">#</th>
        <th style="background:\${DARKER};color:#fff;padding:10px 12px;border:2px solid \${DARKER};font-weight:bold;text-align:left;width:180px;font-size:13px">Store</th>
        \${STOCK_CATS.map(c => \`<th style="background:#fff8e1;color:\${DARKER};padding:12px 8px;border:2px solid \${CRIT_C};font-weight:bold;text-align:center;width:140px;font-size:15px">\${c.icon} \${c.name}</th>\`).join('')}
        <th style="background:\${DARKER};color:#fff;padding:10px 8px;border:2px solid \${DARKER};font-weight:bold;text-align:center;width:90px;font-size:13px">Problem Rate</th>
        <th style="background:\${DARKER};color:#fff;padding:10px 8px;border:2px solid \${DARKER};font-weight:bold;text-align:center;width:80px;font-size:13px">Priority</th>
      </tr></thead>
      <tbody>\${overviewRows}</tbody>
    </table>\`;
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

  // Title based on role: AM shows "<Area> Area" with Region subrow; RM shows "<Region>"
  const isAMRole = (S.level||'').toLowerCase() === 'area manager';
  const areaLabel = STOCK_STATE.amArea || '';
  const regionLabel = STOCK_STATE.amRegion || 'CAMANAVA';
  const titleText = isAMRole
    ? (areaLabel ? areaLabel + ' Area' : regionLabel) + ' Fresh Focus 5 Categories Stock Status Report'
    : regionLabel + ' Fresh Focus 5 Categories Stock Status Report';
  const regionRow = isAMRole
    ? \`<tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Region</td><td style="padding:6px 12px">\${escapeHtml(regionLabel)}</td></tr>\`
    : '';
  const headerBlock = \`
    <div style="padding:14px 4px 4px">
      <div style="font-size:22px;font-weight:bold;color:\${DARKER};letter-spacing:.3px">\${escapeHtml(titleText)}</div>
    </div>
    <table style="border-collapse:collapse;margin:8px 0 18px;font-size:12px">
      \${regionRow}
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Reporting Period</td><td style="padding:6px 12px">\${STOCK_STATE.wFromEffective || STOCK_STATE.from} to \${STOCK_STATE.wToEffective || STOCK_STATE.to}</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Prepared By</td><td style="padding:6px 12px">\${escapeHtml(S.manager)} (\${escapeHtml(S.level)})</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Generated</td><td style="padding:6px 12px">\${new Date().toLocaleString()}</td></tr>
      <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Flag Criteria</td><td style="padding:6px 12px">Problem rate &ge; 50% OR 3+ problem days in the period</td></tr>
    </table>\`;

  // Executive KPIs
  const totOOS = flagged.reduce((n,s) => n+s.oosCount, 0);
  const totCrit = flagged.reduce((n,s) => n+s.critCount, 0);
  // Number of unique calendar days in the watchlist range that had any report
  const reportingDays = new Set(wReports.map(r => r.date)).size;
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
          <div style="font-size:28px">\${reportingDays}</div>
          <div style="font-size:11px;letter-spacing:.5px">REPORTING DAYS</div>
          <div style="font-size:10px;opacity:.85;font-weight:normal;margin-top:2px">calendar days covered by this report</div>
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
      <thead>
        <tr>
          <th style="background:\${DARKER};color:#fff;padding:10px 8px;border:2px solid \${DARKER};font-weight:bold;text-align:center;width:40px;font-size:13px">#</th>
          <th style="background:\${DARKER};color:#fff;padding:10px 12px;border:2px solid \${DARKER};font-weight:bold;text-align:left;width:180px;font-size:13px">Store</th>
          \${STOCK_CATS.map(c => \`<th style="background:#fff8e1;color:\${DARKER};padding:12px 8px;border:2px solid \${CRIT_C};font-weight:bold;text-align:center;width:140px;font-size:15px">\${c.icon} \${c.name}</th>\`).join('')}
          <th style="background:\${DARKER};color:#fff;padding:10px 8px;border:2px solid \${DARKER};font-weight:bold;text-align:center;width:90px;font-size:13px">Problem Rate</th>
          <th style="background:\${DARKER};color:#fff;padding:10px 8px;border:2px solid \${DARKER};font-weight:bold;text-align:center;width:80px;font-size:13px">Priority</th>
        </tr>
      </thead>
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
  \${buildFlaggedOverviewHTML(data, flagged, wReports)}
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

// ---- Focus 5 Stock Status - Regional Manager dashboard (sourced from SKUChecklistData) ----
async function loadStockTabRM(){
  const out = $('#stockOut');
  out.innerHTML = '<div class="card muted">Loading...</div>';
  const date = todayStr();
  const [rmRes, reviewRes] = await Promise.all([
    api('/api/sku-rm-monitor?date=' + date),
    api('/api/review-monitor?date=' + date)
  ]);
  if (!rmRes.ok) { out.innerHTML = '<div class="card err">'+escapeHtml(rmRes.error||'Failed to load')+'</div>'; return; }
  const k = rmRes.kpis;
  const DARK = '#1f7a3a', ACCENT = '#FFC107', OOS = '#c33', AMBER = '#e0a020';

  // KPI tiles
  const kpi = (icon, num, lbl, bg, sub) => \`<div style="flex:1 1 150px;min-width:0;background:\${bg};color:#fff;padding:14px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08)">
    <div style="font-size:22px;opacity:.95;line-height:1">\${icon}</div>
    <div style="font-size:28px;font-weight:800;margin-top:6px;line-height:1">\${num}</div>
    <div style="font-size:11px;opacity:.95;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:.4px">\${lbl}</div>
    \${sub?'<div style="font-size:10px;opacity:.85;margin-top:2px;font-weight:400">'+sub+'</div>':''}
  </div>\`;
  const complianceBg = k.complianceRate >= 90 ? DARK : k.complianceRate >= 60 ? AMBER : OOS;
  const passBg       = k.passRate       >= 90 ? DARK : k.passRate       >= 70 ? AMBER : OOS;
  const onTimeBg     = k.onTimeRate     >= 90 ? DARK : k.onTimeRate     >= 70 ? AMBER : OOS;
  const kpiRow = \`<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px">
    \${kpi('&#128202;', k.complianceRate + '%', 'Slot Compliance', complianceBg, k.submittedSlots+' of '+k.expectedSlots+' slots submitted')}
    \${kpi('&#9203;',    k.onTimeRate     + '%', 'On-Time Rate',   onTimeBg,     k.onTimeSlots+' on time &middot; '+k.lateSlots+' late')}
    \${kpi('&#127919;',  k.passRate       + '%', 'Pass Rate',       passBg,       k.totalAvailable+' available of '+(k.totalAvailable+k.totalOOS))}
    \${kpi('&#10060;',   k.totalOOS,              'OOS SKUs Today', OOS,          'across '+k.submittedSlots+' submitted slots')}
    \${kpi('&#127978;',  k.totalStores,           'Stores',          '#345',       k.expectedSlots+' total slot submissions expected')}
  </div>\`;

  // AM Review Dashboard
  let amReviewCard = '';
  if (reviewRes && reviewRes.ok) {
    const amStats = reviewRes.amStats || [];
    const totExp = amStats.reduce((n,a)=>n+a.slotsTotal,0);
    const totDn  = amStats.reduce((n,a)=>n+a.reviewed,0);
    const totLt  = amStats.reduce((n,a)=>n+a.late,0);
    const cRate = totExp ? Math.round((totDn/totExp)*100) : 0;
    const nowHr = new Date().getHours();
    const amRows = amStats.map(a => {
      const nm = nameOf(a.manager);
      const chip = (b, dlHr) => {
        const past = nowHr >= dlHr;
        if (b.reviewed) { const bg = b.onTime ? DARK : OOS; return '<span style="display:inline-block;background:'+bg+';color:#fff;padding:3px 8px;border-radius:10px;font-size:11px;font-weight:700;margin:1px" title="'+escapeHtml(b.store)+' '+b.slot+' - '+(b.onTime?'on time':'LATE')+'">'+escapeHtml(b.store)+'</span>'; }
        if (!b.smSubmitted) return '<span style="display:inline-block;background:#eef;color:#789;padding:3px 8px;border-radius:10px;font-size:11px;font-weight:700;margin:1px" title="'+escapeHtml(b.store)+' - SM not submitted">'+escapeHtml(b.store)+' (SM&#9888;)</span>';
        const bg = past ? OOS : AMBER;
        return '<span style="display:inline-block;background:'+bg+';color:#fff;padding:3px 8px;border-radius:10px;font-size:11px;font-weight:700;margin:1px" title="'+escapeHtml(b.store)+' - '+(past?'past deadline, not reviewed':'awaiting review')+'">'+escapeHtml(b.store)+(past?' LATE':' pending')+'</span>';
      };
      const amB = a.breakdown.filter(b => b.slot==='AM'), pmB = a.breakdown.filter(b => b.slot==='PM');
      const borderCol = a.late > 0 ? OOS : (a.pending > 0 ? AMBER : DARK);
      const rowBg = a.pending > 0 ? '#fff5f5' : '#f0faf3';
      return \`<div style="border-left:4px solid \${borderCol};background:\${rowBg};padding:10px 12px;border-radius:6px;margin-bottom:8px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
          <b style="font-size:14px;color:#223;flex:1">\${escapeHtml(nm)}\${nm!==a.manager?' <span style="color:#789;font-weight:400;font-size:11px">('+escapeHtml(a.manager)+')</span>':''}</b>
          <span style="background:#fff;color:#1f7a3a;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px;border:1px solid #cfd8d3">\${a.reviewed}/\${a.slotsTotal} done</span>
          \${a.late?'<span style="background:'+OOS+';color:#fff;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px">'+a.late+' LATE</span>':''}
          \${a.pending?'<span style="background:'+AMBER+';color:#fff;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px">'+a.pending+' pending</span>':'<span style="background:'+DARK+';color:#fff;padding:2px 10px;border-radius:10px;font-weight:700;font-size:12px">ALL DONE</span>'}
        </div>
        <div style="font-size:11px;color:#789;margin-bottom:2px"><b>AM slot</b> (deadline 11:00):</div>
        <div style="margin-bottom:4px">\${amB.map(b=>chip(b,11)).join('')||'<span class="muted">none</span>'}</div>
        <div style="font-size:11px;color:#789;margin-bottom:2px"><b>PM slot</b> (deadline 16:00):</div>
        <div>\${pmB.map(b=>chip(b,16)).join('')||'<span class="muted">none</span>'}</div>
      </div>\`;
    }).join('');
    amReviewCard = \`<div class="card">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px">
        <h3 style="margin:0;color:#1f7a3a">AM Review Dashboard</h3>
        <span style="background:\${cRate===100?DARK:OOS};color:#fff;padding:4px 12px;border-radius:12px;font-weight:800;font-size:13px">\${cRate}% done</span>
        <span class="muted" style="font-size:12px">\${totDn}/\${totExp} reviews &middot; \${totLt} late</span>
      </div>
      \${amRows || '<div class="muted">No Area Managers assigned yet.</div>'}
    </div>\`;
  }

  // Category breakdown chart
  const CATS = [{n:'RICE',i:'&#127834;'},{n:'EGGS',i:'&#129370;'},{n:'POULTRY',i:'&#128020;'},{n:'MEAT',i:'&#129385;'},{n:'SUGAR',i:'&#129474;'}];
  const catBars = CATS.map(c => {
    const b = (rmRes.categories && rmRes.categories[c.n]) || { oos:0, available:0 };
    const total = b.oos + b.available;
    if (!total) return '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><div style="width:120px;font-size:13px;font-weight:600">'+c.i+' '+c.n+'</div><div style="flex:1;height:24px;background:#f2f2f2;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#aaa;font-size:11px">No data yet</div></div>';
    const oPct = (b.oos/total)*100;
    const aPct = (b.available/total)*100;
    return '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><div style="width:120px;font-size:13px;font-weight:600">'+c.i+' '+c.n+'</div><div style="flex:1;height:24px;background:#eee;border-radius:6px;overflow:hidden;display:flex">'
      + (b.oos?'<div style="width:'+oPct+'%;background:'+OOS+';color:#fff;font-weight:700;font-size:11px;display:flex;align-items:center;justify-content:center">'+b.oos+' OOS</div>':'')
      + (b.available?'<div style="width:'+aPct+'%;background:'+DARK+';color:#fff;font-weight:700;font-size:11px;display:flex;align-items:center;justify-content:center">'+b.available+' Available</div>':'')
      + '</div><div style="width:60px;text-align:right;font-size:12px;color:#556">'+total+'</div></div>';
  }).join('');
  const catCard = \`<div class="card">
    <h3 style="margin:0 0 8px;color:#1f7a3a">SKU Status by Category - Today</h3>
    <div style="font-size:11px;color:#789;margin-bottom:8px"><span style="display:inline-block;width:10px;height:10px;background:\${OOS};border-radius:2px;vertical-align:middle;margin-right:4px"></span>OOS <span style="display:inline-block;width:10px;height:10px;background:\${DARK};border-radius:2px;vertical-align:middle;margin-right:4px;margin-left:10px"></span>Available</div>
    \${catBars}
  </div>\`;

  // 14-day OOS trend
  const maxOOS = Math.max(1, ...rmRes.trend.map(t => t.oos));
  const trendBars = rmRes.trend.map(t => {
    const h = Math.round((t.oos / maxOOS) * 90) + 4;
    const bg = t.oos === 0 ? DARK : t.oos < 20 ? AMBER : OOS;
    return '<div style="flex:1;min-width:30px;max-width:60px;display:flex;flex-direction:column;align-items:center;gap:3px"><div style="font-size:10px;color:'+OOS+';font-weight:700">'+(t.oos||'')+'</div><div style="width:100%;background:#eee;border-radius:3px;height:100px;display:flex;align-items:flex-end"><div style="width:100%;height:'+h+'px;background:'+bg+'"></div></div><div style="font-size:9px;color:#789">'+t.date.slice(5)+'</div><div style="font-size:9px;color:#556">'+t.submissions+'s</div></div>';
  }).join('');
  const trendCard = \`<div class="card">
    <h3 style="margin:0 0 8px;color:#1f7a3a">Daily OOS Trend - Last 14 Days</h3>
    <div style="font-size:11px;color:#789;margin-bottom:8px">Bar = OOS SKU count that day across all stores. Small number below = # slot submissions that day.</div>
    <div style="display:flex;gap:4px;overflow-x:auto;padding:4px 0">\${trendBars}</div>
  </div>\`;

  // Per-store compliance grid
  const storeRows = rmRes.storeStats.map(s => {
    const slotCell = (slot, dlHr) => {
      if (slot.submitted) {
        const bg = slot.onTime ? DARK : OOS;
        const nm = slot.submittedBy ? nameOf(slot.submittedBy) : '';
        return '<td style="padding:4px 8px;text-align:center;background:'+bg+';color:#fff;font-weight:700;font-size:11px" title="OOS: '+slot.oos+' / Total: '+slot.total+(nm?' - by '+nm:'')+'">'+(slot.onTime?'OK':'LATE')+' <span style="font-size:10px;opacity:.9">('+slot.oos+' OOS)</span></td>';
      }
      const nowHr = new Date().getHours();
      const past = nowHr >= dlHr;
      const bg = past ? OOS : '#aaa';
      return '<td style="padding:4px 8px;text-align:center;background:'+bg+';color:#fff;font-weight:700;font-size:11px">'+(past?'MISSED':'NOT YET')+'</td>';
    };
    return '<tr><td style="padding:4px 8px;font-weight:600;font-size:12px">'+escapeHtml(s.store)+'<div style="font-size:10px;color:#789">'+escapeHtml(s.area)+'</div></td>'+slotCell(s.am,10)+slotCell(s.pm,15)+'</tr>';
  }).join('');
  const gridCard = \`<div class="card">
    <h3 style="margin:0 0 8px;color:#1f7a3a">Per-Store Submission Grid - Today</h3>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#eef"><th style="padding:6px 8px;text-align:left">Store</th><th style="padding:6px 8px;text-align:center">AM slot</th><th style="padding:6px 8px;text-align:center">PM slot</th></tr></thead>
      <tbody>\${storeRows}</tbody>
    </table></div>
  </div>\`;

  // Late submitters list
  const latesAM = rmRes.storeStats.filter(s => s.am.submitted && !s.am.onTime).map(s => ({store:s.store, slot:'AM', by:s.am.submittedBy, ts:s.am.timestamp}));
  const latesPM = rmRes.storeStats.filter(s => s.pm.submitted && !s.pm.onTime).map(s => ({store:s.store, slot:'PM', by:s.pm.submittedBy, ts:s.pm.timestamp}));
  const lates = latesAM.concat(latesPM);
  const latesHTML = lates.length ? lates.map(l => '<div style="padding:6px 8px;border-left:3px solid '+OOS+';background:#fff5f5;margin-bottom:4px;font-size:12px"><b>'+escapeHtml(l.store)+'</b> <span style="color:#789">('+l.slot+')</span> <span style="color:'+OOS+';font-weight:700">LATE</span> - by <b>'+escapeHtml(nameOf(l.by))+'</b> at '+new Date(l.ts).toLocaleString()+'</div>').join('') : '<div class="muted" style="padding:6px">No late submissions today</div>';
  const latesCard = \`<div class="card">
    <h3 style="margin:0 0 8px;color:\${lates.length?OOS:DARK}">Late Submissions Today \${lates.length?'('+lates.length+')':''}</h3>
    \${latesHTML}
  </div>\`;

  out.innerHTML = kpiRow + amReviewCard + catCard + trendCard + gridCard + latesCard;
}

// ---- Stock Review (Area Manager) ----
let REVIEW_STATE = { items: [], loading: false, expanded: {}, confirmed: {} };
// expanded: { "store||slot": true }
// confirmed: { "store||slot": Set of SKU codes }
function rvKey(store, slot){ return store + '||' + slot; }

async function loadReviewTab(){
  const out = $('#stockOut');
  out.innerHTML = '<div class="card muted">Loading reviews...</div>';
  const date = todayStr();
  const [pendingRes] = await Promise.all([
    api('/api/review-pending?manager=' + encodeURIComponent(S.manager) + '&date=' + date)
  ]);
  if (!pendingRes.ok) { out.innerHTML = '<div class="card err">'+escapeHtml(pendingRes.error||'Failed')+'</div>'; return; }
  REVIEW_STATE.items = pendingRes.items || [];
  renderReviewTab();
}

function renderReviewTab(){
  const out = $('#stockOut');
  const date = todayStr();
  const items = REVIEW_STATE.items;
  const amItems = items.filter(x => x.slot === 'AM');
  const pmItems = items.filter(x => x.slot === 'PM');
  const nowHr = new Date().getHours();
  const amDeadlinePassed = nowHr >= 11;
  const pmDeadlinePassed = nowHr >= 16;

  const totalSlots = items.length;
  const reviewed = items.filter(x => x.reviewed).length;
  const pending  = items.filter(x => !x.reviewed && x.skuSubmitted).length;
  const notYetSubmittedBySM = items.filter(x => !x.skuSubmitted).length;

  const kpi = (icon, num, lbl, bg) => \`<div style="flex:1 1 140px;min-width:0;background:\${bg};color:#fff;padding:14px;border-radius:10px">
    <div style="font-size:20px;opacity:.9;line-height:1">\${icon}</div>
    <div style="font-size:28px;font-weight:800;margin-top:6px;line-height:1">\${num}</div>
    <div style="font-size:12px;opacity:.95;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:.4px">\${lbl}</div>
  </div>\`;
  const headerCard = \`<div class="card">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">
      <h3 style="margin:0;color:#1f7a3a">Focus 5 Stock Status - Review &amp; Validate</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${escapeHtml(S.manager)}</span>
      <span style="background:#eef;color:#334;font-weight:600;font-size:11px;padding:3px 10px;border-radius:12px">\${date}</span>
    </div>
    <div style="margin-bottom:10px;padding:10px 12px;background:#fff8e1;border-left:4px solid #e0a020;border-radius:4px;font-size:12px;color:#5a4300">
      <b style="color:#a06800">DEADLINES:</b> Validate <b>AM slot</b> submissions before <b>11:00 AM</b> and <b>PM slot</b> submissions before <b>4:00 PM</b>. Reviews are per store per slot. Store Managers' SKU Checklist must be submitted first.
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      \${kpi('&#128202;', totalSlots, 'Total Slot Reviews', '#345')}
      \${kpi('&#9989;',   reviewed,   'Reviewed Today',   '#1f7a3a')}
      \${kpi('&#9203;',   pending,    'Pending (SM Done)','#e0a020')}
      \${kpi('&#9888;',   notYetSubmittedBySM, 'SM Not Yet', '#c33')}
    </div>
  </div>\`;

  const renderSection = (title, slot, deadlineHr, items2, deadlinePassed) => \`<div class="card">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px">
      <h3 style="margin:0;color:#1f7a3a">\${title}</h3>
      <span style="background:\${deadlinePassed?'#c33':'#e0a020'};color:#fff;font-weight:600;font-size:11px;padding:3px 10px;border-radius:12px">Deadline \${deadlineHr}:00 \${deadlinePassed?'(PASSED)':''}</span>
    </div>
    \${items2.length ? '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px">' + items2.map(x => reviewCardHTML(x, deadlinePassed)).join('') + '</div>' : '<div class="muted" style="padding:10px">No stores assigned.</div>'}
  </div>\`;

  const amSection = renderSection('AM Slot Reviews', 'AM', 11, amItems, amDeadlinePassed);
  const pmSection = renderSection('PM Slot Reviews', 'PM', 16, pmItems, pmDeadlinePassed);

  out.innerHTML = headerCard + amSection + pmSection;
  document.querySelectorAll('[data-review-store]').forEach(b => b.onclick = () => doReview(b.dataset.reviewStore, b.dataset.reviewSlot));
  document.querySelectorAll('[data-rv-toggle]').forEach(b => b.onclick = () => toggleRvExpand(b.dataset.rvToggle, b.dataset.rvSlot));
  document.querySelectorAll('[data-rv-sku]').forEach(cb => cb.onchange = () => toggleRvSku(cb.dataset.rvStore, cb.dataset.rvSlot2, cb.dataset.rvSku));
  document.querySelectorAll('[data-rv-confirmall]').forEach(b => b.onclick = () => confirmAllRvSkus(b.dataset.rvConfirmall, b.dataset.rvSlot));
}

function reviewCardHTML(x, deadlinePassed){
  const DARK = '#1f7a3a', OOS = '#c33', AMBER = '#e0a020';
  const key = rvKey(x.store, x.slot);
  const oosList = x.oosList || [];
  const confirmed = REVIEW_STATE.confirmed[key] || new Set();
  const expanded = REVIEW_STATE.expanded[key];
  const allConfirmed = oosList.length === 0 || oosList.every(o => confirmed.has(o.sku));
  let statusBadge, borderColor, bgTint;
  if (x.reviewed) {
    statusBadge = x.reviewOnTime
      ? '<span style="background:'+DARK+';color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">VALIDATED</span>'
      : '<span style="background:'+OOS+';color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">VALIDATED (LATE)</span>';
    borderColor = x.reviewOnTime ? DARK : OOS; bgTint = '#f4faf6';
  } else if (!x.skuSubmitted) {
    statusBadge = '<span style="background:'+OOS+';color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">SM NOT YET</span>';
    borderColor = OOS; bgTint = '#fff5f5';
  } else {
    statusBadge = deadlinePassed
      ? '<span style="background:'+OOS+';color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">PENDING (LATE)</span>'
      : '<span style="background:'+AMBER+';color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">PENDING</span>';
    borderColor = AMBER; bgTint = '#fffdf6';
  }
  const smName = x.skuSubmittedBy ? nameOf(x.skuSubmittedBy) : (x.storeManagerName || '');
  const skuStat = x.skuSubmitted
    ? '<div style="font-size:12px;color:#456;margin-top:4px"><span style="color:'+DARK+';font-weight:700">'+x.skuAvailable+' Available</span> · <span style="color:'+OOS+';font-weight:700">'+x.skuOOS+' OOS</span> · <span style="color:#789">'+x.skuTotal+' total</span></div>'
      + '<div style="font-size:11px;color:#789;margin-top:2px">SM submitted ' + new Date(x.skuTimestamp).toLocaleString() + (x.skuOnTime ? '' : ' <b style="color:'+OOS+'">LATE</b>') + (smName?' <b style="color:#334">by '+escapeHtml(smName)+'</b>':'') + '</div>'
    : '<div style="font-size:11px;color:#c33;margin-top:4px">Store Manager has not submitted SKU Checklist for this slot yet.</div>';
  const reviewInfo = x.reviewed
    ? '<div style="font-size:11px;color:#789;margin-top:4px">Reviewed ' + new Date(x.reviewTimestamp).toLocaleString() + ' by <b style="color:#334">'+escapeHtml(nameOf(S.manager))+'</b></div>'
    : '';
  // Expand/collapse for OOS SKU confirmation
  let expandSection = '';
  if (!x.reviewed && x.skuSubmitted && oosList.length) {
    const confirmedCount = oosList.filter(o => confirmed.has(o.sku)).length;
    const toggleBtn = '<button data-rv-toggle="'+escapeHtml(x.store)+'" data-rv-slot="'+x.slot+'" style="margin-top:8px;width:100%;background:#eef;color:#223;border:0;padding:8px;border-radius:6px;font-weight:600;cursor:pointer;font-size:12px">'+(expanded?'&#9660; Hide OOS list':'&#9654; Review '+oosList.length+' OOS SKUs ('+confirmedCount+'/'+oosList.length+' confirmed)')+'</button>';
    let oosHtml = '';
    if (expanded) {
      const confirmAllBtn = '<button data-rv-confirmall="'+escapeHtml(x.store)+'" data-rv-slot="'+x.slot+'" style="margin:6px 0;background:#1f7a3a;color:#fff;border:0;padding:6px 10px;border-radius:4px;font-weight:600;cursor:pointer;font-size:11px">Confirm All</button>';
      oosHtml = '<div style="margin-top:6px;padding:8px;background:#fff5f5;border-radius:4px;max-height:280px;overflow-y:auto">'
        + confirmAllBtn
        + oosList.map(o => {
          const checked = confirmed.has(o.sku) ? 'checked' : '';
          return '<label style="display:flex;align-items:flex-start;gap:6px;padding:5px 0;border-bottom:1px dashed #eed;cursor:pointer">'
            + '<input type="checkbox" '+checked+' data-rv-sku="'+escapeHtml(o.sku)+'" data-rv-store="'+escapeHtml(x.store)+'" data-rv-slot2="'+x.slot+'" style="margin-top:3px"/>'
            + '<div style="flex:1;font-size:11px">'
              + '<div><b style="color:#c33">OOS</b> &middot; <b>'+escapeHtml(o.description||o.sku)+'</b></div>'
              + '<div style="color:#789">'+escapeHtml(o.sku||'')+' &middot; '+escapeHtml(o.category||'')+' &middot; Rank #'+(o.rank||'?')+'</div>'
              + (o.remarks ? '<div style="color:#456;font-style:italic;margin-top:2px">"'+escapeHtml(o.remarks)+'"</div>' : '')
            + '</div>'
          + '</label>';
        }).join('')
        + '</div>';
    }
    expandSection = toggleBtn + oosHtml;
  }
  const btn = (!x.reviewed && x.skuSubmitted)
    ? '<button data-review-store="'+escapeHtml(x.store)+'" data-review-slot="'+x.slot+'" '+(allConfirmed?'':'disabled')+' style="margin-top:8px;width:100%;background:'+(allConfirmed?DARK:'#aaa')+';color:#fff;border:0;padding:10px;border-radius:6px;font-weight:700;cursor:'+(allConfirmed?'pointer':'not-allowed')+'">'+(oosList.length?'Validate ('+confirmed.size+'/'+oosList.length+' confirmed)':'Validate (no OOS)')+'</button>'
      + (!allConfirmed ? '<div style="font-size:10px;color:#c33;margin-top:4px;text-align:center">Confirm every OOS SKU before validating</div>' : '')
    : '';
  return '<div style="border:1px solid #ddd;border-left:4px solid '+borderColor+';background:'+bgTint+';border-radius:6px;padding:10px">'
    + '<div style="display:flex;align-items:center;gap:6px"><b style="font-size:13px;color:#223;flex:1">'+escapeHtml(x.store)+'</b>'+statusBadge+'</div>'
    + '<div style="font-size:11px;color:#789;margin-top:2px">'+escapeHtml(x.area||'')+'</div>'
    + skuStat + reviewInfo + expandSection + btn
    + '</div>';
}

function toggleRvExpand(store, slot){
  const k = rvKey(store, slot);
  REVIEW_STATE.expanded[k] = !REVIEW_STATE.expanded[k];
  renderReviewTab();
}
function toggleRvSku(store, slot, sku){
  const k = rvKey(store, slot);
  if (!REVIEW_STATE.confirmed[k]) REVIEW_STATE.confirmed[k] = new Set();
  if (REVIEW_STATE.confirmed[k].has(sku)) REVIEW_STATE.confirmed[k].delete(sku);
  else REVIEW_STATE.confirmed[k].add(sku);
  renderReviewTab();
}
function confirmAllRvSkus(store, slot){
  const k = rvKey(store, slot);
  const item = REVIEW_STATE.items.find(x => x.store === store && x.slot === slot);
  if (!item) return;
  REVIEW_STATE.confirmed[k] = new Set((item.oosList||[]).map(o => o.sku));
  renderReviewTab();
}

async function doReview(store, slot){
  const k = rvKey(store, slot);
  const confirmedOOS = [...(REVIEW_STATE.confirmed[k] || new Set())];
  const item = REVIEW_STATE.items.find(x => x.store === store && x.slot === slot);
  const totalOOS = item ? (item.oosList||[]).length : 0;
  const msg = totalOOS
    ? 'Validate ' + slot + ' slot for ' + store + '?\\n\\nYou have confirmed ' + confirmedOOS.length + ' of ' + totalOOS + ' OOS SKUs.\\n\\nThis records your sign-off and cannot be undone.'
    : 'Validate ' + slot + ' slot for ' + store + '? No OOS to confirm.\\n\\nThis records your sign-off and cannot be undone.';
  if (!confirm(msg)) return;
  const r = await api('/api/review-submit', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ manager: S.manager, store, date: todayStr(), slot, confirmedOOS }) });
  if (!r.ok) { alert(r.error || 'Failed'); return; }
  // Clear confirmed state and reload
  delete REVIEW_STATE.confirmed[k];
  delete REVIEW_STATE.expanded[k];
  loadReviewTab();
}

// ---- Focus 5 SKU Checklist (Store Manager only) ----
// Order matches existing Focus 5 Stock Status: Rice, Eggs, Poultry, Meat, Sugar
const SKU_CAT_ORDER = ['RICE','EGGS','POULTRY','MEAT','SUGAR'];
const SKU_CAT_ICONS = { RICE:'&#127834;', EGGS:'&#129370;', POULTRY:'&#128020;', MEAT:'&#129385;', SUGAR:'&#129474;' };
// Normalize sheet sub-dept names into the 5 display categories (PORK/BEEF → MEAT)
const skuGroupOf = (raw) => {
  const u = (raw||'').trim().toUpperCase();
  if (u === 'PORK' || u === 'BEEF') return 'MEAT';
  return u;
};
let SKU_STATE = { items: [], statuses: {}, remarks: {}, expanded: { RICE:true, EGGS:true, POULTRY:true, MEAT:true, SUGAR:true }, histFrom:null, histTo:null, viewDate:null, history:[], currentSlot:null };
function autoSKUSlot(){ const h = new Date().getHours(); return h < 10 ? 'AM' : 'PM'; }

async function loadSKUChecklist(){
  $('#skuChkOut').innerHTML = '<div class="card muted">Loading SKUs...</div>';
  const today = todayStr();
  if (!SKU_STATE.histFrom) SKU_STATE.histFrom = todayStr(-29);
  if (!SKU_STATE.histTo) SKU_STATE.histTo = today;
  if (!SKU_STATE.viewDate) SKU_STATE.viewDate = today;
  if (!SKU_STATE.currentSlot) SKU_STATE.currentSlot = autoSKUSlot();
  const [skuRes, latestRes, histRes] = await Promise.all([
    api('/api/sku-list?storeId=' + encodeURIComponent(S.storeId||'') + '&store=' + encodeURIComponent(S.storeName||'')),
    api('/api/sku-latest?storeMgr=' + encodeURIComponent(S.manager) + '&date=' + SKU_STATE.viewDate + '&slot=' + SKU_STATE.currentSlot),
    api('/api/sku-history?storeMgr=' + encodeURIComponent(S.manager) + '&from=' + SKU_STATE.histFrom + '&to=' + SKU_STATE.histTo)
  ]);
  // Backend now returns per-slot entries. Convert to legacy "days" shape (one row per date, aggregating AM+PM) for existing render code.
  const histEntries = (histRes && histRes.entries) || [];
  const byDate = {};
  histEntries.forEach(e => {
    byDate[e.date] = byDate[e.date] || { date: e.date, total:0, available:0, oos:0, timestamp:e.timestamp, onTime:true, slots:{} };
    byDate[e.date].total += e.total;
    byDate[e.date].available += e.available;
    byDate[e.date].oos += e.oos;
    byDate[e.date].slots[e.slot] = e;
    if (!e.onTime) byDate[e.date].onTime = false;
    if (e.timestamp > byDate[e.date].timestamp) byDate[e.date].timestamp = e.timestamp;
  });
  SKU_STATE.history = Object.values(byDate).sort((a,b) => b.date.localeCompare(a.date));
  SKU_STATE.histSlots = histEntries;
  if (!skuRes.ok){ $('#skuChkOut').innerHTML = '<div class="card err">'+escapeHtml(skuRes.error||'Failed to load SKUs')+'</div>'; return; }
  if (!skuRes.items || !skuRes.items.length){
    const d = skuRes.diag || {};
    $('#skuChkOut').innerHTML = '<div class="card"><div style="padding:12px;color:#c33;font-weight:bold">No SKUs found for store "'+escapeHtml(S.storeName||'')+'" (ID: '+escapeHtml(S.storeId||'')+') in Focus5SummarySKU sheet.</div>'
      + (d.idsInSheet ? '<div style="padding:8px 12px;font-size:11px;color:#556;background:#f6f6f6;border-radius:6px;margin:8px 12px"><b>Store IDs in Focus5SummarySKU:</b> '+escapeHtml(d.idsInSheet)+'<br><b>Store Names in Focus5SummarySKU:</b> '+escapeHtml(d.namesInSheet)+'</div>' : '')
      + '<div style="padding:0 12px 12px;font-size:12px;color:#789">Add a row for this store in Focus5SummarySKU, or contact admin.</div></div>';
    return;
  }
  SKU_STATE.items = skuRes.items;
  // Preload previously submitted statuses/remarks for today (if any)
  const prev = {};
  (latestRes.entries || []).forEach(e => { prev[e.sku + '||' + e.category] = { status: e.status, remarks: e.remarks || '' }; });
  SKU_STATE.statuses = {}; SKU_STATE.remarks = {};
  skuRes.items.forEach(it => {
    const k = it.sku + '||' + (it.category||'').trim().toUpperCase(); // key uses ORIGINAL category (PORK stays PORK)
    if (prev[k]) { SKU_STATE.statuses[k] = prev[k].status; SKU_STATE.remarks[k] = prev[k].remarks; }
  });
  renderSKUChecklist(latestRes);
}

function renderSKUChecklist(latestRes){
  const today = todayStr();
  const hasExisting = latestRes && (latestRes.entries || []).length > 0;
  // Group items by DISPLAY category (PORK/BEEF both bucket under MEAT)
  const byCat = {};
  SKU_STATE.items.forEach(it => {
    const c = skuGroupOf(it.category);
    (byCat[c] = byCat[c] || []).push(it);
  });
  // Sort each category: by original sub-category first (so PORK then BEEF stay grouped), then by rank
  Object.values(byCat).forEach(list => list.sort((a,b) => {
    const ca = (a.category||'').toUpperCase(), cb = (b.category||'').toUpperCase();
    if (ca !== cb) return ca.localeCompare(cb);
    return (a.rank||99) - (b.rank||99);
  }));

  // Build sections in requested order (Rice, Eggs, Poultry, Meat, Sugar)
  const sectionsHtml = SKU_CAT_ORDER.map(cat => {
    const items = byCat[cat] || [];
    if (!items.length) return \`<div class="card">
      <div style="font-weight:700;color:#1f7a3a">\${SKU_CAT_ICONS[cat]||''} \${toTitle(cat)}</div>
      <div class="muted" style="margin-top:6px;font-size:12px">No SKUs listed for this category.</div>
    </div>\`;
    const keyFor = (it) => it.sku + '||' + (it.category||'').trim().toUpperCase();
    const avail = items.filter(it => SKU_STATE.statuses[keyFor(it)] === 'Available').length;
    const oos   = items.filter(it => SKU_STATE.statuses[keyFor(it)] === 'OOS').length;
    const unset = items.length - avail - oos;
    const expanded = SKU_STATE.expanded[cat];
    const rowsHtml = expanded ? items.map(it => skuRowHTML(it)).join('') : '';
    return \`<div class="card" style="padding:0;overflow:hidden">
      <div style="padding:12px 14px;background:#eef7ec;border-left:4px solid #1f7a3a;cursor:pointer;display:flex;align-items:center;gap:10px" onclick="toggleSKUCat('\${cat}')">
        <div style="font-size:22px">\${SKU_CAT_ICONS[cat]||''}</div>
        <div style="flex:1">
          <div style="font-weight:700;color:#1f7a3a;font-size:15px">\${toTitle(cat)} <span style="color:#789;font-weight:400;font-size:12px">(\${items.length} SKUs)</span></div>
          <div style="font-size:11px;color:#456;margin-top:2px">
            <span style="color:#1f7a3a;font-weight:600">\${avail} Available</span>
            &nbsp;·&nbsp;
            <span style="color:#c33;font-weight:600">\${oos} OOS</span>
            &nbsp;·&nbsp;
            <span style="color:#a60;font-weight:600">\${unset} not set</span>
          </div>
        </div>
        <div style="color:#1f7a3a;font-size:16px">\${expanded?'&#9660;':'&#9654;'}</div>
      </div>
      \${expanded ? '<div style="padding:4px 14px 10px">'+rowsHtml+'</div>' : ''}
    </div>\`;
  }).join('');

  const totalItems = SKU_STATE.items.length;
  const totalSet = Object.values(SKU_STATE.statuses).filter(v => v==='Available' || v==='OOS').length;
  const totalOOS = Object.values(SKU_STATE.statuses).filter(v => v==='OOS').length;
  const totalAvail = Object.values(SKU_STATE.statuses).filter(v => v==='Available').length;
  const pct = totalItems ? Math.round((totalSet/totalItems)*100) : 0;

  const isToday = (SKU_STATE.viewDate === today);
  // Per-slot lock: only the CURRENT slot is considered locked (not both)
  const todayLocked = isToday && hasExisting;
  // Status per slot (AM / PM) for today — read from history
  const todaySlotRows = (SKU_STATE.histSlots || []).filter(e => e.date === today);
  const slotInfo = (sl) => todaySlotRows.find(e => e.slot === sl);
  const slotBadge = (sl) => {
    const info = slotInfo(sl);
    if (!info) return \`<span style="background:#999;color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">\${sl}: not yet</span>\`;
    const bg = info.onTime ? '#1f7a3a' : '#c33';
    return \`<span style="background:\${bg};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">\${sl}: \${info.onTime?'ON TIME':'LATE'}</span>\`;
  };
  // ---- KPI summary at the very top ----
  const todayRow = (SKU_STATE.history || []).find(d => d.date === today);
  const statusBadge = !todayRow ? '<span style="background:#c33;color:#fff;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700">NOT YET SUBMITTED</span>'
    : todayRow.onTime ? '<span style="background:#1f7a3a;color:#fff;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700">ON TIME</span>'
    : '<span style="background:#c33;color:#fff;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700">LATE</span>';
  const kpi = (icon, num, lbl, bg) => \`<div style="flex:1 1 140px;min-width:0;background:\${bg};color:#fff;padding:14px;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
    <div style="font-size:20px;opacity:.9;line-height:1">\${icon}</div>
    <div style="font-size:26px;font-weight:800;margin-top:6px;line-height:1">\${num}</div>
    <div style="font-size:12px;opacity:.95;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:.4px">\${lbl}</div>
  </div>\`;
  const slotBtn = (sl) => {
    const on = SKU_STATE.currentSlot === sl;
    const info = slotInfo(sl);
    const lockMark = info ? ' &#128274;' : '';
    return \`<button type="button" onclick="setSKUSlot('\${sl}')" style="background:\${on?'#1f7a3a':'#eef'};color:\${on?'#fff':'#223'};border:0;padding:8px 18px;border-radius:8px;font-weight:700;cursor:pointer;font-size:14px">\${sl} slot\${lockMark}</button>\`;
  };
  const kpiRow = \`<div class="card" style="padding:12px">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">
      <h3 style="margin:0;color:#1f7a3a">Focus 5 SKU Checklist</h3>
      <span style="background:#e8f5ec;color:#1f7a3a;font-weight:600;font-size:12px;padding:3px 10px;border-radius:12px;border:1px solid #b7dcc3">\${S.storeName||'(no store)'}</span>
      <span style="background:#eef;color:#334;font-weight:600;font-size:11px;padding:3px 10px;border-radius:12px">\${today}</span>
      \${slotBadge('AM')} \${slotBadge('PM')}
    </div>
    <div style="margin-bottom:10px;padding:8px;background:#f4faf6;border-radius:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <span style="font-size:12px;color:#556;font-weight:600">Rate:</span>
      \${slotBtn('AM')} \${slotBtn('PM')}
      <span class="muted" style="font-size:11px;margin-left:auto">AM deadline 10:00 &middot; PM deadline 15:00 &middot; &#128274; = submitted</span>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      \${kpi('&#128202;', totalItems, 'Total SKUs', '#345')}
      \${kpi('&#9989;',   totalAvail, 'Available today', '#1f7a3a')}
      \${kpi('&#10060;',  totalOOS,   'OOS today', '#c33')}
      \${kpi('&#128221;', (todayRow?todayRow.total:0), 'Submitted', '#345')}
      \${(function(){
        const submittedCount = (todayRow ? todayRow.total : 0);
        const passRate = submittedCount ? Math.round((totalAvail / submittedCount) * 100) : 0;
        const bg = passRate >= 90 ? '#1f7a3a' : passRate >= 70 ? '#e0a020' : '#c33';
        return kpi('&#127919;', passRate + '%', 'Pass Rate', bg);
      })()}
    </div>
  </div>\`;

  // ---- Daily Trend chart ----
  const days = SKU_STATE.history.slice().reverse(); // oldest -> newest
  const maxBar = Math.max(1, ...days.map(d => d.total));
  const barMax = Math.max(1, ...days.map(d => d.oos));
  const trendBars = days.map(d => {
    const h = Math.round((d.oos / Math.max(1, barMax)) * 90) + 4;
    const barBg = d.oos === 0 ? '#1f7a3a' : d.oos < 5 ? '#e0a020' : '#c33';
    const isSel = (d.date === SKU_STATE.viewDate) ? 'outline:2px solid #1f7a3a;outline-offset:1px' : '';
    return \`<div onclick="viewSKUDate('\${d.date}')" title="\${d.date}: \${d.oos} OOS of \${d.total}" style="flex:1;min-width:28px;max-width:60px;display:flex;flex-direction:column;align-items:center;gap:2px;cursor:pointer">
      <div style="font-size:10px;color:#c33;font-weight:700">\${d.oos||''}</div>
      <div style="width:100%;background:#eee;border-radius:3px;overflow:hidden;height:100px;display:flex;align-items:flex-end;\${isSel}">
        <div style="width:100%;height:\${h}px;background:\${barBg}"></div>
      </div>
      <div style="font-size:9px;color:#789;text-align:center;line-height:1.1">\${d.date.slice(5)}</div>
    </div>\`;
  }).join('');
  const trendCard = days.length ? \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:8px">
      <h3 style="margin:0;color:#1f7a3a">Daily OOS Trend</h3>
      <span class="muted" style="font-size:12px">\${SKU_STATE.histFrom} to \${SKU_STATE.histTo} - click a day to view</span>
    </div>
    <div style="display:flex;gap:4px;overflow-x:auto;padding:4px 0">\${trendBars}</div>
  </div>\` : '';

  // ---- History filter + list ----
  const histListRows = SKU_STATE.history.map(d => \`<tr onclick="viewSKUDate('\${d.date}')" style="cursor:pointer\${d.date===SKU_STATE.viewDate?';background:#e8f5ec':''}" onmouseover="this.style.background='#f4faf6'" onmouseout="this.style.background='\${d.date===SKU_STATE.viewDate?'#e8f5ec':''}'">
    <td style="padding:6px 8px;font-weight:600;font-size:12px">\${d.date}\${d.date===today?' <span class="muted">(today)</span>':''}</td>
    <td style="padding:6px 8px;text-align:center">\${d.onTime?'<span class="pill" style="background:#1f7a3a;font-size:10px">ON TIME</span>':'<span class="pill" style="background:#c33;font-size:10px">LATE</span>'}</td>
    <td style="padding:6px 8px;text-align:center;color:#1f7a3a;font-weight:700;font-size:12px">\${d.available}</td>
    <td style="padding:6px 8px;text-align:center;color:#c33;font-weight:700;font-size:12px">\${d.oos}</td>
    <td style="padding:6px 8px;text-align:center;font-size:12px">\${d.total}</td>
    <td style="padding:6px 8px;font-size:11px;color:#789">\${new Date(d.timestamp).toLocaleString()}</td>
  </tr>\`).join('');
  const historyCard = \`<div class="card">
    <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:8px">
      <h3 style="margin:0;color:#1f7a3a">History</h3>
      <span class="muted" style="font-size:12px">pick a date range + click a row to view that day's checklist</span>
    </div>
    <div class="row" style="margin-bottom:10px">
      <div><label>From</label><input id="skuHistFrom" type="date" value="\${SKU_STATE.histFrom}"/></div>
      <div><label>To</label><input id="skuHistTo" type="date" value="\${SKU_STATE.histTo}"/></div>
      <div style="display:flex;align-items:flex-end;gap:6px;flex-wrap:wrap">
        <button id="skuHistApplyBtn">Apply</button>
        <button id="skuViewTodayBtn" class="ghost">View Today</button>
        <button id="skuExportBtn" style="background:#345;color:#fff">&#128228; Export to Excel</button>
      </div>
    </div>
    \${SKU_STATE.history.length ? \`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#eef">
        <th style="padding:6px 8px;text-align:left">Date</th>
        <th style="padding:6px;text-align:center;width:80px">Status</th>
        <th style="padding:6px;text-align:center;width:70px">Available</th>
        <th style="padding:6px;text-align:center;width:60px">OOS</th>
        <th style="padding:6px;text-align:center;width:60px">Total</th>
        <th style="padding:6px 8px;text-align:left">Submitted At</th>
      </tr></thead>
      <tbody>\${histListRows}</tbody></table></div>\` : '<div class="muted" style="padding:10px">No submissions in this range.</div>'}
  </div>\`;

  // ---- Checklist header (date label + view mode indicator) ----
  const checklistHeader = \`<div class="card" style="padding:12px 14px;background:\${todayLocked||!isToday?'#fff8e1':'#f4faf6'};border-left:4px solid \${todayLocked||!isToday?'#e0a020':'#1f7a3a'}">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <b style="color:\${todayLocked||!isToday?'#a06800':'#1f7a3a'}">\${isToday ? (todayLocked ? 'Today '+SKU_STATE.currentSlot+' - '+today+' (submitted - read-only)' : 'Today '+SKU_STATE.currentSlot+' slot - '+today+' (editable)') : 'Viewing '+SKU_STATE.viewDate+' '+SKU_STATE.currentSlot+' (read-only history)'}</b>
      \${!isToday?'<button class="sm ghost" onclick="viewSKUDate(\\''+today+'\\')">Switch to Today</button>':''}
      \${todayLocked ? '<span style="background:#1f7a3a;color:#fff;font-weight:600;font-size:11px;padding:3px 10px;border-radius:12px">&#128274; LOCKED</span>' : ''}
    </div>
    \${isToday && !todayLocked?'<div style="margin-top:8px;font-size:12px;color:#5a4300"><b style="color:#a06800">DEADLINE:</b> Submit before <b>10:00 AM</b> daily. Tap <b>Available</b> or <b>OOS</b> for every SKU. <b>Submission is one-shot - you cannot edit after sending.</b></div>':''}
    <div style="margin-top:8px;padding:8px;background:#fff;border-radius:6px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <div style="flex:1;min-width:140px"><div style="height:10px;background:#eee;border-radius:5px;overflow:hidden"><div style="height:100%;width:\${pct}%;background:#1f7a3a;transition:width .2s"></div></div></div>
        <div style="font-weight:700;color:#1f7a3a;font-size:12px">\${totalSet} of \${totalItems} rated (\${pct}%)</div>
      </div>
    </div>
  </div>\`;

  const submitCard = (isToday && !todayLocked) ? \`<div class="card">
    <button id="skuSubmitBtn" style="font-size:15px;padding:12px 24px">Submit \${SKU_STATE.currentSlot} SKU Checklist</button>
    <div id="skuErr" class="err" style="margin-top:8px">Note: once submitted, you cannot edit this \${SKU_STATE.currentSlot} slot.</div>
  </div>\` : '';

  $('#skuChkOut').innerHTML = kpiRow + trendCard + historyCard + checklistHeader + sectionsHtml + submitCard;
  const sb = $('#skuSubmitBtn'); if (sb) sb.onclick = submitSKUChecklist;
  const ha = $('#skuHistApplyBtn'); if (ha) ha.onclick = () => { SKU_STATE.histFrom = $('#skuHistFrom').value; SKU_STATE.histTo = $('#skuHistTo').value; loadSKUChecklist(); };
  const vt = $('#skuViewTodayBtn'); if (vt) vt.onclick = () => { SKU_STATE.viewDate = todayStr(); loadSKUChecklist(); };

  // If viewing a historical date OR today is already locked, make all status buttons read-only
  if (!isToday || todayLocked) {
    document.querySelectorAll('[data-sku][data-cat][data-val]').forEach(b => { b.onclick = null; b.style.cursor = 'default'; b.style.opacity = '0.9'; });
    document.querySelectorAll('[data-sku-remarks]').forEach(ta => { ta.readOnly = true; ta.style.background = '#fafafa'; });
  }

  const exp = $('#skuExportBtn'); if (exp) exp.onclick = exportSKUHistoryExcel;
}

function viewSKUDate(date){
  SKU_STATE.viewDate = date;
  loadSKUChecklist();
}

function setSKUSlot(slot){
  if (slot !== 'AM' && slot !== 'PM') return;
  SKU_STATE.currentSlot = slot;
  // Clear in-progress inputs when switching slots (per-slot state is independent)
  SKU_STATE.statuses = {}; SKU_STATE.remarks = {};
  loadSKUChecklist();
}

function skuRowHTML(it){
  const origCat = (it.category||'').trim().toUpperCase();
  const k = it.sku + '||' + origCat;
  const st = SKU_STATE.statuses[k];
  const rm = SKU_STATE.remarks[k] || '';
  const btn = (val, bg) => {
    const on = st === val;
    return \`<button type="button" data-sku="\${escapeHtml(it.sku)}" data-cat="\${origCat}" data-val="\${val}" onclick="setSKUStatus(this)" style="flex:1;background:\${on?bg:'#eef'};color:\${on?'#fff':'#334'};border:0;border-radius:6px;padding:8px 4px;font-weight:700;cursor:pointer;font-size:13px">\${val}</button>\`;
  };
  // Show sub-category tag when it differs from the display group (so PORK/BEEF are visible inside Meat section)
  const displayGroup = skuGroupOf(origCat);
  const subTag = (origCat && origCat !== displayGroup) ? \`<span style="background:#eef;color:#334;font-weight:600;font-size:10px;padding:1px 6px;border-radius:3px;margin-left:4px">\${escapeHtml(origCat)}</span>\` : '';
  return \`<div style="padding:10px 0;border-bottom:1px dashed #eee">
    <div style="display:flex;align-items:baseline;gap:8px;margin-bottom:6px">
      <span style="background:#1f7a3a;color:#fff;font-weight:700;font-size:11px;padding:2px 7px;border-radius:4px;min-width:26px;text-align:center">#\${it.rank||'?'}</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:13px;color:#223;line-height:1.3">\${escapeHtml(it.description||it.sku)}\${subTag}</div>
        <div style="font-size:11px;color:#789;margin-top:1px">\${escapeHtml(it.sku||'')} &middot; \${escapeHtml(it.supplier||'')} &middot; \${escapeHtml(it.skuType||'')}</div>
      </div>
    </div>
    <div style="display:flex;gap:6px;margin-bottom:4px">\${btn('Available','#1f7a3a')}\${btn('OOS','#c33')}</div>
    \${st==='OOS' ? \`<textarea data-sku-remarks="\${escapeHtml(it.sku)}" data-cat="\${origCat}" oninput="setSKURemarks(this)" placeholder="Remarks for this OOS SKU (optional)" style="min-height:36px;font-size:12px;margin-top:4px">\${escapeHtml(rm)}</textarea>\` : ''}
  </div>\`;
}

function toTitle(s){ return s.charAt(0) + s.slice(1).toLowerCase(); }

function setSKUStatus(btn){
  const sku = btn.dataset.sku, cat = btn.dataset.cat, val = btn.dataset.val;
  SKU_STATE.statuses[sku + '||' + cat] = val;
  renderSKUChecklist({ entries: [] });
}
function setSKURemarks(ta){
  const sku = ta.dataset.skuRemarks, cat = ta.dataset.cat;
  SKU_STATE.remarks[sku + '||' + cat] = ta.value;
}
function toggleSKUCat(cat){
  SKU_STATE.expanded[cat] = !SKU_STATE.expanded[cat];
  renderSKUChecklist({ entries: [] });
}

async function exportSKUHistoryExcel(){
  const btn = $('#skuExportBtn'); const orig = btn ? btn.textContent : ''; if (btn) { btn.disabled = true; btn.textContent = 'Fetching...'; }
  try {
    const r = await api('/api/sku-history-detail?storeMgr=' + encodeURIComponent(S.manager) + '&from=' + encodeURIComponent(SKU_STATE.histFrom) + '&to=' + encodeURIComponent(SKU_STATE.histTo));
    if (!r.ok) { alert(r.error || 'Export failed'); return; }
    if (!r.entries.length) { alert('No submissions in this date range.'); return; }
    const DARK = '#1f7a3a', DARKER = '#155a2b', LIGHT_BG = '#e8f5ec', LIGHTER = '#f4faf6', OOS_C = '#c33';
    // Summary table from history already in SKU_STATE.history
    const summary = SKU_STATE.history.slice().sort((a,b) => b.date.localeCompare(a.date));
    const sumRows = summary.map(d => \`<tr>
      <td style="border:1px solid #cfd8d3;padding:6px 8px;font-weight:bold">\${escapeHtml(d.date)}</td>
      <td style="border:1px solid #cfd8d3;padding:6px;text-align:center;background:\${d.onTime?DARK:OOS_C};color:#fff;font-weight:bold;font-size:11px">\${d.onTime?'ON TIME':'LATE'}</td>
      <td style="border:1px solid #cfd8d3;padding:6px;text-align:center;color:\${DARK};font-weight:bold">\${d.available}</td>
      <td style="border:1px solid #cfd8d3;padding:6px;text-align:center;color:\${OOS_C};font-weight:bold">\${d.oos}</td>
      <td style="border:1px solid #cfd8d3;padding:6px;text-align:center">\${d.total}</td>
      <td style="border:1px solid #cfd8d3;padding:6px 8px;color:#789;font-size:11px">\${new Date(d.timestamp).toLocaleString()}</td>
    </tr>\`).join('');
    // Detail table - group by date desc then category then rank
    const byDate = {};
    r.entries.forEach(e => { (byDate[e.date] = byDate[e.date] || []).push(e); });
    const dates = Object.keys(byDate).sort((a,b) => b.localeCompare(a));
    const detailRows = [];
    dates.forEach(d => {
      const items = byDate[d].slice().sort((a,b) => (a.category||'').localeCompare(b.category||'') || (a.rank||99) - (b.rank||99));
      items.forEach((e,i) => detailRows.push(\`<tr>
        <td style="border:1px solid #cfd8d3;padding:4px 8px;font-weight:\${i===0?'bold':'normal'}">\${i===0?escapeHtml(d):''}</td>
        <td style="border:1px solid #cfd8d3;padding:4px 8px">\${escapeHtml(e.category||'')}</td>
        <td style="border:1px solid #cfd8d3;padding:4px 8px;text-align:center">#\${e.rank||'?'}</td>
        <td style="border:1px solid #cfd8d3;padding:4px 8px">\${escapeHtml(e.sku||'')}</td>
        <td style="border:1px solid #cfd8d3;padding:4px 8px">\${escapeHtml(e.description||'')}</td>
        <td style="border:1px solid #cfd8d3;padding:4px 8px;text-align:center;background:\${e.status==='OOS'?OOS_C:DARK};color:#fff;font-weight:bold;font-size:11px">\${escapeHtml(e.status||'')}</td>
        <td style="border:1px solid #cfd8d3;padding:4px 8px;font-size:11px">\${escapeHtml(e.remarks||'')}</td>
      </tr>\`));
    });
    const html = \`<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>SKU History</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml></head>
<body style="font-family:Calibri,Arial,sans-serif;padding:0;margin:0">
  <div style="background:\${DARK};color:#fff;padding:14px 20px"><div style="font-size:20px;font-weight:bold">Focus 5 SKU Checklist - History Report</div><div style="font-size:12px;opacity:.9;margin-top:3px">\${escapeHtml(S.storeName||'')} &middot; by \${escapeHtml(S.manager||'')}</div></div>
  <table style="border-collapse:collapse;margin:10px 0 16px;font-size:12px">
    <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Date Range</td><td style="padding:6px 12px">\${SKU_STATE.histFrom} to \${SKU_STATE.histTo}</td></tr>
    <tr><td style="padding:6px 12px;background:\${LIGHT_BG};font-weight:bold;color:\${DARKER}">Generated</td><td style="padding:6px 12px">\${new Date().toLocaleString()}</td></tr>
  </table>
  <div style="background:\${DARK};color:#fff;padding:8px 12px;font-weight:bold;font-size:13px">DAILY SUMMARY</div>
  <table style="border-collapse:collapse;font-size:12px;margin-bottom:18px">
    <thead><tr><th style="background:\${DARK};color:#fff;padding:8px 10px;border:1px solid \${DARKER};text-align:left">Date</th><th style="background:\${DARK};color:#fff;padding:8px 10px;border:1px solid \${DARKER}">Status</th><th style="background:\${DARK};color:#fff;padding:8px 10px;border:1px solid \${DARKER}">Available</th><th style="background:\${DARK};color:#fff;padding:8px 10px;border:1px solid \${DARKER}">OOS</th><th style="background:\${DARK};color:#fff;padding:8px 10px;border:1px solid \${DARKER}">Total</th><th style="background:\${DARK};color:#fff;padding:8px 10px;border:1px solid \${DARKER};text-align:left">Submitted At</th></tr></thead>
    <tbody>\${sumRows}</tbody>
  </table>
  <div style="background:\${DARK};color:#fff;padding:8px 12px;font-weight:bold;font-size:13px">DETAILED SKU-LEVEL ENTRIES</div>
  <table style="border-collapse:collapse;font-size:11px">
    <thead><tr><th style="background:\${DARK};color:#fff;padding:6px 10px;border:1px solid \${DARKER};text-align:left">Date</th><th style="background:\${DARK};color:#fff;padding:6px 10px;border:1px solid \${DARKER};text-align:left">Category</th><th style="background:\${DARK};color:#fff;padding:6px 10px;border:1px solid \${DARKER}">Rank</th><th style="background:\${DARK};color:#fff;padding:6px 10px;border:1px solid \${DARKER};text-align:left">SKU</th><th style="background:\${DARK};color:#fff;padding:6px 10px;border:1px solid \${DARKER};text-align:left">Description</th><th style="background:\${DARK};color:#fff;padding:6px 10px;border:1px solid \${DARKER}">Status</th><th style="background:\${DARK};color:#fff;padding:6px 10px;border:1px solid \${DARKER};text-align:left">Remarks</th></tr></thead>
    <tbody>\${detailRows.join('')}</tbody>
  </table>
</body></html>\`;
    const blob = new Blob(['\\ufeff'+html], {type:'application/vnd.ms-excel'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'SKU_Checklist_' + (S.storeName||'store').replace(/[^a-z0-9]+/gi,'_') + '_' + SKU_STATE.histFrom + '_to_' + SKU_STATE.histTo + '.xls';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('Export failed: ' + (e && e.message || e));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
}

async function submitSKUChecklist(){
  $('#skuErr').textContent = '';
  const entries = SKU_STATE.items.map(it => {
    const origCat = (it.category||'').trim().toUpperCase();
    const k = it.sku + '||' + origCat;
    return {
      category: origCat, // preserve PORK/BEEF/etc. in the saved sheet
      rank: it.rank, sku: it.sku, description: it.description,
      status: SKU_STATE.statuses[k] || '',
      remarks: SKU_STATE.remarks[k] || ''
    };
  });
  const missing = entries.filter(e => !e.status);
  if (missing.length) {
    $('#skuErr').textContent = 'Please rate all SKUs. Missing: ' + missing.length + ' SKU' + (missing.length===1?'':'s') + '. The first few: ' + missing.slice(0,3).map(e => e.sku + ' (' + e.category + ')').join(', ') + (missing.length>3?'...':'');
    return;
  }
  const date = todayStr();
  const nowHr = new Date().getHours();
  const slot = SKU_STATE.currentSlot || (nowHr < 10 ? 'AM' : 'PM');
  const btn = $('#skuSubmitBtn'); btn.disabled = true; const orig = btn.textContent; btn.textContent = 'Submitting...';
  const r = await api('/api/sku-submit', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ storeMgr: S.manager, store: S.storeName, date, slot, entries }) });
  btn.disabled = false; btn.textContent = orig;
  if (!r.ok) { $('#skuErr').textContent = r.error || 'Failed'; return; }
  alert('Focus 5 SKU Checklist submitted - ' + entries.length + ' SKUs recorded');
  loadSKUChecklist();
}

// ---- User Approvals (Regional Manager only) ----
async function loadUserApprovalsTab(){
  const out = $('#usersOut');
  out.innerHTML = '<div class="card muted">Loading accounts...</div>';
  const r = await api('/api/user-accounts?email=' + encodeURIComponent(S.email || '') + '&username=' + encodeURIComponent(S.manager || ''));
  if (!r.ok) { out.innerHTML = '<div class="card err">'+escapeHtml(r.error||'Failed')+'</div>'; return; }
  const pending  = r.accounts.filter(a => a.status === 'Pending');
  const approved = r.accounts.filter(a => a.status === 'Approved');
  const rejected = r.accounts.filter(a => a.status === 'Rejected');
  const storesText = (a) => {
    if (a.level === 'Regional Manager') return '<span class="muted">(all areas)</span>';
    if (!a.assignedStores || !a.assignedStores.length) return '<span style="color:#c33">(none)</span>';
    return a.assignedStores.map(s => '<span style="display:inline-block;background:#eef7ec;color:#1f7a3a;padding:2px 7px;border-radius:10px;font-size:11px;margin:1px">'+escapeHtml(s)+'</span>').join(' ');
  };

  const pendRows = pending.map(a => \`<tr>
    <td style="padding:6px 8px;border:1px solid #eee"><b>\${escapeHtml(a.fullName||'')}</b><div style="font-size:11px;color:#789">\${escapeHtml(a.email||'')}</div></td>
    <td style="padding:6px 8px;border:1px solid #eee;font-weight:600">\${escapeHtml(a.level||'')}</td>
    <td style="padding:6px;border:1px solid #eee">\${storesText(a)}</td>
    <td style="padding:6px;border:1px solid #eee;font-size:11px;color:#789">\${a.submittedAt?new Date(a.submittedAt).toLocaleString():''}</td>
    <td style="padding:6px;border:1px solid #eee;white-space:nowrap">
      <button class="ua-approve" data-email="\${escapeHtml(a.email)}" style="background:#1f7a3a;color:#fff;border:0;padding:6px 10px;border-radius:4px;font-weight:600;cursor:pointer;font-size:11px">Approve</button>
      <button class="ua-reject" data-email="\${escapeHtml(a.email)}" style="background:#c33;color:#fff;border:0;padding:6px 10px;border-radius:4px;font-weight:600;cursor:pointer;font-size:11px;margin-left:4px">Reject</button>
    </td>
  </tr>\`).join('');

  const apprRows = approved.map(a => \`<tr>
    <td style="padding:6px 8px;border:1px solid #eee"><b>\${escapeHtml(a.fullName||'')}</b><div style="font-size:11px;color:#789">\${escapeHtml(a.email||'')}</div></td>
    <td style="padding:6px 8px;border:1px solid #eee">\${escapeHtml(a.level||'')}</td>
    <td style="padding:6px 8px;border:1px solid #eee">\${storesText(a)}</td>
    <td style="padding:6px;border:1px solid #eee;font-size:11px;color:#789">\${a.approvedAt?new Date(a.approvedAt).toLocaleString():''}<br>by \${escapeHtml(a.approvedBy||'')}</td>
    <td style="padding:6px;border:1px solid #eee"><button class="ua-reset" data-email="\${escapeHtml(a.email)}" style="background:#345;color:#fff;border:0;padding:6px 10px;border-radius:4px;font-weight:600;cursor:pointer;font-size:11px">Reset Password</button></td>
  </tr>\`).join('');

  const rejRows = rejected.map(a => \`<tr style="background:#fff5f5">
    <td style="padding:6px 8px;border:1px solid #eee"><b>\${escapeHtml(a.fullName||'')}</b><div style="font-size:11px;color:#789">\${escapeHtml(a.email||'')}</div></td>
    <td style="padding:6px;border:1px solid #eee;font-size:11px;color:#789">\${a.approvedAt?new Date(a.approvedAt).toLocaleString():''}<br>by \${escapeHtml(a.approvedBy||'')}</td>
  </tr>\`).join('');

  out.innerHTML = \`
    <div class="card">
      <h3 style="margin:0;color:#1f7a3a">User Account Approvals</h3>
      <div class="muted" style="font-size:12px;margin-top:4px">Approve new signups and link them to their existing username so historical data stays attached. Only Regional Managers can access.</div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 8px;color:#c33">Pending (\${pending.length})</h3>
      \${pending.length ? '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:#eef"><th style="padding:6px 8px;text-align:left">User</th><th style="padding:6px 8px;text-align:left">Position</th><th style="padding:6px 8px;text-align:left">Assigned Stores</th><th style="padding:6px 8px;text-align:left">Signed up</th><th style="padding:6px;text-align:left">Action</th></tr></thead><tbody>'+pendRows+'</tbody></table></div>' : '<div class="muted">No pending accounts.</div>'}
    </div>

    <div class="card">
      <h3 style="margin:0 0 8px;color:#1f7a3a">Approved (\${approved.length})</h3>
      \${approved.length ? '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:#eef"><th style="padding:6px 8px;text-align:left">User</th><th style="padding:6px 8px;text-align:left">Position</th><th style="padding:6px 8px;text-align:left">Assigned Stores</th><th style="padding:6px 8px;text-align:left">Approved</th><th style="padding:6px;text-align:left">Action</th></tr></thead><tbody>'+apprRows+'</tbody></table></div>' : '<div class="muted">No approved accounts yet.</div>'}
    </div>

    <div class="card">
      <h3 style="margin:0 0 8px;color:#789">Rejected (\${rejected.length})</h3>
      \${rejected.length ? '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:#eef"><th style="padding:6px 8px;text-align:left">User</th><th style="padding:6px 8px;text-align:left">Rejected</th></tr></thead><tbody>'+rejRows+'</tbody></table></div>' : '<div class="muted">No rejected accounts.</div>'}
    </div>
  \`;

  document.querySelectorAll('.ua-approve').forEach(b => b.onclick = async () => {
    const email = b.dataset.email;
    const r = await api('/api/approve-account', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ requesterEmail:S.email, requesterUsername:S.manager, email })});
    if (!r.ok) { alert(r.error||'Failed'); return; }
    loadUserApprovalsTab();
  });
  document.querySelectorAll('.ua-reject').forEach(b => b.onclick = async () => {
    const email = b.dataset.email;
    if (!confirm('Reject '+email+'? They will not be able to log in.')) return;
    const r = await api('/api/reject-account', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ requesterEmail:S.email, requesterUsername:S.manager, email })});
    if (!r.ok) { alert(r.error||'Failed'); return; }
    loadUserApprovalsTab();
  });
  document.querySelectorAll('.ua-reset').forEach(b => b.onclick = async () => {
    const email = b.dataset.email;
    const np = prompt('New password for ' + email + ' (6+ chars):');
    if (!np || np.length < 6) { alert('Need 6+ characters'); return; }
    const r = await api('/api/reset-password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ requesterEmail:S.email, requesterUsername:S.manager, email, newPassword:np })});
    if (!r.ok) { alert(r.error||'Failed'); return; }
    alert('Password reset done. Share the new password with ' + email);
  });
}

// Auto-login if remembered
const remembered = localStorage.getItem('ff5_mgr');
if (remembered) {
  S.manager = remembered;
  S.level = localStorage.getItem('ff5_lvl') || 'Area Manager';
  S.storeId = localStorage.getItem('ff5_sid') || null;
  S.storeName = localStorage.getItem('ff5_sname') || null;
  S.email = localStorage.getItem('ff5_email') || null;
  enterApp();
}
</script>
</body></html>`;

app.get('/', (req, res) => res.type('html').send(HTML));

app.listen(PORT, () => console.log('Fresh Focus 5 Checklist listening on', PORT));
