import 'dotenv/config';
import express from 'express';
import http from 'http';
import httpProxy from 'http-proxy';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import CryptoJS from 'crypto-js';
import { spawn } from 'child_process';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

const MSSQL_CONFIG = process.env.MSSQL_SERVER ? {
  server: process.env.MSSQL_SERVER,
  port: parseInt(process.env.MSSQL_PORT || '1433'),
  database: process.env.MSSQL_DATABASE || 'remotedesktop',
  user: process.env.MSSQL_USER || 'remotedesktop',
  password: process.env.MSSQL_PASSWORD || '',
  options: { encrypt: false, trustServerCertificate: true, connectTimeout: 3000, requestTimeout: 5000 },
} : null;

const PORT = process.env.API_PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'myamoto-super-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'myamoto-encryption-key-32-char!!';
const DB_PATH = process.env.DB_PATH || './data/users.json';
const MESHCTRL_PATH = process.env.MESHCTRL_PATH || findMeshctrl();

function findMeshctrl() {
  const paths = [
    './node_modules/meshcentral/meshctrl.js',
    '../node_modules/meshcentral/meshctrl.js',
    '/opt/meshcentral/node_modules/meshcentral/meshctrl.js',
    '/root/meshcentral/node_modules/meshcentral/meshctrl.js',
    '/usr/local/lib/node_modules/meshcentral/meshctrl.js',
  ];
  for (const p of paths) {
    if (existsSync(p)) return p;
  }
  return 'meshctrl.js';
}

function readDB() {
  if (!existsSync(DB_PATH)) return { users: [], servers: [] };
  return JSON.parse(readFileSync(DB_PATH, 'utf8'));
}
function writeDB(db) {
  const dir = DB_PATH.substring(0, DB_PATH.lastIndexOf('/'));
  if (!existsSync(dir)) { import('fs').then(fs => fs.mkdirSync(dir, { recursive: true })); }
  writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

let mssqlPool = null;
let mssqlUserTable = null;
let mssqlFailed = false;

async function getMSSQLPool() {
  if (mssqlPool) return mssqlPool;
  if (mssqlFailed) return null;
  if (!MSSQL_CONFIG) return null;
  try {
    const sql = require('mssql');
    const connectPromise = sql.connect(MSSQL_CONFIG);
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('MSSQL connect timeout')), 3000)
    );
    mssqlPool = await Promise.race([connectPromise, timeoutPromise]);
    console.log('Connected to MSSQL: ' + MSSQL_CONFIG.server + '/' + MSSQL_CONFIG.database);
    return mssqlPool;
  } catch (err) {
    console.log('MSSQL connection failed:', err.message);
    mssqlFailed = true;
    return null;
  }
}

async function discoverMSSQLUserTable(pool) {
  if (mssqlUserTable) return mssqlUserTable;
  try {
    const result = await pool.request().query(`
      SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE COLUMN_NAME IN ('email', 'Email', 'EMAIL')
        AND TABLE_CATALOG = '${MSSQL_CONFIG.database}'
    `);
    const tables = {};
    for (const row of result.recordset) {
      const key = row.TABLE_SCHEMA + '.' + row.TABLE_NAME;
      tables[key] = (tables[key] || 0) + 1;
    }
    const best = Object.entries(tables).sort((a, b) => b[1] - a[1])[0];
    if (best) {
      mssqlUserTable = best[0];
      console.log('Discovered user table: ' + mssqlUserTable);
    }
    return mssqlUserTable;
  } catch (err) {
    console.log('Table discovery failed:', err.message);
    return null;
  }
}

async function findUserInMSSQL(identifier) {
  const pool = await getMSSQLPool();
  if (!pool) return null;
  const table = await discoverMSSQLUserTable(pool);
  if (!table) {
    console.log('MSSQL: no user table found with email column');
    return null;
  }
  try {
    const [schema, tableName] = table.split('.');
    const sql = require('mssql');
    const isEmail = identifier.includes('@');
    const query = isEmail
      ? `SELECT * FROM ${schema}.${tableName} WHERE email = @val OR Email = @val OR EMAIL = @val`
      : `SELECT * FROM ${schema}.${tableName} WHERE id = @val OR Id = @val OR ID = @val`;
    const result = await pool.request()
      .input('val', sql.NVarChar, identifier)
      .query(query);
    const row = result.recordset[0];
    if (!row) {
      console.log('MSSQL: user not found by ' + (isEmail ? 'email' : 'id') + '=' + identifier);
      return null;
    }
    const pwd = row.password || row.Password || row.PasswordHash || row.password_hash || '';
    console.log('MSSQL: found user ' + row.email + ' in ' + table + ', hash starts with ' + (pwd ? pwd.substring(0, 15) : 'empty'));
    return {
      id: String(row.id || row.Id || row.ID || row.user_id || ''),
      email: row.email || row.Email || row.EMAIL || '',
      name: row.name || row.Name || row.username || row.UserName || row.display_name || '',
      password: pwd,
      role: row.role || row.Role || 'user',
    };
  } catch (err) {
    console.log('MSSQL query failed:', err.message);
    return null;
  }
}

function encrypt(text) {
  return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}
function decrypt(encryptedText) {
  const bytes = CryptoJS.AES.decrypt(encryptedText, ENCRYPTION_KEY);
  return bytes.toString(CryptoJS.enc.Utf8);
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    req.userId = decoded.id;
    req.userEmail = decoded.email;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

function runMeshctrl(command, serverUrl, username, password, extraArgs = []) {
  return new Promise((resolve, reject) => {
    const wssUrl = serverUrl.replace(/^https:\/\//, 'wss://').replace(/^http:\/\//, 'ws://');
    const args = [MESHCTRL_PATH, command, '--url', wssUrl, '--loginuser', username, '--loginpass', password, ...extraArgs];
    const child = spawn(process.execPath, args, { timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      if (code !== 0 && !stdout) reject(new Error(stderr || `Exit code ${code}`));
      else resolve(stdout);
    });
  });
}

const MESHCENTRAL_TARGET = process.env.MESHCENTRAL_URL || 'https://connect.myamoto.com';

const TOOLBAR_HTML = `
<div id="myamoto-toolbar">
  <div class="mt-left">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
    <span class="mt-brand">Myamoto Remote</span>
    <span class="mt-sep">|</span>
    <span class="mt-device-name" id="mt-device-name">Remote Desktop</span>
  </div>
  <div class="mt-center">
    <button class="mt-btn" onclick="mtToolAction('fullscreen')" title="Fullscreen"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H5a2 2 0 00-2 2v3m18 0V5a2 2 0 00-2-2h-3m0 18h3a2 2 0 002-2v-3M3 16v3a2 2 0 002 2h3"/></svg></button>
    <button class="mt-btn" onclick="mtToolAction('screenshot')" title="Screenshot"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4"/></svg></button>
    <button class="mt-btn" onclick="mtToolAction('ctrlaltdel')" title="Ctrl+Alt+Del"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg></button>
    <button class="mt-btn" onclick="mtToolAction('clipboard')" title="Clipboard"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg></button>
    <button class="mt-btn" onclick="mtToolAction('files')" title="File Transfer"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M12 18v-6M9 15l3-3 3 3"/></svg></button>
    <button class="mt-btn" onclick="mtToolAction('chat')" title="Chat"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg></button>
    <button class="mt-btn" onclick="mtToolAction('restart')" title="Restart"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg></button>
    <button class="mt-btn" onclick="mtToolAction('shutdown')" title="Shutdown"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64A9 9 0 1120.77 15"/><path d="M12 2v10"/></svg></button>
  </div>
  <div class="mt-right">
    <button class="mt-btn mt-disconnect" onclick="mtToolAction('disconnect')" title="Disconnect"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg> Disconnect</button>
    <span class="mt-status" id="mt-status">Connected</span>
  </div>
</div>
<style>
#myamoto-toolbar{display:flex;align-items:center;height:44px;min-height:44px;background:#161b22;border-bottom:1px solid #30363d;padding:0 12px;gap:8px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;position:fixed;bottom:0;left:0;right:0;z-index:999999;box-sizing:border-box}
#myamoto-toolbar *{box-sizing:border-box}
.mt-left{display:flex;align-items:center;gap:8px;flex-shrink:0}
.mt-brand{font-weight:700;font-size:13px;color:#e6edf3;letter-spacing:-0.3px}
.mt-sep{color:#30363d;font-size:11px}
.mt-device-name{font-size:12px;color:#8b949e;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mt-center{display:flex;align-items:center;gap:2px;flex:1;justify-content:center}
.mt-right{display:flex;align-items:center;gap:8px;flex-shrink:0}
.mt-btn{display:flex;align-items:center;justify-content:center;width:30px;height:30px;border:none;border-radius:6px;background:transparent;color:#8b949e;cursor:pointer;transition:all 0.15s}
.mt-btn:hover{background:#21262d;color:#e6edf3}
.mt-btn svg{flex-shrink:0}
.mt-disconnect{background:#da3633;color:#fff;width:auto;padding:0 12px;gap:4px}
.mt-disconnect:hover{background:#b8251f;color:#fff}
.mt-status{font-size:11px;color:#3fb950;font-weight:600}
</style>
<script>
function mtToolAction(a){switch(a){case'fullscreen':document.documentElement.requestFullscreen?.();break;case'disconnect':window.close();break;case'screenshot':alert('Screenshot captured');break;case'ctrlaltdel':document.dispatchEvent(new KeyboardEvent('keydown',{ctrlKey:true,altKey:true,key:'Delete'}));break;case'clipboard':navigator.clipboard.readText().then(t=>alert('Clipboard: '+t));break;case'files':alert('File transfer coming soon');break;case'chat':alert('Chat coming soon');break;case'restart':if(confirm('Restart this device?'))alert('Restart sent');break;case'shutdown':if(confirm('Shutdown this device?'))alert('Shutdown sent');break}}
window.addEventListener('load',function(){var h=44;['p11','p12','p13','LeftSideToolBar'].forEach(function(id){var el=document.getElementById(id);if(el){var b=parseInt(el.style.bottom);if(!isNaN(b)&&b>=0)el.style.bottom=(b+h)+'px'}})});
</script>
`;

const proxy = httpProxy.createProxyServer({ changeOrigin: true, ws: true, selfHandleResponse: true });

proxy.on('proxyRes', (proxyRes, req, res) => {
  delete proxyRes.headers['x-frame-options'];
  delete proxyRes.headers['X-Frame-Options'];
  delete proxyRes.headers['content-security-policy'];
  delete proxyRes.headers['Content-Security-Policy'];

  const statusCode = proxyRes.statusCode;
  const headers = { ...proxyRes.headers };
  const chunks = [];

  proxyRes.on('data', chunk => chunks.push(chunk));
  proxyRes.on('end', () => {
    const buffer = Buffer.concat(chunks);
    let body = buffer.toString('utf8');
    const contentType = headers['content-type'] || '';
    if (req.url && req.url.includes('/sharing') && contentType.includes('text/html')) {
      body = body.replace(/<body[^>]*>/i, match => match + TOOLBAR_HTML);
      body = body.replace(/top!=self[^;]*top\.location[^;]*;?\s*/gi, '');
      body = body.replace(/<meta[^>]*http-equiv=["']X-Frame-Options["'][^>]*>/gi, '');
      headers['content-length'] = Buffer.byteLength(body);
    }
    res.writeHead(statusCode, headers);
    res.end(body);
  });
});

proxy.on('error', (err, req, res) => {
  if (res && res.writeHead) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Proxy error');
  }
});

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    let user = null;
    let source = 'json';
    const db = readDB();
    user = db.users.find(u => u.email === email);
    if (!user && MSSQL_CONFIG) {
      user = await findUserInMSSQL(email);
      if (user) source = 'mssql';
    }
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    let passwordOk = false;
    if (user.password && (user.password.startsWith('$2a$') || user.password.startsWith('$2b$') || user.password.startsWith('$2y$'))) {
      passwordOk = await bcrypt.compare(password, user.password);
    } else if (user.password) {
      const crypto = await import('crypto');
      const shaHash = crypto.createHash('sha256').update(password).digest('hex');
      const shaLower = crypto.createHash('sha256').update(password.toLowerCase()).digest('hex');
      passwordOk = (password === user.password) || (shaHash === user.password.toLowerCase()) || (shaLower === user.password.toLowerCase()) || (user.password === shaHash);
    }
    if (!passwordOk) {
      console.log('LOGIN FAIL from ' + source + ': ' + email + ' hash=' + (user.password ? user.password.substring(0, 20) + '...' : 'empty'));
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    console.log('LOGIN OK from ' + source + ': ' + email);
    const access_token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ access_token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    console.log('LOGIN ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    let user = null;
    const db = readDB();
    user = db.users.find(u => u.id === req.userId || u.email === req.userEmail);
    if (!user && MSSQL_CONFIG && !mssqlFailed) {
      try {
        user = await Promise.race([
          findUserInMSSQL(req.userId),
          new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000))
        ]);
      } catch (_) { /* MSSQL timeout or error, will use JSON fallback */ }
      if (!user && req.userEmail) {
        try {
          user = await Promise.race([
            findUserInMSSQL(req.userEmail),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000))
          ]);
        } catch (_) { /* MSSQL timeout or error */ }
      }
    }
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role || 'user' } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/logout', (_req, res) => {
  res.json({ message: 'Logged out' });
});

app.get('/api/devices', authMiddleware, async (req, res) => {
  try {
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'MeshCentral not configured. Please configure in Settings.' });
    if (server.status !== 'connected') return res.status(400).json({ message: 'Connection not tested. Go to Settings and test the connection first.' });
    const password = decrypt(server.encrypted_password);
    const output = await runMeshctrl('ListDevices', server.server_url, server.bot_username, password, ['--json']);
    const devices = JSON.parse(output).map(item => ({
      id: item._id || item.id,
      name: item.name,
      os: item.osdesc || item.os || 'Unknown',
      status: item.conn || 0,
      online: item.conn === 1,
      lastOnline: item.lastconnect || item.agct || null,
      createdAt: item.firstconnect || null,
      lastBoot: item.lastbootuptime || null,
      tags: [],
    }));
    res.json(devices);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/meshcentral/config', authMiddleware, (req, res) => {
  try {
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.json({ configured: false });
    res.json({ configured: true, server_url: server.server_url, bot_username: server.bot_username, status: server.status || 'unknown' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/meshcentral/config', authMiddleware, async (req, res) => {
  try {
    const { server_url, bot_username, bot_password } = req.body;
    if (!server_url || !bot_username) return res.status(400).json({ message: 'Server URL and username required' });
    const db = readDB();
    let idx = db.servers.findIndex(s => s.user_id === req.userId);
    const entry = {
      user_id: req.userId,
      server_url: server_url.replace(/\/$/, ''),
      bot_username,
      encrypted_password: bot_password ? encrypt(bot_password) : (idx >= 0 ? db.servers[idx].encrypted_password : ''),
      status: 'configured',
    };
    if (idx >= 0) db.servers[idx] = entry;
    else db.servers.push(entry);
    writeDB(db);
    res.json({ message: 'Configuration saved successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/meshcentral/test', authMiddleware, async (req, res) => {
  try {
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    await runMeshctrl('ServerInfo', server.server_url, server.bot_username, password);
    server.status = 'connected';
    writeDB(db);
    res.json({ success: true, message: 'Connection successful' });
  } catch (err) {
    res.status(500).json({ success: false, message: `Connection failed: ${err.message}` });
  }
});

app.get('/api/meshcentral/download-link', authMiddleware, async (req, res) => {
  try {
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    const groupsOutput = await runMeshctrl('ListDeviceGroups', server.server_url, server.bot_username, password, ['--json']);
    const groups = JSON.parse(groupsOutput);
    const group = groups[0];
    if (!group) return res.status(400).json({ message: 'No device group found' });
    const link = await runMeshctrl('GenerateInviteLink', server.server_url, server.bot_username, password, ['--id', group._id, '--hours', '0']);
    res.json({ download_url: link.trim(), filename: 'MeshCentralAgentInstaller' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/remote/session/:deviceId', authMiddleware, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    const output = await runMeshctrl('DeviceSharing', server.server_url, server.bot_username, password, [
      '--id', deviceId, '--add', `myamoto-${Date.now()}`, '--type', 'desktop', '--duration', '60', '--consent', 'none',
    ]);
    const urlMatch = output.match(/URL: (.+)/);
    if (!urlMatch) return res.status(500).json({ message: 'Failed to create share link' });
    const shareUrl = urlMatch[1].trim();
    const cMatch = shareUrl.match(/[?&]c=([^&]+)/);
    const proxyHost = process.env.PROXY_HOST || `http://localhost:${PORT}`;
    const proxyUrl = cMatch ? `${proxyHost}/sharing?c=${encodeURIComponent(cMatch[1])}` : shareUrl;
    res.json({ url: proxyUrl, share_url: proxyUrl, server_url: server.server_url, device_name: 'Device' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/remote/:deviceId/info', authMiddleware, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    const output = await runMeshctrl('DeviceInfo', server.server_url, server.bot_username, password, ['--id', deviceId, '--json']);
    res.json(JSON.parse(output));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/remote/:deviceId/power', authMiddleware, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { action } = req.body;
    const validActions = ['restart', 'shutdown', 'sleep', 'wake'];
    if (!validActions.includes(action)) return res.status(400).json({ message: 'Invalid action' });
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    const flagMap = { restart: '--reset', shutdown: '--off', sleep: '--sleep', wake: '--wake' };
    await runMeshctrl('DevicePower', server.server_url, server.bot_username, password, ['--id', deviceId, flagMap[action]]);
    res.json({ message: `${action} command sent to device` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/remote/:deviceId/message', authMiddleware, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { message, title } = req.body;
    if (!message) return res.status(400).json({ message: 'Message required' });
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    const args = ['--id', deviceId, '--msg', message, '--timeout', '30000'];
    if (title) args.push('--title', title);
    await runMeshctrl('DeviceMessage', server.server_url, server.bot_username, password, args);
    res.json({ message: 'Message sent to device' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/remote/:deviceId/share', authMiddleware, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { type } = req.body;
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    const output = await runMeshctrl('DeviceSharing', server.server_url, server.bot_username, password, [
      '--id', deviceId, '--add', `myamoto-${Date.now()}`, '--type', type || 'desktop', '--duration', '60', '--consent', 'none',
    ]);
    const urlMatch = output.match(/URL: (.+)/);
    if (!urlMatch) return res.status(500).json({ message: 'Failed to parse sharing URL' });
    const typeLabels = { desktop: 'Full Control', terminal: 'Terminal Only', files: 'File Transfer' };
    res.json({ share_url: urlMatch[1].trim(), type: type || 'desktop', label: typeLabels[type] || type });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/remote/:deviceId/command', authMiddleware, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { command } = req.body;
    if (!command) return res.status(400).json({ message: 'Command required' });
    const db = readDB();
    const server = db.servers.find(s => s.user_id === req.userId);
    if (!server) return res.status(400).json({ message: 'Not configured' });
    const password = decrypt(server.encrypted_password);
    const output = await runMeshctrl('RunCommand', server.server_url, server.bot_username, password, ['--id', deviceId, '--run', command, '--reply']);
    res.json({ output: output.trim() });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/seed', (req, res) => {
  try {
    const db = readDB();
    const exists = db.users.find(u => u.email === 'admin@myamoto.com');
    if (!exists) {
      const id = 'user_' + Date.now();
      db.users.push({ id, email: 'admin@myamoto.com', name: 'Admin', password: bcrypt.hashSync('admin123', 10), role: 'admin' });
      writeDB(db);
      res.json({ message: 'Admin created (admin@myamoto.com / admin123)' });
    } else {
      res.json({ message: 'Admin already exists' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

function ensureDb() {
  if (!existsSync(DB_PATH)) {
    const dir = DB_PATH.substring(0, DB_PATH.lastIndexOf('/'));
    if (!existsSync(dir)) { try { import('fs').then(fs => fs.mkdirSync(dir, { recursive: true })); } catch {} }
    writeDB({ users: [], servers: [] });
    console.log('Created empty database at ' + DB_PATH);
  }
}

const cmd = process.argv[2];
if (cmd === 'seed') {
  ensureDb();
  const db = readDB();
  const exists = db.users.find(u => u.email === 'admin@myamoto.com');
  if (!exists) {
    db.users.push({ id: 'user_' + Date.now(), email: 'admin@myamoto.com', name: 'Admin', password: bcrypt.hashSync('admin123', 10), role: 'admin' });
    writeDB(db);
    console.log('Admin created: admin@myamoto.com / admin123');
  } else {
    console.log('Admin already exists');
  }
} else {
  ensureDb();
  const server = http.createServer((req, res) => {
    if (req.url && req.url.startsWith('/api/')) {
      app(req, res);
    } else {
      proxy.web(req, res, { target: MESHCENTRAL_TARGET });
    }
  });
  server.on('upgrade', (req, socket, head) => {
    proxy.ws(req, socket, head, { target: MESHCENTRAL_TARGET });
  });
  server.listen(PORT, () => {
    console.log(`Myamoto server running on port ${PORT} (API + Proxy -> ${MESHCENTRAL_TARGET})`);
  });
}
