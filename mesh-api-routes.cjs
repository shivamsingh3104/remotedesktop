// MeshCentral API Plugin - adds custom REST API routes to MeshCentral's Express app
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const path = require('path');
const fs = require('fs');

try { require('dotenv').config({ path: require('path').join(__dirname, '../../.env') }); } catch (ex) {}

const JWT_SECRET = process.env.JWT_SECRET || 'myamoto-super-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'myamoto-encryption-key-32-char!!';

let mssqlPool = null;
let mssqlUserTable = null;

async function getMSSQLPool() {
  if (mssqlPool) return mssqlPool;
  const config = {
    server: process.env.MSSQL_SERVER,
    port: parseInt(process.env.MSSQL_PORT || '1433'),
    database: process.env.MSSQL_DATABASE || 'remotedesktop',
    user: process.env.MSSQL_USER || 'remotedesktop',
    password: process.env.MSSQL_PASSWORD || '',
    options: { encrypt: false, trustServerCertificate: true },
  };
  if (!config.server) return null;
  try {
    const sql = require('mssql');
    mssqlPool = await sql.connect(config);
    console.log('[API] Connected to MSSQL: ' + config.server + '/' + config.database);
    return mssqlPool;
  } catch (err) {
    console.log('[API] MSSQL connection failed:', err.message);
    return null;
  }
}

async function discoverUserTable(pool) {
  if (mssqlUserTable) return mssqlUserTable;
  try {
    const result = await pool.request().query(`
      SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE COLUMN_NAME IN ('email', 'Email', 'EMAIL')
        AND TABLE_CATALOG = '${process.env.MSSQL_DATABASE || 'remotedesktop'}'
    `);
    const tables = {};
    for (const row of result.recordset) {
      const key = row.TABLE_SCHEMA + '.' + row.TABLE_NAME;
      tables[key] = (tables[key] || 0) + 1;
    }
    const best = Object.entries(tables).sort((a, b) => b[1] - a[1])[0];
    if (best) {
      mssqlUserTable = best[0];
      console.log('[API] Discovered user table: ' + mssqlUserTable);
    }
    return mssqlUserTable;
  } catch (err) {
    console.log('[API] Table discovery failed:', err.message);
    return null;
  }
}

async function findMSSQLUser(identifier) {
  const pool = await getMSSQLPool();
  if (!pool) return null;
  const table = await discoverUserTable(pool);
  if (!table) return null;
  try {
    const [schema, tableName] = table.split('.');
    const sql = require('mssql');
    const isEmail = identifier.includes('@');
    const query = isEmail
      ? 'SELECT * FROM ' + schema + '.' + tableName + ' WHERE email = @val OR Email = @val OR EMAIL = @val'
      : 'SELECT * FROM ' + schema + '.' + tableName + ' WHERE id = @val OR Id = @val OR ID = @val';
    const result = await pool.request().input('val', sql.NVarChar, identifier).query(query);
    const row = result.recordset[0];
    if (!row) return null;
    const pwd = row.password || row.Password || row.PasswordHash || '';
    return {
      id: String(row.id || row.Id || row.ID || row.user_id || ''),
      email: row.email || row.Email || row.EMAIL || '',
      name: row.name || row.Name || row.username || '',
      password: pwd,
      role: row.role || row.Role || 'user',
    };
  } catch (err) {
    console.log('[API] MSSQL query failed:', err.message);
    return null;
  }
}

async function checkPassword(plain, hash) {
  if (!hash) return false;
  if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) {
    return await bcrypt.compare(plain, hash);
  }
  const crypto = require('crypto');
  const sha = crypto.createHash('sha256').update(plain).digest('hex');
  const shaLower = crypto.createHash('sha256').update(plain.toLowerCase()).digest('hex');
  return (plain === hash) || (sha === hash.toLowerCase()) || (shaLower === hash.toLowerCase());
}

function readJSON(file) {
  if (!fs.existsSync(file)) return {};
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

module.exports = async function addApiRoutes(app) {
  // CORS
  app.use(function(req, res, next) {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
  });

  app.use(require('express').json());

  // Login
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      let user = null;
      let source = 'json';
      if (process.env.MSSQL_SERVER) {
        user = await findMSSQLUser(email);
        if (user) source = 'mssql';
      }
      if (!user) {
        const dataDir = path.join(__dirname, 'data');
        const db = readJSON(path.join(dataDir, 'users.json'));
        user = (db.users || []).find(u => u.email === email);
      }
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      if (!(await checkPassword(password, user.password))) {
        console.log('[API] LOGIN FAIL ' + source + ': ' + email);
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
      console.log('[API] LOGIN OK ' + source + ': ' + email);
      res.json({ access_token: token, user: { id: user.id, email: user.email, name: user.name } });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  });

  // Me
  app.post('/api/auth/me', (req, res) => {
    try {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
      const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
      res.json({ user: { id: decoded.id, email: decoded.email, name: decoded.name || '' } });
    } catch {
      res.status(401).json({ message: 'Invalid token' });
    }
  });

  // Logout
  app.post('/api/auth/logout', (req, res) => {
    res.json({ message: 'Logged out' });
  });

  // MeshCentral config
  app.get('/api/meshcentral/config', (req, res) => {
    res.json({ configured: true, server_url: 'https://connect.myamoto.com', bot_username: 'myfrontend', status: 'connected' });
  });

  console.log('[API] Routes added to MeshCentral');
};
