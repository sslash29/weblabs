/*
 * Meridian Global Freight - Customer & Operations Portal
 * Lab build. Intentionally contains multiple chained vulnerabilities
 * for authorized security testing practice. See ../SCOPE.md.
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { exec } = require('child_process');

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fetch = require('node-fetch');
const initSqlJs = require('sql.js');

const FLAG1 = 'MERIDIAN{1d0r_5h1pm3nt_3xp0sur3}';
const FLAG2 = 'MERIDIAN{5ql1_un10n_cr3d_h4rv3st}';
const FLAG3 = 'MERIDIAN{cmd_1nj3ct10n_v1a_upl04d}';

const JWT_SECRET = crypto.randomBytes(32).toString('hex');
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// write flag3 to disk so it must be *read via RCE*, not found in source
fs.writeFileSync(path.join(__dirname, 'flag3.txt'), FLAG3 + '\n');

let db;

function md5(s) {
  return crypto.createHash('md5').update(s, 'utf8').digest('hex');
}

async function initDb() {
  const SQL = await initSqlJs();
  db = new SQL.Database();
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      hash_type TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      email TEXT
    );
    CREATE TABLE shipments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      tracking_number TEXT,
      origin TEXT,
      destination TEXT,
      status TEXT,
      notes TEXT
    );
  `);

  const insUser = db.prepare('INSERT INTO users (username, password_hash, hash_type, role, email) VALUES (?,?,?,?,?)');
  insUser.run(['jdoe', bcrypt.hashSync('Passw0rd!', 8), 'bcrypt', 'customer', 'jdoe@customer.example']);
  insUser.run(['aramirez', bcrypt.hashSync('Sunshine22', 8), 'bcrypt', 'customer', 'aramirez@customer.example']);
  // legacy account, never migrated off the old auth system (see internal note on shipment #4)
  insUser.run(['admin', md5('Freight2023!'), 'md5', 'admin', 'ops@meridianfreight.example']);
  insUser.free();

  const insShip = db.prepare('INSERT INTO shipments (user_id, tracking_number, origin, destination, status, notes) VALUES (?,?,?,?,?,?)');
  insShip.run([1, 'MGF-100234', 'Rotterdam, NL', 'Newark, NJ, US', 'In Transit', 'Fragile - handle with care']);
  insShip.run([1, 'MGF-100235', 'Rotterdam, NL', 'Baltimore, MD, US', 'Delivered', 'Signed by receiving dock']);
  insShip.run([2, 'MGF-100501', 'Singapore, SG', 'Long Beach, CA, US', 'In Transit', 'Customer requested delay to Friday']);
  insShip.run([3, 'MGF-INTERNAL-01', 'Ops HQ', 'Ops HQ', 'Internal',
    `Reminder to self: internal ops dashboard is on the service network at http://internal:5000 (not internet facing). ` +
    `Still need to migrate this account off md5 auth. FLAG1=${FLAG1}`]);
  insShip.free();
}

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

function currentUser(req) {
  const token = req.cookies.token;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  if (user.role !== 'admin') return res.status(403).render('message', { title: 'Forbidden', message: 'Admin access required.', user });
  req.user = user;
  next();
}

// ---------- public ----------

app.get('/', (req, res) => {
  res.render('index', { user: currentUser(req) });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null, user: currentUser(req) });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('register', { error: 'Username and password required.', user: null });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ?');
  existing.bind([username]);
  const taken = existing.step();
  existing.free();
  if (taken) {
    return res.render('register', { error: 'That username is already registered.', user: null });
  }
  const hash = bcrypt.hashSync(password, 8);
  const ins = db.prepare('INSERT INTO users (username, password_hash, hash_type, role, email) VALUES (?,?,?,?,?)');
  ins.run([username, hash, 'bcrypt', 'customer', `${username}@customer.example`]);
  ins.free();
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, user: currentUser(req) });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  stmt.bind([username]);
  let user = null;
  if (stmt.step()) user = stmt.getAsObject();
  stmt.free();

  if (!user) return res.render('login', { error: 'Invalid credentials.', user: null });

  let ok = false;
  if (user.hash_type === 'md5') {
    ok = md5(password || '') === user.password_hash;
  } else {
    ok = bcrypt.compareSync(password || '', user.password_hash);
  }
  if (!ok) return res.render('login', { error: 'Invalid credentials.', user: null });

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
  res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// ---------- authenticated customer area ----------

app.get('/dashboard', requireAuth, (req, res) => {
  const stmt = db.prepare('SELECT * FROM shipments WHERE user_id = ?');
  stmt.bind([req.user.id]);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  res.render('dashboard', { user: req.user, shipments: rows });
});

// SQL injection: q is concatenated directly into the query
// (registered before /shipments/:id so "search" isn't swallowed as an id)
app.get('/shipments/search', requireAuth, (req, res) => {
  const q = req.query.q || '';
  let rows = [];
  let error = null;
  try {
    const sql = `SELECT id, tracking_number, origin, destination, status, notes FROM shipments ` +
      `WHERE tracking_number LIKE '%${q}%' OR origin LIKE '%${q}%' OR destination LIKE '%${q}%'`;
    const res_ = db.exec(sql);
    if (res_.length) {
      const cols = res_[0].columns;
      rows = res_[0].values.map(v => Object.fromEntries(cols.map((c, i) => [c, v[i]])));
    }
  } catch (e) {
    error = e.message;
  }
  res.render('search', { user: req.user, q, rows, error });
});

// IDOR: looks up any shipment by id with no ownership check against req.user.id
app.get('/shipments/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).render('message', { title: 'Bad request', message: 'Invalid shipment id.', user: req.user });
  const stmt = db.prepare('SELECT * FROM shipments WHERE id = ?');
  stmt.bind([id]);
  let row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return res.status(404).render('message', { title: 'Not found', message: 'No such shipment.', user: req.user });
  res.render('track', { user: req.user, shipment: row });
});

// ---------- admin area ----------

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  // preserves the caller-supplied filename (minus path separators) - no
  // extension allowlist and no shell-metacharacter sanitization
  filename: (req, file, cb) => cb(null, path.basename(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

function listUploads() {
  try {
    return fs.readdirSync(UPLOAD_DIR);
  } catch (e) {
    return [];
  }
}

app.get('/admin', requireAdmin, (req, res) => {
  res.render('admin', {
    user: req.user,
    flag2: FLAG2,
    files: listUploads(),
    convertOutput: null,
    convertError: null,
    webhookOutput: null,
    webhookError: null
  });
});

app.post('/admin/upload', requireAdmin, upload.single('invoice'), (req, res) => {
  res.redirect('/admin');
});

// Command injection: filename is interpolated into a shell command.
// Wrapping it in double quotes blocks naive ';' chaining but NOT
// command substitution via $(...) or backticks.
app.get('/admin/convert', requireAdmin, (req, res) => {
  const filename = req.query.file || '';
  const cmd = `file "uploads/${filename}" 2>&1`;
  exec(cmd, { cwd: __dirname, timeout: 5000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
    res.render('admin', {
      user: req.user,
      flag2: FLAG2,
      files: listUploads(),
      convertOutput: stdout || null,
      convertError: stderr || (err ? err.message : null),
      webhookOutput: null,
      webhookError: null
    });
  });
});

// SSRF: server-side fetch of an admin-supplied URL, no restriction on
// destination host/IP - can be used to reach services on the internal
// docker network that are not published to the host.
app.post('/admin/webhook-test', requireAdmin, async (req, res) => {
  const url = req.body.url || '';
  let webhookOutput = null;
  let webhookError = null;
  try {
    const r = await fetch(url, { timeout: 5000 });
    webhookOutput = await r.text();
  } catch (e) {
    webhookError = e.message;
  }
  res.render('admin', {
    user: req.user,
    flag2: FLAG2,
    files: listUploads(),
    convertOutput: null,
    convertError: null,
    webhookOutput,
    webhookError
  });
});

app.use((req, res) => {
  res.status(404).render('message', { title: 'Not found', message: 'Page not found.', user: currentUser(req) });
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`meridian-freight-portal listening on :${PORT}`));
}).catch(err => {
  console.error('failed to init db', err);
  process.exit(1);
});
