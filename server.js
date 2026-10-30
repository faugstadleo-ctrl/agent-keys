const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || __dirname;
const AGENTS_FILE = path.join(DATA, 'agents.json');
const LOGS_FILE = path.join(DATA, 'logs.json');
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const SECRET = process.env.SESSION_SECRET || 'agent-keys-secret';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return []; }
}
function writeJson(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); } catch (e) { console.error('save failed', e.message); }
}

let agents = readJson(AGENTS_FILE);
let logs = readJson(LOGS_FILE);

function id() { return crypto.randomBytes(6).toString('hex'); }
function key() { return 'ak_' + crypto.randomBytes(18).toString('hex'); }
function save() { writeJson(AGENTS_FILE, agents); writeJson(LOGS_FILE, logs); }

function sign(value) {
  return value + '.' + crypto.createHmac('sha256', SECRET).update(value).digest('hex');
}
function validSession(cookie) {
  if (!cookie) return false;
  const raw = cookie.split(';').map(s => s.trim()).find(s => s.startsWith('session='));
  if (!raw) return false;
  const token = decodeURIComponent(raw.slice(8));
  const i = token.lastIndexOf('.');
  if (i < 0) return false;
  const value = token.slice(0, i);
  return sign(value) === token && value === ADMIN_USER;
}
function requireLogin(req, res, next) {
  if (validSession(req.headers.cookie)) return next();
  res.status(401).json({ error: 'Login required.' });
}

function actionOf(method) {
  const m = (method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD') return 'read';
  if (m === 'DELETE') return 'delete';
  return 'write';
}
function agentKeyFrom(req) {
  const header = req.get('authorization') || '';
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  return (req.body && req.body.key || '').trim();
}

app.post('/api/login', (req, res) => {
  const user = (req.body.user || '').trim();
  const password = req.body.password || '';
  if (user !== ADMIN_USER || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Wrong user or password.' });
  }
  res.setHeader('Set-Cookie', 'session=' + encodeURIComponent(sign(user)) + '; HttpOnly; Path=/; SameSite=Lax');
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ ok: validSession(req.headers.cookie) });
});

app.get('/api/agents', requireLogin, (req, res) => {
  res.json({
    agents: agents.map(a => ({ id: a.id, name: a.name, owner: a.owner, allowed: a.allowed, created: a.created, killed: !!a.killed, key: a.key.slice(0, 10) + '...' })),
    logs: logs.slice(-100).reverse()
  });
});

app.post('/api/agents', requireLogin, (req, res) => {
  const name = (req.body.name || '').trim();
  const owner = (req.body.owner || '').trim();
  const allowed = Array.isArray(req.body.allowed) ? req.body.allowed : [];
  if (!name || !owner) return res.status(400).json({ error: 'Name and owner are required.' });
  const agent = { id: id(), name, owner, allowed, key: key(), killed: false, created: new Date().toISOString() };
  agents.push(agent);
  logs.push({ at: agent.created, agent: name, action: 'created', result: 'allowed', detail: 'Owner ' + owner + '. Allowed: ' + (allowed.join(', ') || 'nothing') });
  save();
  res.json({ agent });
});

app.post('/api/agents/:id/kill', requireLogin, (req, res) => {
  const agent = agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'No agent.' });
  agent.killed = true;
  logs.push({ at: new Date().toISOString(), agent: agent.name, action: 'killed', result: 'refused', detail: 'Key turned off' });
  save();
  res.json({ ok: true });
});

async function gate(agentKey, method, ghPath, body) {
  const agent = agents.find(a => a.key === agentKey);
  const at = new Date().toISOString();
  if (!agent) {
    logs.push({ at, agent: 'unknown', action: method + ' ' + ghPath, result: 'refused', detail: 'No agent for this key' });
    save();
    return { status: 401, payload: { error: 'Unknown agent key.', result: 'refused' } };
  }
  if (agent.killed) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'refused', detail: 'Key was killed' });
    save();
    return { status: 403, payload: { error: agent.name + ' was killed.', result: 'refused' } };
  }
  const action = actionOf(method);
  if (!agent.allowed.includes(action)) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'refused', detail: 'Not allowed to ' + action });
    save();
    return { status: 403, payload: { error: agent.name + ' is not allowed to ' + action + '.', result: 'refused' } };
  }
  if (!ghPath.startsWith('/')) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'refused', detail: 'Path must start with /' });
    save();
    return { status: 400, payload: { error: 'Path must start with /', result: 'refused' } };
  }
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'allowed', detail: 'Gate allowed it. No GitHub token on the server, so nothing was sent.' });
    save();
    return { status: 200, payload: { result: 'allowed', forwarded: false, detail: 'Gate allowed it. No GitHub token on the server, so nothing was sent.' } };
  }
  const upstream = await fetch('https://api.github.com' + ghPath, {
    method,
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'agent-keys',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json'
    },
    body: method === 'GET' || method === 'HEAD' ? undefined : JSON.stringify(body || {})
  });
  const text = await upstream.text();
  const result = upstream.ok ? 'allowed' : 'sent';
  const detail = upstream.ok ? ('Sent to GitHub. GitHub ' + upstream.status) : ('Gate allowed it. GitHub rejected it (' + upstream.status + ').');
  logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result, detail });
  save();
  return { status: 200, payload: { result, forwarded: true, status: upstream.status, detail, body: text.slice(0, 4000) } };
}

app.post('/api/gate', async (req, res) => {
  try {
    const out = await gate(agentKeyFrom(req), (req.body.method || 'GET').toUpperCase(), (req.body.path || '').trim(), req.body.body);
    res.status(out.status).json(out.payload);
  } catch (err) {
    res.status(502).json({ error: err.message, result: 'sent' });
  }
});

app.post('/api/run-agent', requireLogin, async (req, res) => {
  const agentKey = (req.body.key || '').trim();
  const agent = agents.find(a => a.key === agentKey);
  if (!agent) return res.status(401).json({ error: 'Unknown agent key.' });
  if (agent.killed) return res.status(403).json({ error: 'This agent was killed.' });
  const steps = [
    { method: 'GET', path: '/user' },
    { method: 'GET', path: '/user/repos?per_page=5' },
    { method: 'DELETE', path: '/user' }
  ];
  const results = [];
  for (const step of steps) {
    const out = await gate(agentKey, step.method, step.path);
    results.push({ method: step.method, path: step.path, result: out.payload.result, detail: out.payload.detail || out.payload.error, body: out.payload.body || '' });
  }
  res.json({ agent: agent.name, results });
});

app.listen(PORT, () => console.log('agent-keys on ' + PORT));
