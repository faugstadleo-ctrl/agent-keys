const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || __dirname;
const AGENTS_FILE = path.join(DATA, 'agents.json');
const LOGS_FILE = path.join(DATA, 'logs.json');

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

function actionOf(method) {
  const m = (method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD') return 'read';
  if (m === 'DELETE') return 'delete';
  return 'write';
}

app.get('/api/agents', (req, res) => {
  res.json({
    agents: agents.map(a => ({ id: a.id, name: a.name, owner: a.owner, allowed: a.allowed, created: a.created, key: a.key.slice(0, 10) + '...' })),
    logs: logs.slice(-100).reverse()
  });
});

app.post('/api/agents', (req, res) => {
  const name = (req.body.name || '').trim();
  const owner = (req.body.owner || '').trim();
  const allowed = Array.isArray(req.body.allowed) ? req.body.allowed : [];
  if (!name || !owner) return res.status(400).json({ error: 'Name and owner are required.' });
  const agent = { id: id(), name, owner, allowed, key: key(), created: new Date().toISOString() };
  agents.push(agent);
  logs.push({ at: agent.created, agent: name, action: 'created', result: 'allowed', detail: 'Owner ' + owner + '. Allowed: ' + (allowed.join(', ') || 'nothing') });
  save();
  res.json({ agent });
});

app.post('/api/gate', async (req, res) => {
  const agentKey = (req.body.key || '').trim();
  const method = (req.body.method || 'GET').toUpperCase();
  const ghPath = (req.body.path || '').trim();
  const agent = agents.find(a => a.key === agentKey);
  const at = new Date().toISOString();
  if (!agent) {
    logs.push({ at, agent: 'unknown', action: method + ' ' + ghPath, result: 'refused', detail: 'No agent for this key' });
    save();
    return res.status(401).json({ error: 'Unknown agent key.', result: 'refused' });
  }
  const action = actionOf(method);
  if (!agent.allowed.includes(action)) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'refused', detail: 'Not allowed to ' + action });
    save();
    return res.status(403).json({ error: agent.name + ' is not allowed to ' + action + '.', result: 'refused' });
  }
  if (!ghPath.startsWith('/')) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'refused', detail: 'Path must start with /' });
    save();
    return res.status(400).json({ error: 'Path must start with /', result: 'refused' });
  }
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'allowed', detail: 'Allowed, but no GitHub token is set on the server, so nothing was sent.' });
    save();
    return res.json({ result: 'allowed', forwarded: false, detail: 'Allowed. No GitHub token on the server, so the call was not sent.' });
  }
  try {
    const upstream = await fetch('https://api.github.com' + ghPath, {
      method,
      headers: {
        Authorization: 'Bearer ' + token,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'agent-keys',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json'
      },
      body: method === 'GET' || method === 'HEAD' ? undefined : JSON.stringify(req.body.body || {})
    });
    const text = await upstream.text();
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: upstream.ok ? 'allowed' : 'refused', detail: 'GitHub ' + upstream.status });
    save();
    res.status(upstream.status).json({ result: upstream.ok ? 'allowed' : 'refused', forwarded: true, status: upstream.status, body: text.slice(0, 2000) });
  } catch (err) {
    logs.push({ at, agent: agent.name, action: method + ' ' + ghPath, result: 'refused', detail: err.message });
    save();
    res.status(502).json({ error: err.message, result: 'refused' });
  }
});

app.listen(PORT, () => console.log('agent-keys on ' + PORT));
