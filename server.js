const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

async function gh(token, url) {
  const res = await fetch('https://api.github.com' + url, {
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'agent-keys',
      'X-GitHub-Api-Version': '2022-11-28'
    }
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
  if (!res.ok) {
    const msg = (data && data.message) || res.statusText;
    throw new Error(msg + ' (' + res.status + ')');
  }
  return data;
}

function flag(scopes) {
  const wide = ['repo', 'admin:org', 'delete_repo', 'admin:enterprise', 'workflow', 'write:packages'];
  const hit = (scopes || []).filter(s => wide.some(w => s === w || s.startsWith(w)));
  return hit;
}

app.post('/api/keys', async (req, res) => {
  const token = (req.body && req.body.token || '').trim();
  if (!token) return res.status(400).json({ error: 'Token is required.' });
  try {
    const me = await gh(token, '/user');
    let pats = [];
    let patError = null;
    try {
      pats = await gh(token, '/user/personal-access-tokens?per_page=100');
      if (!Array.isArray(pats)) pats = [];
    } catch (e) { patError = e.message; }
    let ssh = [];
    try { ssh = await gh(token, '/user/keys'); } catch (e) { ssh = []; }
    const rows = pats.map(p => {
      const perms = [];
      const rp = p.permissions || {};
      for (const group of Object.keys(rp)) {
        const obj = rp[group] || {};
        for (const k of Object.keys(obj)) {
          if (obj[k] && obj[k] !== 'none') perms.push(group + ':' + k + '=' + obj[k]);
        }
      }
      return {
        kind: 'fine-grained token',
        name: p.name || ('token ' + p.id),
        owner: p.owner && p.owner.login,
        access: p.access_granted_at || p.token_last_eight || '',
        expires: p.token_expires_at || null,
        permissions: perms,
        wide: perms.some(x => /admin|write|contents=write|members=write/.test(x))
      };
    });
    ssh.forEach(k => rows.push({
      kind: 'ssh key',
      name: k.title || ('ssh ' + k.id),
      owner: me.login,
      access: k.key ? k.key.slice(0, 24) + '...' : '',
      expires: null,
      permissions: ['ssh'],
      wide: false
    }));
    res.json({
      user: me.login,
      collected_at: new Date().toISOString(),
      pat_error: patError,
      count: rows.length,
      keys: rows
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log('agent-keys on ' + PORT));
