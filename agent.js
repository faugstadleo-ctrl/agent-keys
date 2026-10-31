const key = process.argv[2];
if (!key) {
  console.log('Usage: node agent.js ak_YOUR_KEY');
  process.exit(1);
}

const calls = [
  { method: 'GET', path: '/user' },
  { method: 'GET', path: '/user/repos?per_page=5' },
  { method: 'DELETE', path: '/user' }
];

(async () => {
  for (const call of calls) {
    const res = await fetch('https://flaike.org/api/gate', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + key,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(call)
    });
    const data = await res.json();
    console.log(call.method, call.path, '->', data.result || 'refused', data.detail || data.error || '');
  }
})();
