// ╔══════════════════════════════════════════════════════════════════╗
// ║  DIS-CORE — Device Intelligence System Server v1.1             ║
// ║  Auto-OS-Detector · WebSocket · LAN-Discovery · IrsanAI        ║
// ╚══════════════════════════════════════════════════════════════════╝
const express = require('express');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { execSync, exec } = require('child_process');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'dist')));

// ── AUTO OS DETECTOR ────────────────────────────────────────────────
function detectServerOS() {
  const platform = os.platform();
  const release  = os.release();
  const arch     = os.arch();
  const hostname = os.hostname();

  let osType = 'unknown', osLabel = 'Unknown';
  let terminalHint = '', agentScript = '';

  if (platform === 'linux') {
    // ── Termux detection (multiple signals) ──
    const isTermux =
      fs.existsSync('/data/data/com.termux') ||
      fs.existsSync('/data/data/com.termux/files/usr/bin/bash') ||
      (process.env.PREFIX  || '').includes('com.termux') ||
      (process.env.HOME    || '').includes('com.termux') ||
      (process.env.TERMUX_VERSION) ||
      (() => { try { return execSync('uname -a',{timeout:1500}).toString().toLowerCase().includes('android'); } catch { return false; } })();

    if (isTermux) {
      osType      = 'android';
      osLabel     = `Android / Termux (${release})`;
      terminalHint = 'Scout scripts run natively in Termux';
      agentScript  = 'scripts/android/dis_scout.sh';
    } else {
      osType      = 'linux';
      osLabel     = `Linux (${release})`;
      terminalHint = 'bash scripts/linux/dis_scout.sh';
      agentScript  = 'scripts/linux/dis_scout.sh';
    }
  } else if (platform === 'win32') {
    osType      = 'windows';
    osLabel     = `Windows ${release}`;
    terminalHint = 'powershell -ExecutionPolicy Bypass -File scripts/windows/dis_scout.ps1';
    agentScript  = 'scripts/windows/dis_scout.ps1';
  } else if (platform === 'darwin') {
    osType      = 'macos';
    osLabel     = `macOS ${release}`;
    terminalHint = 'bash scripts/linux/dis_scout.sh';
    agentScript  = 'scripts/linux/dis_scout.sh';
  }

  // ── ADB check (optional — suppressed if missing) ──
  let adbDevice = null;
  try {
    const out = execSync('adb devices 2>/dev/null', { timeout: 2500, stdio: ['pipe','pipe','pipe'] }).toString();
    const hit = out.split('\n').find(l => l.includes('\tdevice'));
    if (hit) adbDevice = hit.split('\t')[0].trim();
  } catch { /* adb not installed — that's fine */ }

  return {
    osType, osLabel, platform, arch, hostname, release,
    terminalHint, agentScript,
    adbDevice, adbAvailable: !!adbDevice,
    cpus:        os.cpus().length,
    totalMemGB:  (os.totalmem()  / 1_073_741_824).toFixed(1),
    freeMemGB:   (os.freemem()   / 1_073_741_824).toFixed(1),
    uptime:      Math.floor(os.uptime() / 3600) + 'h',
    networkInterfaces: Object.keys(os.networkInterfaces()),
    timestamp:   new Date().toISOString()
  };
}

// ── CLIENT OS DETECTOR (User-Agent) ────────────────────────────────
function detectClientOS(ua = '') {
  const u = ua.toLowerCase();
  if (u.includes('android')) {
    const m = u.match(/android ([\d.]+)/);
    return { type:'android', label:`Android${m?' '+m[1]:''}`, icon:'📱',
             color:'#30d158', agent:'termux',   hint:'Termux → Scout-Script ausführen' };
  }
  if (u.includes('iphone') || u.includes('ipad'))
    return { type:'ios',     label:'iOS/iPadOS', icon:'🍎',
             color:'#60b4ff', agent:'shortcuts', hint:'iOS Shortcuts Agent' };
  if (u.includes('windows'))
    return { type:'windows', label:'Windows',    icon:'🪟',
             color:'#0078d4', agent:'powershell', hint:'PowerShell als Admin ausführen' };
  if (u.includes('macintosh') || u.includes('mac os'))
    return { type:'macos',   label:'macOS',      icon:'🍎',
             color:'#ff9500', agent:'bash',       hint:'Terminal → bash Scout-Script' };
  if (u.includes('linux'))
    return { type:'linux',   label:'Linux',      icon:'🐧',
             color:'#ff9472', agent:'bash',       hint:'Terminal → bash Scout-Script' };
  return   { type:'unknown', label:'Unknown',    icon:'❓',
             color:'#888',   agent:'generic',    hint:'Plattform nicht erkannt' };
}

// ── LAN DISCOVERY ──────────────────────────────────────────────────
function getLANInfo() {
  const addresses = [];
  for (const [name, nets] of Object.entries(os.networkInterfaces())) {
    for (const net of (nets || [])) {
      if (net.family === 'IPv4' && !net.internal)
        addresses.push({ interface: name, address: net.address,
                         dashboardUrl: `http://${net.address}:3001` });
    }
  }
  return addresses;
}

// ── API ROUTES ──────────────────────────────────────────────────────
app.get('/api/env', (req, res) => {
  res.json({
    server:         detectServerOS(),
    client:         detectClientOS(req.headers['user-agent']),
    lan:            getLANInfo(),
    dashboardReady: true,
    version:        '1.1.0',
    stack:          'IrsanAI DIS-Core'
  });
});

app.get('/api/ping', (req, res) =>
  res.json({ ok: true, ts: Date.now(), hostname: os.hostname() }));

app.post('/api/scout/run', (req, res) => {
  const { scriptPath } = req.body;
  if (!scriptPath || scriptPath.includes('..'))
    return res.status(400).json({ error: 'Invalid path' });
  exec(`bash "${path.join(__dirname, scriptPath)}"`, { timeout: 120_000 },
    (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: err.message, stderr });
      res.json({ output: stdout, success: true });
    });
});

app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, 'dist', 'index.html')));

// ── WEBSOCKET ───────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const client = detectClientOS(req.headers['user-agent']);
  console.log(`[DIS] Client connected: ${client.label}`);

  ws.send(JSON.stringify({
    type: 'welcome',
    message: `DIS-Core v1.1 — Client: ${client.label}`,
    clientOS:  client,
    serverOS:  detectServerOS()
  }));

  ws.on('message', data => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'run_command' && msg.command) {
        const proc = exec(msg.command, { timeout: 60_000 });
        proc.stdout.on('data', d => ws.send(JSON.stringify({ type:'stdout', data:d })));
        proc.stderr.on('data', d => ws.send(JSON.stringify({ type:'stderr', data:d })));
        proc.on('close', code => ws.send(JSON.stringify({ type:'done', code })));
      }
    } catch (e) {
      ws.send(JSON.stringify({ type:'error', message: e.message }));
    }
  });

  ws.on('close', () => console.log('[DIS] Client disconnected'));
});

// ── START ────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  const s   = detectServerOS();
  const lan = getLANInfo();

  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  🛡️  DIS-CORE — Device Intelligence System v1.1    ║');
  console.log('║  IrsanAI Security Stack                             ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  Server OS  : ${s.osLabel.padEnd(37)}║`);
  console.log(`║  Port       : ${String(PORT).padEnd(37)}║`);
  console.log(`║  ADB Device : ${(s.adbDevice || 'none detected').padEnd(37)}║`);
  console.log(`║  CPUs/RAM   : ${(s.cpus+' cores / '+s.totalMemGB+'GB').padEnd(37)}║`);
  console.log('╠══════════════════════════════════════════════════════╣');
  lan.forEach(l =>
    console.log(`║  📡 Dashboard: ${l.dashboardUrl.padEnd(36)}║`));
  console.log(`║  📡 Local   : ${'http://localhost:'+PORT}`.padEnd(54)+'║');
  console.log('╚══════════════════════════════════════════════════════╝\n');
});
