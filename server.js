// ╔══════════════════════════════════════════════════════════════════╗
// ║  DIS-CORE — Device Intelligence System Server                  ║
// ║  Auto-OS-Detector · WebSocket · LAN-Discovery · IrsanAI        ║
// ╚══════════════════════════════════════════════════════════════════╝
const express = require('express');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const http = require('http');
const os = require('os');
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
  const release = os.release();
  const arch = os.arch();
  const hostname = os.hostname();

  let osType = 'unknown';
  let osLabel = 'Unknown';
  let terminalHint = '';
  let agentScript = '';

  if (platform === 'linux') {
    try {
      const fs = require('fs');
      const isTermux = fs.existsSync('/data/data/com.termux') ||
        (process.env.PREFIX || '').includes('termux') ||
        (process.env.HOME || '').includes('com.termux') ||
        fs.existsSync('/data/data/com.termux/files/usr/bin/termux-info');

      if (isTermux) {
        osType = 'android';
        osLabel = 'Android / Termux';
        terminalHint = 'Termux detected — Scout agents run natively';
        agentScript = 'scripts/android/dis_scout.sh';
      } else {
        osType = 'linux';
        osLabel = 'Linux';
        terminalHint = 'bash scripts/linux/dis_scout.sh';
        agentScript = 'scripts/linux/dis_scout.sh';
      }
    } catch {
      osType = 'linux';
      osLabel = 'Linux';
      terminalHint = 'bash scripts/linux/dis_scout.sh';
      agentScript = 'scripts/linux/dis_scout.sh';
    }
  } else if (platform === 'win32') {
    osType = 'windows';
    osLabel = `Windows ${release}`;
    terminalHint = 'powershell -ExecutionPolicy Bypass -File scripts/windows/dis_scout.ps1';
    agentScript = 'scripts/windows/dis_scout.ps1';
  } else if (platform === 'darwin') {
    osType = 'macos';
    osLabel = `macOS ${release}`;
    terminalHint = 'bash scripts/linux/dis_scout.sh';
    agentScript = 'scripts/linux/dis_scout.sh';
  }

  // ADB check — is a phone connected?
  let adbDevice = null;
  try {
    const adbOut = execSync('adb devices 2>/dev/null', { timeout: 3000, stdio: ['pipe','pipe','pipe'] }).toString();
    const lines = adbOut.split('\n').filter(l => l.includes('\tdevice'));
    if (lines.length > 0) {
      adbDevice = lines[0].split('\t')[0].trim();
    }
  } catch { /* adb not available */ }

  return {
    osType,
    osLabel,
    platform,
    arch,
    hostname,
    release,
    terminalHint,
    agentScript,
    adbDevice,
    adbAvailable: adbDevice !== null,
    cpus: os.cpus().length,
    totalMemGB: (os.totalmem() / 1073741824).toFixed(1),
    freeMemGB: (os.freemem() / 1073741824).toFixed(1),
    uptime: Math.floor(os.uptime() / 3600) + 'h',
    networkInterfaces: Object.keys(os.networkInterfaces()),
    timestamp: new Date().toISOString()
  };
}

// ── CLIENT OS DETECTOR (from User-Agent) ───────────────────────────
function detectClientOS(userAgent) {
  const ua = (userAgent || '').toLowerCase();
  if (ua.includes('android')) {
    const match = ua.match(/android ([\d.]+)/);
    return {
      type: 'android',
      label: `Android${match ? ' ' + match[1] : ''}`,
      icon: '📱',
      color: '#30d158',
      agent: 'termux',
      hint: 'Öffne Termux → Scout-Script ausführen'
    };
  }
  if (ua.includes('iphone') || ua.includes('ipad')) {
    return {
      type: 'ios',
      label: 'iOS / iPadOS',
      icon: '🍎',
      color: '#60b4ff',
      agent: 'shortcuts',
      hint: 'iOS Shortcuts Agent verwenden'
    };
  }
  if (ua.includes('windows')) {
    return {
      type: 'windows',
      label: 'Windows',
      icon: '🪟',
      color: '#0078d4',
      agent: 'powershell',
      hint: 'PowerShell als Admin ausführen'
    };
  }
  if (ua.includes('macintosh') || ua.includes('mac os')) {
    return {
      type: 'macos',
      label: 'macOS',
      icon: '🍎',
      color: '#ff9500',
      agent: 'bash',
      hint: 'Terminal → bash Scout-Script'
    };
  }
  if (ua.includes('linux')) {
    return {
      type: 'linux',
      label: 'Linux',
      icon: '🐧',
      color: '#ff9472',
      agent: 'bash',
      hint: 'Terminal → bash Scout-Script'
    };
  }
  return {
    type: 'unknown',
    label: 'Unknown',
    icon: '❓',
    color: '#888',
    agent: 'generic',
    hint: 'Plattform nicht erkannt'
  };
}

// ── LAN DISCOVERY ──────────────────────────────────────────────────
function getLANInfo() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const [name, nets] of Object.entries(interfaces)) {
    for (const net of nets) {
      if (net.family === 'IPv4' && !net.internal) {
        addresses.push({
          interface: name,
          address: net.address,
          dashboardUrl: `http://${net.address}:3001`
        });
      }
    }
  }
  return addresses;
}

// ── API ROUTES ──────────────────────────────────────────────────────

// Server OS + environment info
app.get('/api/env', (req, res) => {
  const serverOS = detectServerOS();
  const clientOS = detectClientOS(req.headers['user-agent']);
  const lan = getLANInfo();

  res.json({
    server: serverOS,
    client: clientOS,
    lan,
    dashboardReady: true,
    version: '1.0.0',
    stack: 'IrsanAI DIS-Core'
  });
});

// Run a scout script (server-side, Linux/macOS/Termux only)
app.post('/api/scout/run', (req, res) => {
  const { scriptPath } = req.body;
  if (!scriptPath || scriptPath.includes('..')) {
    return res.status(400).json({ error: 'Invalid script path' });
  }
  const fullPath = path.join(__dirname, scriptPath);
  exec(`bash "${fullPath}"`, { timeout: 120000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: err.message, stderr });
    res.json({ output: stdout, success: true });
  });
});

// Ping — alive check
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, ts: Date.now(), hostname: os.hostname() });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// ── WEBSOCKET — Live Terminal Stream ───────────────────────────────
wss.on('connection', (ws, req) => {
  const clientOS = detectClientOS(req.headers['user-agent']);
  console.log(`[DIS] Client connected: ${clientOS.label}`);

  ws.send(JSON.stringify({
    type: 'welcome',
    message: `DIS-Core connected. Client detected: ${clientOS.label}`,
    clientOS,
    serverOS: detectServerOS()
  }));

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'run_command' && msg.command) {
        // Stream command output back
        const proc = exec(msg.command, { timeout: 60000 });
        proc.stdout.on('data', d => ws.send(JSON.stringify({ type: 'stdout', data: d })));
        proc.stderr.on('data', d => ws.send(JSON.stringify({ type: 'stderr', data: d })));
        proc.on('close', code => ws.send(JSON.stringify({ type: 'done', code })));
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', message: e.message }));
    }
  });

  ws.on('close', () => console.log('[DIS] Client disconnected'));
});

// ── START ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  const serverOS = detectServerOS();
  const lan = getLANInfo();

  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  🛡️  DIS-CORE — Device Intelligence System          ║');
  console.log('║  IrsanAI Security Stack v1.0                        ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  Server OS  : ${serverOS.osLabel.padEnd(37)}║`);
  console.log(`║  Port       : ${String(PORT).padEnd(37)}║`);
  console.log(`║  ADB Device : ${(serverOS.adbDevice || 'none detected').padEnd(37)}║`);
  console.log('╠══════════════════════════════════════════════════════╣');
  lan.forEach(l => {
    console.log(`║  📡 Dashboard: ${l.dashboardUrl.padEnd(36)}║`);
  });
  console.log(`║  📡 Local   : http://localhost:${PORT}`.padEnd(54) + '║');
  console.log('╚══════════════════════════════════════════════════════╝\n');
});
