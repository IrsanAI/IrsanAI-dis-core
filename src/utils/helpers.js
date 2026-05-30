/**
 * DIS — Helper Utilities v1.1
 * IrsanAI Stack · github.com/IrsanAI/IrsanAI-dis-core
 * Logging · Safe JSON · Clipboard · Validation · Error Handling
 */

// ── Logging ──────────────────────────────────────
export const LOG_LEVELS = { DEBUG:0, INFO:1, WARN:2, ERROR:3, NONE:4 };
let currentLevel = LOG_LEVELS.INFO;
export function setLogLevel(level) { currentLevel = level; }
export function log(level, msg, data = null) {
  if (level < currentLevel) return;
  const prefix = { 0:'🔍', 1:'ℹ️', 2:'⚠️', 3:'❌' }[level] || '•';
  const ts = new Date().toISOString().split('T')[1].split('.')[0];
  console.log(`${prefix} [${ts}] DIS: ${msg}`, data || '');
}
export const debug = (m,d) => log(LOG_LEVELS.DEBUG, m, d);
export const info  = (m,d) => log(LOG_LEVELS.INFO,  m, d);
export const warn  = (m,d) => log(LOG_LEVELS.WARN,  m, d);
export const error = (m,d) => log(LOG_LEVELS.ERROR, m, d);

// ── Safe JSON Parse ───────────────────────────────
export function safeJsonParse(str, fallback = null) {
  if (!str || typeof str !== 'string') return fallback;
  // Try 1: Direct
  try { return JSON.parse(str); } catch (_) {}
  // Try 2: Strip markdown code fences
  try {
    const cleaned = str.replace(/```(?:json)?\n?|\n?```/g, '').trim();
    return JSON.parse(cleaned);
  } catch (_) {}
  // Try 3: Extract first {...} block
  try {
    const match = str.match(/\{[\s\S]*\}/);
    if (match) return JSON.parse(match[0]);
  } catch (_) {}
  warn('safeJsonParse: all attempts failed');
  return fallback;
}

// ── Clipboard with Fallback ───────────────────────
export async function safeClipboardWrite(text) {
  // Primary: modern Clipboard API
  if (navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch (e) { warn(`Clipboard API failed: ${e.message}`); }
  }
  // Fallback: execCommand (deprecated but widely supported)
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    info('Copied via execCommand fallback');
    return true;
  } catch (e) {
    error(`All clipboard methods failed: ${e.message}`);
    return false;
  }
}

// ── Debounce / Throttle ───────────────────────────
export function debounce(fn, delay) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}
export function throttle(fn, limit) {
  let inThrottle;
  return (...args) => {
    if (!inThrottle) { fn(...args); inThrottle = true; setTimeout(() => inThrottle = false, limit); }
  };
}

// ── Retry & Timeout ───────────────────────────────
export async function withRetry(fn, { retries = 3, delay = 1000 } = {}) {
  let lastErr;
  for (let i = 1; i <= retries; i++) {
    try { return await fn(i); }
    catch (e) {
      lastErr = e;
      warn(`Attempt ${i}/${retries} failed: ${e.message}`);
      if (i < retries) await new Promise(r => setTimeout(r, delay * i));
    }
  }
  throw new Error(`All ${retries} attempts failed. Last: ${lastErr?.message}`);
}
export function withTimeout(promise, ms = 30000) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`Timeout after ${ms}ms`)), ms))
  ]);
}

// ── Feature Detection ─────────────────────────────
export const features = {
  hasFetch:      () => typeof fetch === 'function',
  isOnline:      () => navigator.onLine !== false,
  hasLocalStorage: () => {
    try { localStorage.setItem('__dis__','1'); localStorage.removeItem('__dis__'); return true; }
    catch { return false; }
  },
  getMemoryInfo: () => performance?.memory
    ? { used: Math.round(performance.memory.usedJSHeapSize/1048576),
        total: Math.round(performance.memory.totalJSHeapSize/1048576),
        limit: Math.round(performance.memory.jsHeapSizeLimit/1048576) }
    : null
};

// ── Validators ────────────────────────────────────
export const validators = {
  nonEmpty:   (val, name='value') => { if (!val?.toString().trim()) throw new Error(`${name} cannot be empty`); return val; },
  isJson:     (str) => { try { JSON.parse(str); return true; } catch { return false; } },
  safeString: (str, max=10000) => typeof str === 'string' ? str.slice(0,max).replace(/[<>]/g,'') : '',
  threatId:   (id) => /^[a-z0-9_]+$/.test(id) ? id : null
};

// ── DisError Class ────────────────────────────────
export class DisError extends Error {
  constructor(message, context = {}) {
    super(message);
    this.name = 'DisError';
    this.timestamp = new Date().toISOString();
    this.context = context;
    this.recoverable = context.recoverable ?? true;
  }
  toJSON() {
    return { name:this.name, message:this.message,
             timestamp:this.timestamp, context:this.context };
  }
}
export function wrapError(fn, context = {}) {
  return async (...args) => {
    try { return await fn(...args); }
    catch (err) {
      const e = err instanceof DisError ? err : new DisError(err.message, { ...context, originalError:err });
      error(e.message, e.toJSON());
      throw e;
    }
  };
}

// ── Markdown Export Builder ───────────────────────
export function buildClaudeExport(threat, rawReport, analysis, termLines, script) {
  const now = new Date().toISOString();
  const sys = rawReport?.system || rawReport?.system_context || {};
  const termOutput  = (termLines || []).map(l => l.t).join('\n');
  const reportJson  = JSON.stringify(rawReport, null, 2);
  const patterns    = (threat?.cve   || []).map(c => '- ' + c).join('\n');
  const fixes       = (threat?.fixes || []).map((f,i) => `${i+1}. ${f}`).join('\n');

  // Build as array then join — avoids ALL template-literal/backtick issues
  const lines = [
    '# DIS — Device Intelligence System',
    '## Export for Claude AI Analysis',
    '> Generated: ' + now,
    '> IrsanAI DIS-Core v1.1 · github.com/IrsanAI/IrsanAI-dis-core',
    '',
    '---',
    '',
    '## Scan Context',
    '',
    '| Field | Value |',
    '|---|---|',
    '| **Tool** | DIS — Device Intelligence System |',
    '| **Threat** | ' + (threat?.icon||'') + ' ' + (threat?.name||'Unknown') + ' |',
    '| **Severity** | ' + (threat?.sev||'UNKNOWN') + ' |',
    '| **Platform** | ' + (threat?.platform||'android') + ' |',
    '| **Device** | ' + (sys.model||'?') + ' |',
    '| **Android** | ' + (sys.android||sys.android_version||'?') + ' |',
    '| **Patch** | ' + (sys.patch||sys.security_patch||'?') + ' |',
    '| **Knox** | ' + (sys.knox_warranty||'?') + ' |',
    '| **SELinux** | ' + (sys.selinux||'?') + ' |',
    '| **Scan Time** | ' + (rawReport?.dis_meta?.generated_at||now) + ' |',
    '',
    '---',
    '',
    '## What the User Did',
    '',
    '1. Opened DIS Dashboard on device (localhost:3001)',
    '2. Selected threat: ' + (threat?.name||'?') + ' [' + (threat?.sev||'?') + ']',
    '3. Generated Scout Script for: ' + (threat?.platform||'android'),
    '4. Executed script in Termux / PowerShell / Bash',
    '5. Collected JSON report and pasted into dashboard',
    '6. Requesting Claude AI deeper analysis',
    '',
    '---',
    '',
    '## Terminal Output (Scout Execution)',
    '',
    '```',
    termOutput || '(no terminal output captured)',
    '```',
    '',
    '---',
    '',
    '## Raw Device Report (JSON)',
    '',
    '```json',
    reportJson,
    '```',
    '',
    '---',
    '',
    '## Known Attack Patterns',
    '',
    patterns || '(none listed)',
    '',
    '---',
    '',
    '## Fix Playbook',
    '',
    fixes || '(none listed)',
    '',
    '---',
    '',
    '## Instructions for Claude',
    '',
    'You are IrsanAI — an autonomous device security analyst.',
    '',
    'Device: ' + (sys.model||'Unknown') + ' | Android ' + (sys.android||sys.android_version||'?'),
    'Threat: ' + (threat?.name||'Security Scan') + ' | Severity: ' + (threat?.sev||'UNKNOWN'),
    '',
    'Analyze the report above and provide in German:',
    '1. Is this threat ACTIVE? (yes/no/unclear) + confidence %',
    '2. Risk Score 0-100',
    '3. Specific findings referencing actual JSON values',
    '4. Immediate actions the user must take NOW',
    '5. Next scout script to run for deeper investigation',
    '6. Long-term hardening recommendations',
  ];

  return lines.join('\n');
}
