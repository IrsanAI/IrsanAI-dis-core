/**
 * DIS — Robust Script Builder v1.1
 * IrsanAI Stack · github.com/IrsanAI/IrsanAI-dis-core
 * Generates platform-adaptive scripts with fallback chains
 */

import { ENV_TYPES } from './envDetector.js';

const TIMEOUT = 30000;

const FORBIDDEN = [
  /rm\s+-rf\s+\//i,
  /format\s+[c-z]:/i,
  /del\s+\/f\s+\/s\s+\/q\s+\\windows/i,
  /:[(][)][{]:|:&[}];:/,
  /chmod\s+-R\s+777\s+\//i
];

export function validateCommand(cmd) {
  for (const p of FORBIDDEN) {
    if (p.test(cmd)) return { valid:false, error:'Forbidden pattern: '+p };
  }
  return { valid:true };
}

// ── TERMUX SCRIPT ─────────────────────────────────
function buildTermuxScript(threat) {
  const id   = threat.id   || 'unknown';
  const name = threat.name || 'Unknown Threat';
  const sev  = threat.sev  || 'UNKNOWN';
  const cve  = JSON.stringify(threat.cve   || []);
  const fix  = JSON.stringify(threat.fixes || []);

  return [
    '#!/data/data/com.termux/files/usr/bin/bash',
    '# ╔════════════════════════════════════════════════════════════╗',
    '# ║  DIS Scout — ' + name.padEnd(45) + '║',
    '# ║  IrsanAI · Termux · DSGVO-konform · Offline              ║',
    '# ╚════════════════════════════════════════════════════════════╝',
    'set -euo pipefail',
    'trap \'echo "❌ Error at line $LINENO" >&2\' ERR',
    '',
    'TS=$(date +"%Y%m%d_%H%M%S")',
    'OUT="$HOME/dis_' + id + '_$TS.json"',
    '',
    '# ── Dependency Check ─────────────────────────────────────────',
    'command -v python3 &>/dev/null || pkg install -y python 2>/dev/null || {',
    '  echo "❌ Python required" >&2; exit 2',
    '}',
    '',
    'echo "🛡️  DIS Scout: ' + name + '"',
    'echo "    Severity : ' + sev + '"',
    'echo "    Output   : $OUT"',
    'echo ""',
    '',
    '# ── Core System ──────────────────────────────────────────────',
    'MODEL=$(getprop ro.product.model 2>/dev/null||echo N/A)',
    'AND_VER=$(getprop ro.build.version.release 2>/dev/null||echo N/A)',
    'PATCH=$(getprop ro.build.version.security_patch 2>/dev/null||echo N/A)',
    'BUILD=$(getprop ro.build.display.id 2>/dev/null||echo N/A)',
    'WARRANTY=$(getprop ro.boot.warranty_bit 2>/dev/null||echo N/A)',
    'BOOT_ST=$(getprop ro.boot.verifiedbootstate 2>/dev/null||echo N/A)',
    'SELINUX=$(getenforce 2>/dev/null||echo N/A)',
    'KNOX=$(getprop ro.knox.version 2>/dev/null||echo N/A)',
    'SDK=$(getprop ro.build.version.sdk 2>/dev/null||echo N/A)',
    '',
    '# ── Threat-Specific Scan ─────────────────────────────────────',
    'echo "→ Scanning: ' + name + '..."',
    (threat.termux || 'echo "→ Standard system scan..."'),
    '',
    '# ── JSON Report ──────────────────────────────────────────────',
    'python3 << \'PYEOF\'',
    'import json, datetime, os',
    'report = {',
    '  "dis_meta": {',
    '    "version": "1.1",',
    '    "platform": "termux_android",',
    '    "generated_at": datetime.datetime.now().isoformat(),',
    '    "threat_id": "' + id + '",',
    '    "threat_name": "' + name + '",',
    '    "severity": "' + sev + '",',
    '    "llm_instruction": "IrsanAI Security Analyst. Bedrohung: ' + name + '. Antworte auf Deutsch. 1) Aktiv? 2) Risk 0-100. 3) Sofortmassnahmen. 4) Haertung. Referenziere konkrete Werte.",',
    '    "dsgvo": "Nur technische Systemmetadaten. Keine personenbezogenen Daten."',
    '  },',
    '  "system": {',
    '    "model":       os.getenv("MODEL",   "N/A"),',
    '    "android":     os.getenv("AND_VER", "N/A"),',
    '    "sdk":         os.getenv("SDK",     "N/A"),',
    '    "patch":       os.getenv("PATCH",   "N/A"),',
    '    "build":       os.getenv("BUILD",   "N/A"),',
    '    "knox_warranty": os.getenv("WARRANTY","N/A"),',
    '    "verified_boot": os.getenv("BOOT_ST","N/A"),',
    '    "selinux":     os.getenv("SELINUX", "N/A"),',
    '    "knox":        os.getenv("KNOX",    "N/A")',
    '  },',
    '  "known_patterns": ' + cve + ',',
    '  "fix_playbook":   ' + fix,
    '}',
    'out_path = os.getenv("OUT", os.path.expanduser("~/dis_report.json"))',
    'with open(out_path, "w", encoding="utf-8") as f:',
    '  json.dump(report, f, indent=2, ensure_ascii=False)',
    'size_kb = round(os.path.getsize(out_path)/1024, 1)',
    'print(f"")',
    'print(f"╔═══════════════════════════════════════════╗")',
    'print(f"║  ✅  DIS Report erstellt!               ║")',
    'print(f"╠═══════════════════════════════════════════╣")',
    'print(f"║  Datei  : {out_path[-42:]}")',
    'print(f"║  Größe  : {size_kb} KB")',
    'print(f"╠═══════════════════════════════════════════╣")',
    'print(f"║  → cat ~/dis_' + id + '_*.json")',
    'print(f"║  → Inhalt kopieren → Dashboard Analyse")',
    'print(f"╚═══════════════════════════════════════════╝")',
    'PYEOF',
  ].join('\n');
}

// ── WINDOWS POWERSHELL SCRIPT ─────────────────────
function buildWindowsScript(threat) {
  const id   = threat.id   || 'unknown';
  const name = threat.name || 'Unknown Threat';
  const sev  = threat.sev  || 'UNKNOWN';
  const cve  = JSON.stringify(threat.cve   || []);
  const fix  = JSON.stringify(threat.fixes || []);

  return [
    '# ╔════════════════════════════════════════════════════════════╗',
    '# ║  DIS Scout — ' + name.padEnd(45) + '║',
    '# ║  IrsanAI · Windows PowerShell · DSGVO-konform            ║',
    '# ╚════════════════════════════════════════════════════════════╝',
    '# Run: powershell -ExecutionPolicy Bypass -File dis_scout.ps1',
    '',
    '$ErrorActionPreference = "Continue"',
    '$TS  = Get-Date -Format "yyyyMMdd_HHmmss"',
    '$Out = "$env:USERPROFILE\\dis_' + id + '_$TS.json"',
    '',
    'function Write-DIS { param($Msg, $Color="Cyan") Write-Host $Msg -ForegroundColor $Color }',
    'function safe { param($sb) try { & $sb } catch { "N/A" } }',
    '',
    'Write-DIS "🛡️  DIS Scout: ' + name + '" "Cyan"',
    'Write-DIS "    Severity : ' + sev + '" "Yellow"',
    '',
    '# ── System ───────────────────────────────────────────────────',
    'Write-DIS "[1/4] System Info..." "Yellow"',
    '$sys = @{',
    '  os_name      = (Get-WmiObject Win32_OperatingSystem).Caption',
    '  os_version   = (Get-WmiObject Win32_OperatingSystem).Version',
    '  build_number = (Get-WmiObject Win32_OperatingSystem).BuildNumber',
    '  hostname     = $env:COMPUTERNAME',
    '  ram_gb       = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)',
    '  cpu          = (Get-WmiObject Win32_Processor|Select-Object -First 1).Name',
    '}',
    '',
    '# ── Threat-Specific Scan ─────────────────────────────────────',
    'Write-DIS "[2/4] Threat Scan: ' + name + '..." "Yellow"',
    '$r = @{}',
    (threat.powershell || '$r.basic = @{ status = "scan_complete" }'),
    '',
    '# ── Security Baseline ────────────────────────────────────────',
    'Write-DIS "[3/4] Security Baseline..." "Yellow"',
    '$sec = @{',
    '  defender_enabled   = (Get-MpComputerStatus -EA SilentlyContinue).RealTimeProtectionEnabled',
    '  rdp_enabled        = ((Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -EA SilentlyContinue).fDenyTSConnections -eq 0)',
    '  ps_exec_policy     = (Get-ExecutionPolicy).ToString()',
    '  uac_enabled        = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -EA SilentlyContinue).EnableLUA',
    '  adb_tools_present  = [bool](Get-Command adb -EA SilentlyContinue)',
    '}',
    '',
    '# ── Build & Save Report ───────────────────────────────────────',
    'Write-DIS "[4/4] Building Report..." "Yellow"',
    '$report = @{',
    '  dis_meta = @{',
    '    version="1.1"; platform="windows_powershell"',
    '    generated_at=(Get-Date -Format "o")',
    '    threat_id="' + id + '"; threat_name="' + name + '"; severity="' + sev + '"',
    '    llm_instruction="IrsanAI Security Analyst. Windows Threat: ' + name + '. Antworte Deutsch. 1) Aktiv? 2) Risk 0-100. 3) Sofort-Massnahmen. 4) Haertung."',
    '    dsgvo="Nur technische Systemmetadaten. Keine personenbezogenen Daten."',
    '  }',
    '  system   = $sys',
    '  security = $sec',
    '  scan     = $r',
    '  known_patterns = (' + cve + ' | ConvertFrom-Json)',
    '  fix_playbook   = (' + fix + ' | ConvertFrom-Json)',
    '} | ConvertTo-Json -Depth 5',
    '',
    'try {',
    '  $report | Out-File $Out -Encoding UTF8 -Force',
    '  $report | Set-Clipboard',
    '  $kb = [math]::Round((Get-Item $Out).Length/1KB,1)',
    '  Write-DIS "" "White"',
    '  Write-DIS "╔══════════════════════════════════════════╗" "Green"',
    '  Write-DIS "║  ✅  DIS Windows Report erstellt!       ║" "Green"',
    '  Write-DIS "╠══════════════════════════════════════════╣" "Green"',
    '  Write-DIS "║  Datei: $($Out.Split(\"\\\\\")[-1].PadRight(34))║" "Green"',
    '  Write-DIS "║  Größe: $("${kb} KB".PadRight(34))║" "Green"',
    '  Write-DIS "╠══════════════════════════════════════════╣" "Green"',
    '  Write-DIS "║  📋 Report in Zwischenablage kopiert!   ║" "Green"',
    '  Write-DIS "║  → Dashboard öffnen → Analyse Tab       ║" "Green"',
    '  Write-DIS "╚══════════════════════════════════════════╝" "Green"',
    '  explorer.exe /select,"$Out" 2>$null',
    '} catch {',
    '  Write-DIS "❌ Fehler: $($_.Exception.Message)" "Red"',
    '}',
  ].join('\n');
}

// ── LINUX/MACOS SCRIPT ────────────────────────────
function buildLinuxScript(threat) {
  const id   = threat.id   || 'unknown';
  const name = threat.name || 'Unknown Threat';
  const sev  = threat.sev  || 'UNKNOWN';
  const cve  = JSON.stringify(threat.cve   || []);
  const fix  = JSON.stringify(threat.fixes || []);

  return [
    '#!/bin/bash',
    '# DIS Scout — ' + name + ' · Linux/macOS · IrsanAI',
    'set -euo pipefail',
    'TS=$(date +"%Y%m%d_%H%M%S")',
    'OUT="$HOME/dis_' + id + '_$TS.json"',
    '',
    'command -v python3 &>/dev/null || { echo "❌ python3 required" >&2; exit 2; }',
    '',
    'echo "🛡️  DIS Scout: ' + name + ' | ' + sev + '"',
    '',
    (threat.bash || 'echo "→ Running system scan..."'),
    '',
    'python3 << \'PYEOF\'',
    'import json, datetime, os',
    'report = {',
    '  "dis_meta": {',
    '    "version": "1.1", "platform": "linux_bash",',
    '    "generated_at": datetime.datetime.now().isoformat(),',
    '    "threat_id": "' + id + '", "threat_name": "' + name + '", "severity": "' + sev + '",',
    '    "llm_instruction": "IrsanAI Security Analyst. Threat: ' + name + '. Antworte auf Deutsch.",',
    '    "dsgvo": "Nur technische Systemmetadaten."',
    '  },',
    '  "system": { "os": os.uname().sysname, "hostname": os.uname().nodename, "kernel": os.uname().release },',
    '  "known_patterns": ' + cve + ',',
    '  "fix_playbook": ' + fix,
    '}',
    'with open(os.getenv("OUT","~/dis_report.json"), "w") as f:',
    '  json.dump(report, f, indent=2)',
    'print(f"✅ Report: {os.getenv(\'OUT\')}")',
    'PYEOF',
  ].join('\n');
}

// ── MAIN EXPORT ───────────────────────────────────
export function buildRobustScript(threat, env = null) {
  const envType = env?.type || 'termux';

  switch (envType) {
    case ENV_TYPES.WINDOWS_PS:
    case ENV_TYPES.WINDOWS_CMD:
      return buildWindowsScript(threat);
    case ENV_TYPES.LINUX_BASH:
    case ENV_TYPES.MACOS_ZSH:
      return buildLinuxScript(threat);
    case ENV_TYPES.TERMUX:
    default:
      return buildTermuxScript(threat);
  }
}
