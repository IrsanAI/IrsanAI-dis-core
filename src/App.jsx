import { useState, useEffect, useCallback } from "react";

// ╔══════════════════════════════════════════════════════════════════╗
// ║  DIS — Device Intelligence System                              ║
// ║  Auto-OS-Detector · Anti-Surveillance · LLM-Native             ║
// ║  IrsanAI Stack v1.0 · github.com/IrsanAI/dis-core              ║
// ╚══════════════════════════════════════════════════════════════════╝

const SEV = { CRITICAL:"#ff2d55", HIGH:"#ff9500", MEDIUM:"#f7c07e", LOW:"#30d158", SAFE:"#00c7be" };
const SEV_BG = { CRITICAL:"#1a0508", HIGH:"#1a0e00", MEDIUM:"#1a1500", LOW:"#001a08", SAFE:"#001a1a" };
const OS_COLOR = { android:"#30d158", ios:"#60b4ff", windows:"#0078d4", linux:"#ff9472", macos:"#ff9500", unknown:"#888" };

const THREATS = [
  { id:"sim_swap", cat:"surveillance", name:"SIM-Swap Detection", icon:"📵", sev:"CRITICAL", platform:"android",
    desc:"Carrier-Übernahme deiner Nummer → 2FA-Bypass → Account-Takeover in Minuten",
    indicators:["Netz-Verlust ohne Grund","SMS nicht empfangbar","Carrier zeigt fremde SIM","Google meldet Fremd-Login"],
    cve:["SS7-Exploit","SIM-Cloning","IMSI-Takeover"],
    fixes:["2FA auf Authenticator-App umstellen — nie SMS","Carrier-App: SIM-Lock aktivieren","Google: Backup-Phone entfernen","Passkey statt Passwort aktivieren"],
    termux:`SIM_STATE=$(getprop gsm.sim.state 2>/dev/null||echo N/A)
SIM_OP=$(getprop gsm.operator.alpha 2>/dev/null||echo N/A)
SIM_NUMERIC=$(getprop gsm.operator.numeric 2>/dev/null||echo N/A)
NET_TYPE=$(dumpsys telephony.registry 2>/dev/null|grep mNetworkType|head -1||echo N/A)
SVC_STATE=$(dumpsys telephony.registry 2>/dev/null|grep mServiceState|head -1||echo N/A)
DUAL_SIM=$(getprop ro.telephony.sim_slots.count 2>/dev/null||echo N/A)
DATA_ROAMING=$(settings get global data_roaming 2>/dev/null||echo N/A)` },

  { id:"imsi_catcher", cat:"surveillance", name:"IMSI-Catcher / Stingray", icon:"📡", sev:"HIGH", platform:"android",
    desc:"Falsche Basisstation → Standort-Tracking + 2G-Downgrade → Gesprächs-Entschlüsselung",
    indicators:["2G/EDGE-Downgrade trotz 4G-Gebiet","Starkes Signal unbekannter Zelle","Akku-Drain ohne Nutzung","Anrufe mit Echo"],
    cve:["IMSI-Grabber","Stingray","SS7-Cell-Fake"],
    fixes:["VoLTE aktivieren — verhindert 2G-Downgrade","4G/5G Only erzwingen in Entwickleroptionen","Signal-App für Kommunikation","Risikogebiet: Flugmodus"],
    termux:`NET_TYPE=$(dumpsys telephony.registry 2>/dev/null|grep mNetworkType|head -3||echo N/A)
CELL_INFO=$(dumpsys telephony.registry 2>/dev/null|grep mCellInfo|head -5||echo N/A)
IMS_REG=$(dumpsys ims 2>/dev/null|grep -E "isRegistered|regState"|head -3||echo N/A)
VOLTE=$(getprop persist.dbg.volte_avail_ovr 2>/dev/null||echo N/A)
SIGNAL=$(dumpsys telephony.registry 2>/dev/null|grep mSignalStrength|head -1||echo N/A)
MCC=$(getprop gsm.operator.numeric 2>/dev/null|cut -c1-3||echo N/A)` },

  { id:"stalkerware", cat:"surveillance", name:"Stalkerware Deep Scan", icon:"🔬", sev:"CRITICAL", platform:"android",
    desc:"Unsichtbare APK — Mikrofon/GPS/SMS live zum Angreifer. Installiert mit physischem Zugriff.",
    indicators:["Akku-Drain ohne Grund","Datenverbrauch hoch","Gerät warm ohne Nutzung","Fremder kennt private Infos"],
    cve:["FlexiSpy","mSpy","Cerberus-RAT","AndroRAT","AhMyth"],
    fixes:["Device-Admin-Apps prüfen: Einstellungen → Sicherheit","Alle unbekannten Accessibility Services deaktivieren","Factory Reset wenn bestätigt","Knox-aktivierter Neuaufbau"],
    termux:`DEV_ADMINS=$(dumpsys device_policy 2>/dev/null|grep -oP 'com\.[a-zA-Z0-9._]+'|sort -u||echo none)
ACCESSIBILITY=$(settings get secure enabled_accessibility_services 2>/dev/null||echo N/A)
NOTIF_LISTEN=$(settings get secure enabled_notification_listeners 2>/dev/null||echo N/A)
INPUT_METHODS=$(settings get secure enabled_input_methods 2>/dev/null||echo N/A)
WAKELOCKS=$(dumpsys power 2>/dev/null|grep PARTIAL_WAKE_LOCK|grep -oP 'com\.[a-zA-Z0-9._]+'|sort|uniq -c|sort -rn|head -10||echo N/A)
OVERLAY=$(dumpsys window 2>/dev/null|grep TYPE_APPLICATION_OVERLAY|grep -oP 'com\.[a-zA-Z0-9._]+'|sort -u|head -10||echo none)` },

  { id:"phone_clone", cat:"surveillance", name:"Phone Clone / Mirror", icon:"👥", sev:"CRITICAL", platform:"android",
    desc:"Physischer ADB-Zugriff → Backup-Extraktion → identisches Gerät beim Angreifer",
    indicators:["Nachrichten gelesen ohne dein Zutun","Fotos in Cloud die du nicht gemacht hast","Fremdes Gerät in Google/Samsung registriert","ADB war aktiviert"],
    cve:["ADB-Backup-Exploit","Samsung-Cloud-Mirror"],
    fixes:["ADB sofort deaktivieren","Developer Options ausschalten","Google: myaccount.google.com/device-activity prüfen","Samsung: Find My Mobile → Geräte-Liste"],
    termux:`ADB_EN=$(settings get global adb_enabled 2>/dev/null||echo N/A)
ADB_TCP=$(getprop service.adb.tcp.port 2>/dev/null||echo N/A)
USB_CFG=$(getprop sys.usb.config 2>/dev/null||echo N/A)
BACKUP_EN=$(settings get secure backup_enabled 2>/dev/null||echo N/A)
SETUP_DONE=$(settings get secure user_setup_complete 2>/dev/null||echo N/A)
USB_STATE=$(getprop sys.usb.state 2>/dev/null||echo N/A)` },

  { id:"mitm", cat:"surveillance", name:"MITM / Netzwerk-Interception", icon:"🕸️", sev:"HIGH", platform:"android",
    desc:"Evil-Twin WLAN · Root-Zertifikat · DNS-Hijacking · Malicious VPN",
    indicators:["User-Zertifikate installiert","Unbekannte VPN läuft","HTTP-Proxy gesetzt","DNS auf fremde IPs"],
    cve:["Evil-Twin-AP","SSL-Strip","DNS-Hijack","Rogue-CA"],
    fixes:["Alle User-Zertifikate löschen: Einstellungen → Sicherheit","Private DNS: dns.google oder 1.1.1.1","Vertrauenswürdiges VPN (ProtonVPN/Mullvad)","WLAN Auto-Connect deaktivieren"],
    termux:`USER_CERTS=$(ls /data/misc/user/0/cacerts-added/ 2>/dev/null|wc -l||echo 0)
PROXY=$(settings get global global_http_proxy 2>/dev/null||echo N/A)
PRIV_DNS=$(settings get global private_dns_mode 2>/dev/null||echo N/A)
PRIV_DNS_HOST=$(settings get global private_dns_specifier 2>/dev/null||echo N/A)
ALWAYS_VPN=$(settings get secure always_on_vpn_app 2>/dev/null||echo N/A)
CAPTIVE=$(settings get global captive_portal_server 2>/dev/null||echo N/A)` },

  { id:"win_rat", cat:"windows", name:"Windows RAT / Backdoor", icon:"🐀", sev:"CRITICAL", platform:"windows",
    desc:"Remote-Access-Trojaner · versteckte RDP · PowerShell-Backdoor · Scheduled Tasks",
    indicators:["Unbekannte Prozesse mit Netzwerk","RDP offen","PowerShell Unrestricted","Unbekannte Scheduled Tasks"],
    cve:["Cobalt-Strike","QuasarRAT","AsyncRAT","njRAT"],
    fixes:["RDP deaktivieren wenn nicht gebraucht","PS ExecutionPolicy: RemoteSigned setzen","Windows Defender vollständiger Scan","Suspicious Tasks löschen"],
    powershell:`$r = @{}
$r.connections = Get-NetTCPConnection -State Established 2>$null |
  ForEach-Object { $p = Get-Process -Id $_.OwningProcess -EA SilentlyContinue
    [PSCustomObject]@{PID=$_.OwningProcess;Proc=$p.Name;Remote="$($_.RemoteAddress):$($_.RemotePort)"} } |
  Where-Object { $_.Remote -notmatch "^(127|::1|0\.0\.0)" }
$r.tasks = Get-ScheduledTask 2>$null | Where-Object {$_.TaskPath -notmatch "Microsoft"} |
  Select-Object TaskName,State | Select-Object -First 20
$r.ps_policy = Get-ExecutionPolicy -List
$r.rdp = (Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
$r.autorun = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -EA SilentlyContinue
$r | ConvertTo-Json -Depth 4` },

  { id:"win_ransomware", cat:"windows", name:"Ransomware Indicators", icon:"💰", sev:"CRITICAL", platform:"windows",
    desc:"Datei-Verschlüsselung · Shadow-Copy-Deletion · Lateral Movement",
    indicators:["VSS Shadow Copies gelöscht","Massenhaft File-Writes","vssadmin.exe unerwartet","Unbekannte SYSTEM-Dienste"],
    cve:["WannaCry","LockBit","BlackCat","Conti","REvil"],
    fixes:["Sofort Offline: Netzwerk trennen","Shadow Copies sichern","Windows Defender Offline Scan","Backup wiederherstellen"],
    powershell:`$r = @{}
$r.shadow_copies = Get-WmiObject Win32_ShadowCopy 2>$null | Measure-Object | Select-Object Count
$r.defender = Get-MpComputerStatus 2>$null | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
$r.suspicious_services = Get-Service 2>$null | Where-Object {$_.Status -eq "Running"} |
  Where-Object {$_.Name -notmatch "^(W32|wlan|Audio|Dhcp|Dns|Event|Plug|Rpc|Sam|Schedule|SENS|Themes|winmgmt|WSearch|WinDefend)"} |
  Select-Object Name,DisplayName | Select-Object -First 25
$r | ConvertTo-Json -Depth 4` },

  { id:"linux_rootkit", cat:"linux", name:"Linux Rootkit Detection", icon:"🌱", sev:"CRITICAL", platform:"linux",
    desc:"Kernel-Rootkit · LD_PRELOAD-Hijack · Hidden Processes · Cron-Backdoor",
    indicators:["Prozesse in /proc die ps nicht zeigt","Unbekannte Kernel-Module","/etc/ld.so.preload hat Einträge","Unbekannte Cron-Jobs"],
    cve:["Diamorphine","Reptile","Azazel","Necurs"],
    fixes:["rkhunter --check --sk","chkrootkit ausführen","/etc/ld.so.preload leeren","Kernel-Update: apt upgrade"],
    bash:`echo "[1] Kernel Modules"
MODS=$(lsmod 2>/dev/null|grep -vE "^(Module|bridge|xt_|nf_|ip_|veth|overlay|tun|loop|dm_|ext4|btrfs|usb|xhci|pci|drm|e1000|cfg80211|mac80211)"|awk '{print $1}'|tr '\n' ',')
echo "[2] LD_PRELOAD"
LD_PRE=$(cat /etc/ld.so.preload 2>/dev/null||echo empty)
echo "[3] Hidden Processes"
PS_P=$(ps aux 2>/dev/null|awk 'NR>1{print $2}'|sort -n)
PROC_P=$(ls /proc 2>/dev/null|grep '^[0-9]'|sort -n)
HIDDEN=$(comm -13 <(echo "$PS_P") <(echo "$PROC_P")|tr '\n' ',')
echo "[4] SUID outside standard paths"
SUID=$(find / -perm -4000 2>/dev/null|grep -vE "^/(bin|usr/bin|usr/sbin|sbin|usr/lib)"|tr '\n' ',')
echo "[5] Open listeners"
LISTEN=$(ss -tlnp 2>/dev/null|grep -v "127\|::1"|tail -n +2)` },

  { id:"patch_status", cat:"os", name:"Security Patch Status", icon:"📋", sev:"HIGH", platform:"android",
    desc:"Patch-Level vs. aktuelle Samsung/Google CVE-Bulletins — Zero-Day-Risiko",
    indicators:["Patch > 60 Tage = Warnung","Patch > 90 Tage = Kritisch","Bekannte aktiv ausgenutzte CVEs"],
    cve:["Samsung-SVE-Bulletins","Google-Android-Bulletins"],
    fixes:["Einstellungen → Software-Update → Herunterladen","Knox Auto-Update aktivieren","Samsung Members: Sicherheits-Bulletins"],
    termux:`PATCH=$(getprop ro.build.version.security_patch 2>/dev/null||echo N/A)
BUILD=$(getprop ro.build.display.id 2>/dev/null||echo N/A)
KERNEL=$(uname -r 2>/dev/null||echo N/A)
MODEL=$(getprop ro.product.model 2>/dev/null||echo N/A)
SDK=$(getprop ro.build.version.sdk 2>/dev/null||echo N/A)
ONEUI=$(getprop ro.build.version.oneui 2>/dev/null||echo N/A)
BASEBAND=$(getprop gsm.version.baseband 2>/dev/null||echo N/A)
FINGERPRINT=$(getprop ro.build.fingerprint 2>/dev/null||echo N/A)` },

  { id:"knox_integrity", cat:"os", name:"Knox / Boot Integrity", icon:"🔐", sev:"HIGH", platform:"android",
    desc:"Verified Boot · Knox Warranty · SELinux · dm-verity",
    indicators:["warranty_bit=1 Knox dauerhaft void","SELinux Permissive","Verified Boot nicht GREEN","Custom Recovery"],
    cve:["Knox-Bypass","SELinux-Exploit","dm-verity-Bypass"],
    fixes:["warranty_bit=1: Nicht reparierbar — Gerät tauschen für Banking","SELinux Permissive: Stock ROM flashen","Verified Boot: Odin Stock Recovery"],
    termux:`WARRANTY=$(getprop ro.boot.warranty_bit 2>/dev/null||echo N/A)
BOOT_ST=$(getprop ro.boot.verifiedbootstate 2>/dev/null||echo N/A)
SELINUX=$(getenforce 2>/dev/null||echo N/A)
KNOX=$(getprop ro.knox.version 2>/dev/null||echo N/A)
BUILD_TAGS=$(getprop ro.build.tags 2>/dev/null||echo N/A)
BUILD_TYPE=$(getprop ro.build.type 2>/dev/null||echo N/A)
TIMA=$(getprop ro.tima.version 2>/dev/null||echo N/A)` },
];

// ── SCRIPT BUILDER ─────────────────────────────────────────────────
function buildScript(threat, platform) {
  const header = (title) => `#!/data/data/com.termux/files/usr/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  DIS — Device Intelligence System Scout                    ║
# ║  Threat : ${title.padEnd(49)}║
# ║  IrsanAI · DSGVO-konform · Offline                         ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail
TS=$(date +"%Y%m%d_%H%M%S")
OUT="$HOME/dis_${threat.id}_$TS.json"
command -v python3 &>/dev/null || pkg install -y python 2>/dev/null
echo "🛡️ DIS Scout: ${threat.name}"

MODEL=$(getprop ro.product.model 2>/dev/null||echo N/A)
PATCH=$(getprop ro.build.version.security_patch 2>/dev/null||echo N/A)
AND_VER=$(getprop ro.build.version.release 2>/dev/null||echo N/A)
BUILD=$(getprop ro.build.display.id 2>/dev/null||echo N/A)
WARRANTY=$(getprop ro.boot.warranty_bit 2>/dev/null||echo N/A)
SELINUX=$(getenforce 2>/dev/null||echo N/A)

echo "→ Scanning..."
${threat.termux || "echo 'scan...'"}

python3 << PYEOF
import json,datetime
report={
  "dis_meta":{
    "version":"1.0","platform":"android","generated_at":datetime.datetime.now().isoformat(),
    "threat_id":"${threat.id}","threat_name":"${threat.name}","severity":"${threat.sev}",
    "llm_instruction":"IrsanAI Security Analyst. Threat: ${threat.name}. Antworte auf Deutsch. 1) Bedrohung aktiv? 2) Risk-Score 0-100. 3) Sofort-Maßnahmen. 4) Härtung.",
    "dsgvo":"Nur technische Systemmetadaten. Keine personenbezogenen Daten."
  },
  "system":{"model":"$MODEL","android":"$AND_VER","patch":"$PATCH","build":"$BUILD","knox_warranty":"$WARRANTY","selinux":"$SELINUX"},
  "known_patterns":${JSON.stringify(threat.cve)},
  "fix_playbook":${JSON.stringify(threat.fixes)}
}
with open("$OUT","w") as f: json.dump(report,f,indent=2,ensure_ascii=False)
print(f"✅ Report: $OUT")
print(f"   cat $OUT  → ins Dashboard kopieren")
PYEOF`;
  if (platform === "windows") return `# DIS Windows Scout — ${threat.name}\n# ExecutionPolicy Bypass -File dis_scout.ps1\n$TS=Get-Date -Format "yyyyMMdd_HHmmss"\n$Out="$env:USERPROFILE\\dis_${threat.id}_$TS.json"\n${threat.powershell || "# scan"}\n($r|ConvertTo-Json -Depth 5)|Out-File $Out -Encoding UTF8\nGet-Content $Out|Set-Clipboard\nWrite-Host "✅ $Out — in Zwischenablage"`;
  if (platform === "linux") return `#!/bin/bash\n# DIS Linux Scout — ${threat.name}\nTS=$(date +"%Y%m%d_%H%M%S")\nOUT="$HOME/dis_${threat.id}_$TS.json"\n${threat.bash || "echo 'scan...'"}\necho "✅ $OUT"`;
  return header(threat.name);
}

// ── CLAUDE ANALYSIS ────────────────────────────────────────────────
async function analyzeWithClaude(report, threat) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514", max_tokens: 1000,
      messages: [{ role: "user", content:
`IrsanAI Security Analyst. JSON only, no markdown:
{
  "threat_active": true/false,
  "confidence": 0-100,
  "risk_score": 0-100,
  "risk_label": "KRITISCH|HOCH|MITTEL|NIEDRIG|SICHER",
  "summary": "Was wurde gefunden?",
  "active_indicators": ["Indikator"],
  "immediate_actions": ["Sofortmaßnahme — konkret"],
  "hardening": ["Langzeit-Härtung"],
  "auto_fix": ["adb shell ... oder powershell ..."],
  "next_scan": "sofort|24h|7d|30d"
}
Threat: ${threat?.name} | Severity: ${threat?.sev}
Patterns: ${JSON.stringify(threat?.cve||[])}
Report: ${JSON.stringify(report, null, 2)}` }]
    })
  });
  const d = await res.json();
  return JSON.parse((d.content||[]).map(b=>b.text||"").join("").replace(/```json|```/g,"").trim());
}

// ── COMPONENTS ─────────────────────────────────────────────────────
function Blink() {
  const [v,setV]=useState(true);
  useEffect(()=>{const t=setInterval(()=>setV(x=>!x),500);return()=>clearInterval(t);},[]);
  return <span style={{opacity:v?1:0,color:"#00ff9d"}}>█</span>;
}

function Pulse({color}) {
  const [s,setS]=useState(1);
  useEffect(()=>{const t=setInterval(()=>setS(x=>x===1?1.4:1),900);return()=>clearInterval(t);},[]);
  return <div style={{width:8,height:8,borderRadius:"50%",background:color,
    transform:`scale(${s})`,transition:"transform 0.4s ease",
    boxShadow:`0 0 8px ${color}`,flexShrink:0}}/>;
}

function OsDetectBanner({env}) {
  if(!env) return null;
  const c = OS_COLOR[env.client?.type] || "#888";
  const sc = OS_COLOR[env.server?.osType] || "#888";
  return (
    <div style={{background:"#080b12",border:`1px solid ${c}33`,borderRadius:10,
      padding:"14px 18px",marginBottom:20,display:"flex",gap:16,flexWrap:"wrap",alignItems:"center"}}>
      <div style={{display:"flex",alignItems:"center",gap:10}}>
        <Pulse color={c}/>
        <div>
          <div style={{color:"#2a3a4a",fontSize:9,letterSpacing:2}}>CLIENT DETECTED</div>
          <div style={{color:c,fontWeight:700,fontSize:13}}>{env.client?.icon} {env.client?.label}</div>
          <div style={{color:"#2a3a4a",fontSize:10}}>{env.client?.hint}</div>
        </div>
      </div>
      <div style={{width:1,background:"#1a2030",alignSelf:"stretch"}}/>
      <div style={{display:"flex",alignItems:"center",gap:10}}>
        <Pulse color={sc}/>
        <div>
          <div style={{color:"#2a3a4a",fontSize:9,letterSpacing:2}}>SERVER OS</div>
          <div style={{color:sc,fontWeight:700,fontSize:13}}>{env.server?.osLabel}</div>
          <div style={{color:"#2a3a4a",fontSize:10}}>{env.server?.cpus} CPUs · {env.server?.totalMemGB}GB RAM · up {env.server?.uptime}</div>
        </div>
      </div>
      {env.server?.adbAvailable && (
        <>
          <div style={{width:1,background:"#1a2030",alignSelf:"stretch"}}/>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <Pulse color="#30d158"/>
            <div>
              <div style={{color:"#2a3a4a",fontSize:9,letterSpacing:2}}>ADB DEVICE</div>
              <div style={{color:"#30d158",fontWeight:700,fontSize:12}}>{env.server.adbDevice}</div>
              <div style={{color:"#2a3a4a",fontSize:10}}>Phone connected via USB</div>
            </div>
          </div>
        </>
      )}
      {env.lan?.length > 0 && (
        <>
          <div style={{width:1,background:"#1a2030",alignSelf:"stretch"}}/>
          <div>
            <div style={{color:"#2a3a4a",fontSize:9,letterSpacing:2,marginBottom:4}}>LAN ACCESS</div>
            {env.lan.map(l=>(
              <div key={l.address} style={{color:"#60b4ff",fontSize:11,fontFamily:"monospace"}}>{l.dashboardUrl}</div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function ScriptModal({script,threat,onClose}) {
  const [ok,setOk]=useState(false);
  const c = SEV[threat?.sev]||"#00ff9d";
  return (
    <div style={{position:"fixed",inset:0,background:"#000000f0",zIndex:300,
      display:"flex",alignItems:"center",justifyContent:"center",padding:16}}>
      <div style={{background:"#06080f",border:`1px solid ${c}44`,borderRadius:14,
        maxWidth:800,width:"100%",maxHeight:"90vh",display:"flex",flexDirection:"column",
        boxShadow:`0 0 80px ${c}18`}}>
        <div style={{padding:"14px 20px",borderBottom:"1px solid #0f1520",
          display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div>
            <div style={{color:c,fontWeight:700,fontSize:13}}>{threat?.icon} {threat?.name} — Scout Script</div>
            <div style={{color:"#2a3a4a",fontSize:10,marginTop:2}}>Kopieren → Termux/Terminal/PowerShell → Ausführen → JSON zurück</div>
          </div>
          <button onClick={onClose} style={{background:"none",border:"none",color:"#555",cursor:"pointer",fontSize:18}}>✕</button>
        </div>
        <div style={{flex:1,overflow:"auto",padding:"16px 20px"}}>
          <pre style={{color:"#5a8a5a",fontFamily:"'Courier New',monospace",fontSize:10.5,
            lineHeight:1.7,margin:0,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{script}</pre>
        </div>
        <div style={{padding:"12px 20px",borderTop:"1px solid #0f1520",display:"flex",gap:10}}>
          <button onClick={()=>{navigator.clipboard.writeText(script);setOk(true);setTimeout(()=>setOk(false),2200);}}
            style={{flex:1,background:ok?"#00e5a022":"#00ff9d18",border:`1px solid ${ok?"#00e5a0":"#00ff9d"}`,
              color:ok?"#00e5a0":"#00ff9d",borderRadius:7,padding:"11px",cursor:"pointer",
              fontFamily:"monospace",fontWeight:700,fontSize:12}}>
            {ok?"✅ KOPIERT!":"📋 SCRIPT KOPIEREN"}
          </button>
          <button onClick={onClose} style={{background:"#ff2d5518",border:"1px solid #ff2d55",
            color:"#ff2d55",borderRadius:7,padding:"11px 18px",cursor:"pointer",fontFamily:"monospace",fontWeight:700}}>✕</button>
        </div>
      </div>
    </div>
  );
}

function ThreatCard({threat,onScan}) {
  const [exp,setExp]=useState(false);
  const c=SEV[threat.sev]||"#888";
  return (
    <div style={{background:"#080b12",border:`1px solid ${c}22`,borderRadius:10,overflow:"hidden",
      transition:"border-color 0.2s"}}
      onMouseEnter={e=>e.currentTarget.style.borderColor=c+"66"}
      onMouseLeave={e=>e.currentTarget.style.borderColor=c+"22"}>
      <div style={{padding:"14px 16px",cursor:"pointer",display:"flex",gap:12,alignItems:"flex-start"}}
        onClick={()=>setExp(x=>!x)}>
        <span style={{fontSize:20}}>{threat.icon}</span>
        <div style={{flex:1}}>
          <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
            <span style={{color:"#e2e5f0",fontWeight:700,fontSize:13}}>{threat.name}</span>
            <span style={{background:SEV_BG[threat.sev],color:c,border:`1px solid ${c}44`,
              borderRadius:4,padding:"1px 7px",fontSize:9,fontWeight:700,letterSpacing:1}}>{threat.sev}</span>
            <span style={{color:OS_COLOR[threat.platform]||"#888",fontSize:9,fontFamily:"monospace",
              background:"#0d0f1a",border:`1px solid ${OS_COLOR[threat.platform]||"#888"}33`,
              borderRadius:4,padding:"1px 6px"}}>{threat.platform}</span>
          </div>
          <div style={{color:"#2a3a4a",fontSize:11}}>{threat.desc}</div>
        </div>
        <span style={{color:"#2a3a4a",fontSize:11}}>{exp?"▲":"▼"}</span>
      </div>
      {exp&&(
        <div style={{borderTop:`1px solid ${c}22`,padding:"14px 16px"}}>
          <div style={{marginBottom:12}}>
            <div style={{color:"#2a3a4a",fontSize:9,letterSpacing:2,marginBottom:6}}>INDIKATOREN</div>
            {threat.indicators.map((ind,i)=>(
              <div key={i} style={{display:"flex",gap:8,marginBottom:4}}>
                <span style={{color:c,fontSize:10}}>◆</span>
                <span style={{color:"#8a9ab0",fontSize:11}}>{ind}</span>
              </div>
            ))}
          </div>
          <div style={{display:"flex",flexWrap:"wrap",gap:5,marginBottom:14}}>
            {threat.cve.map(p=>(
              <span key={p} style={{background:`${c}18`,color:c,border:`1px solid ${c}33`,
                borderRadius:4,padding:"2px 7px",fontSize:9,fontFamily:"monospace"}}>{p}</span>
            ))}
          </div>
          <button onClick={()=>onScan(threat)}
            style={{width:"100%",background:`${c}18`,border:`1px solid ${c}55`,color:c,
              borderRadius:7,padding:"10px",cursor:"pointer",fontFamily:"monospace",fontWeight:700,
              fontSize:12,letterSpacing:1}}>
            🔬 SCAN STARTEN →
          </button>
        </div>
      )}
    </div>
  );
}


// ── EXPORT FOR CLAUDE ──────────────────────────────────────────────
function buildClaudeExport(threat, rawReport, analysis, termLines, script) {
  const now = new Date().toISOString();
  const sys = rawReport?.system || rawReport?.system_context || {};

  const md = `# 🛡️ DIS — Device Intelligence System
## Export for Claude AI Analysis
> Generated: ${now}
> Tool: IrsanAI DIS-Core v1.0 · github.com/IrsanAI/IrsanAI-dis-core

---

## 📋 Scan Context

| Field | Value |
|---|---|
| **Tool** | DIS — Device Intelligence System |
| **Threat Module** | ${threat?.icon || ''} ${threat?.name || 'Unknown'} |
| **Severity** | ${threat?.sev || 'UNKNOWN'} |
| **Platform** | ${threat?.platform || 'android'} |
| **Device** | ${sys.model || '?'} |
| **Android Version** | ${sys.android || sys.android_version || '?'} |
| **Security Patch** | ${sys.patch || sys.security_patch || '?'} |
| **Knox Warranty** | ${sys.knox_warranty || '?'} |
| **SELinux** | ${sys.selinux || '?'} |
| **Scan Time** | ${rawReport?.dis_meta?.generated_at || now} |

---

## 🎯 What the User Did

1. Opened **DIS Dashboard** on Android device (localhost:3001)
2. Selected threat: **${threat?.name || '?'}** (${threat?.sev || '?'})
3. Generated Scout Script for platform: **${threat?.platform || 'android'}**
4. Executed script in **Termux** on Samsung device
5. Collected JSON report and pasted into dashboard
6. Requesting Claude AI analysis

---

## 🖥️ Terminal Output (Scout Execution)

\`\`\`
${termLines.map(l => l.t).join('\n')}
\`\`\`

---

## 📊 Raw Device Report (JSON)

\`\`\`json
${JSON.stringify(rawReport, null, 2)}
\`\`\`

---

## 🔍 Known Attack Patterns for this Threat

${(threat?.cve || []).map(c => `- \`${c}\``).join('\n')}

---

## 🛠️ Fix Playbook (from threat module)

${(threat?.fixes || []).map((f, i) => `${i + 1}. ${f}`).join('\n')}

---

## 💬 Instructions for Claude

You are **IrsanAI** — an autonomous device security analyst.

**User's Device:** ${sys.model || 'Samsung'} running Android ${sys.android || sys.android_version || '?'}
**Threat being analyzed:** ${threat?.name || 'Security Scan'}
**Severity level:** ${threat?.sev || 'UNKNOWN'}

Please analyze the raw device report above and provide:
1. **Is this threat active?** (yes/no/unclear) with confidence %
2. **Risk Score** (0-100)
3. **What the scan data reveals** — specific findings from the JSON
4. **Immediate actions** the user should take RIGHT NOW
5. **Next scout script** to run for deeper investigation
6. **Long-term hardening** recommendations

Respond in German. Be specific and reference actual values from the scan data.
`;

  return md;
}

function ExportModal({threat, rawReport, analysis, termLines, script, onClose}) {
  const [mode, setMode] = useState('preview'); // preview | copied | downloaded
  const [exportType, setExportType] = useState('markdown'); // markdown | json | clipboard

  const mdContent = buildClaudeExport(threat, rawReport, analysis, termLines, script);
  const jsonContent = JSON.stringify({
    dis_export: {
      version: "1.0",
      generated_at: new Date().toISOString(),
      threat: { id: threat?.id, name: threat?.name, severity: threat?.sev, platform: threat?.platform },
      device_report: rawReport,
      terminal_log: termLines?.map(l => l.t),
      fix_playbook: threat?.fixes,
      known_patterns: threat?.cve,
      llm_instruction: `Analyze this DIS security scan. Threat: ${threat?.name}. Device: ${rawReport?.system?.model}. Provide: 1) Threat active? 2) Risk 0-100. 3) Specific findings. 4) Immediate actions. 5) Next scan script. Respond in German.`
    }
  }, null, 2);

  const handleCopy = () => {
    const content = exportType === 'json' ? jsonContent : mdContent;
    navigator.clipboard.writeText(content);
    setMode('copied');
    setTimeout(() => setMode('preview'), 2500);
  };

  const handleDownload = () => {
    const content = exportType === 'json' ? jsonContent : mdContent;
    const ext = exportType === 'json' ? 'json' : 'md';
    const fname = `dis_claude_export_${threat?.id || 'scan'}_${Date.now()}.${ext}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = fname; a.click();
    URL.revokeObjectURL(url);
    setMode('downloaded');
    setTimeout(() => setMode('preview'), 2500);
  };

  return (
    <div style={{position:'fixed',inset:0,background:'#000000f2',zIndex:400,
      display:'flex',alignItems:'center',justifyContent:'center',padding:12}}>
      <div style={{background:'#06080f',border:'1px solid #bf9ffe44',borderRadius:14,
        maxWidth:820,width:'100%',maxHeight:'92vh',display:'flex',flexDirection:'column',
        boxShadow:'0 0 80px #bf9ffe18'}}>

        {/* Header */}
        <div style={{padding:'14px 18px',borderBottom:'1px solid #0f1520',
          display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <div>
            <div style={{color:'#bf9ffe',fontWeight:700,fontSize:14}}>
              🤖 EXPORT FOR CLAUDE AI
            </div>
            <div style={{color:'#2a3a4a',fontSize:10,marginTop:2}}>
              Komplette Analyse-Kette → Kopieren → Claude.ai einfügen
            </div>
          </div>
          <button onClick={onClose} style={{background:'none',border:'none',color:'#555',cursor:'pointer',fontSize:18}}>✕</button>
        </div>

        {/* Format Selector */}
        <div style={{padding:'12px 18px',borderBottom:'1px solid #0f1520',display:'flex',gap:8}}>
          {[
            ['markdown','📄 Markdown','Für claude.ai Chat Upload oder Copy-Paste'],
            ['json','{ } JSON','Für API oder direkte LLM-Integration'],
          ].map(([val,label,desc])=>(
            <button key={val} onClick={()=>setExportType(val)}
              style={{flex:1,background:exportType===val?'#bf9ffe18':'#0a0c14',
                border:`1px solid ${exportType===val?'#bf9ffe':'#1a2030'}`,
                color:exportType===val?'#bf9ffe':'#2a3a4a',borderRadius:8,
                padding:'10px 14px',cursor:'pointer',textAlign:'left',fontFamily:'monospace'}}>
              <div style={{fontSize:12,fontWeight:700,marginBottom:2}}>{label}</div>
              <div style={{fontSize:9,opacity:0.7}}>{desc}</div>
            </button>
          ))}
        </div>

        {/* Summary of what's included */}
        <div style={{padding:'10px 18px',borderBottom:'1px solid #0f1520',
          display:'flex',gap:16,flexWrap:'wrap'}}>
          {[
            ['🎯','Threat',threat?.name],
            ['📱','Device',rawReport?.system?.model||'?'],
            ['🔒','Patch',rawReport?.system?.patch||rawReport?.system?.security_patch||'?'],
            ['📊','Report',`${JSON.stringify(rawReport||{}).length} chars`],
            ['🖥️','Terminal',`${termLines?.length||0} lines`],
          ].map(([icon,label,val])=>(
            <div key={label} style={{display:'flex',alignItems:'center',gap:6}}>
              <span style={{fontSize:12}}>{icon}</span>
              <div>
                <div style={{color:'#2a3a4a',fontSize:8,letterSpacing:1}}>{label}</div>
                <div style={{color:'#c8d0e0',fontSize:10,fontFamily:'monospace'}}>{val}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Preview */}
        <div style={{flex:1,overflow:'auto',padding:'14px 18px'}}>
          <pre style={{color:'#5a7a5a',fontFamily:"'Courier New',monospace",fontSize:10,
            lineHeight:1.7,margin:0,whiteSpace:'pre-wrap',wordBreak:'break-word'}}>
            {exportType==='json' ? jsonContent.slice(0,2000)+'...' : mdContent.slice(0,2000)+'...'}
          </pre>
        </div>

        {/* Action Buttons */}
        <div style={{padding:'14px 18px',borderTop:'1px solid #0f1520'}}>

          {/* Step hint */}
          <div style={{background:'#0d0f1a',border:'1px solid #bf9ffe22',borderRadius:8,
            padding:'10px 14px',marginBottom:12}}>
            <div style={{color:'#bf9ffe',fontSize:9,letterSpacing:2,marginBottom:6}}>WIE ZU CLAUDE SCHICKEN</div>
            <div style={{display:'flex',flexDirection:'column',gap:4}}>
              {[
                '1. Unten auf "KOPIEREN" tippen',
                '2. claude.ai im Browser öffnen',
                '3. Neuer Chat → Text einfügen (lange drücken → Einfügen)',
                '4. Oder: Datei runterladen → bei claude.ai hochladen (📎)',
              ].map((s,i)=>(
                <div key={i} style={{color:'#4a5a6a',fontSize:11}}>{s}</div>
              ))}
            </div>
          </div>

          <div style={{display:'flex',gap:10}}>
            <button onClick={handleCopy}
              style={{flex:2,background:mode==='copied'?'#00e5a022':'#bf9ffe18',
                border:`1px solid ${mode==='copied'?'#00e5a0':'#bf9ffe'}`,
                color:mode==='copied'?'#00e5a0':'#bf9ffe',
                borderRadius:8,padding:'13px',cursor:'pointer',
                fontFamily:'monospace',fontWeight:700,fontSize:13}}>
              {mode==='copied'?'✅ KOPIERT — jetzt claude.ai öffnen!':'📋 KOPIEREN (Zwischenablage)'}
            </button>
            <button onClick={handleDownload}
              style={{flex:1,background:mode==='downloaded'?'#30d15822':'#30d15818',
                border:`1px solid ${mode==='downloaded'?'#30d158':'#30d15844'}`,
                color:mode==='downloaded'?'#30d158':'#30d15888',
                borderRadius:8,padding:'13px',cursor:'pointer',
                fontFamily:'monospace',fontWeight:700,fontSize:12}}>
              {mode==='downloaded'?'✅ SAVED':'⬇️ DOWNLOAD'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AnalysisResult({analysis,threat}) {
  if(!analysis) return null;
  const c=SEV[analysis.risk_label]||SEV[threat?.sev]||"#888";
  return (
    <div style={{marginTop:20}}>
      <div style={{background:SEV_BG[analysis.risk_label]||"#0a0c14",
        border:`1px solid ${c}55`,borderRadius:12,padding:"16px 20px",marginBottom:14,
        display:"flex",alignItems:"center",gap:16}}>
        <div style={{textAlign:"center",minWidth:80}}>
          <div style={{color:c,fontSize:40,fontWeight:900,lineHeight:1}}>{analysis.risk_score}</div>
          <div style={{color:c,fontSize:9,letterSpacing:2,marginTop:4}}>RISK</div>
        </div>
        <div style={{flex:1,borderLeft:`1px solid ${c}33`,paddingLeft:16}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            {analysis.threat_active&&<Pulse color={c}/>}
            <span style={{color:c,fontWeight:700,fontSize:14}}>{analysis.risk_label}</span>
            <span style={{color:"#2a3a4a",fontSize:11}}>| {analysis.confidence}% Konfidenz</span>
          </div>
          <div style={{color:"#c8d0e0",fontSize:12,lineHeight:1.6}}>{analysis.summary}</div>
        </div>
      </div>
      {analysis.active_indicators?.length>0&&(
        <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:10,padding:"14px 16px",marginBottom:12}}>
          <div style={{color:"#ff2d55",fontSize:9,letterSpacing:2,marginBottom:8}}>⚠️ AKTIVE INDIKATOREN</div>
          {analysis.active_indicators.map((ind,i)=>(
            <div key={i} style={{display:"flex",gap:8,padding:"5px 0",borderBottom:"1px solid #0f1520"}}>
              <span style={{color:"#ff2d55",fontSize:10}}>◆</span>
              <span style={{color:"#c8d0e0",fontSize:12}}>{ind}</span>
            </div>
          ))}
        </div>
      )}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
        {analysis.immediate_actions?.length>0&&(
          <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:10,padding:"14px 16px"}}>
            <div style={{color:"#ff9500",fontSize:9,letterSpacing:2,marginBottom:8}}>🚨 SOFORT</div>
            {analysis.immediate_actions.map((a,i)=>(
              <div key={i} style={{display:"flex",gap:8,marginBottom:7}}>
                <span style={{color:"#ff9500",flexShrink:0}}>{i+1}.</span>
                <span style={{color:"#c8d0e0",fontSize:11,lineHeight:1.5}}>{a}</span>
              </div>
            ))}
          </div>
        )}
        {analysis.hardening?.length>0&&(
          <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:10,padding:"14px 16px"}}>
            <div style={{color:"#30d158",fontSize:9,letterSpacing:2,marginBottom:8}}>🛡️ HÄRTUNG</div>
            {analysis.hardening.map((s,i)=>(
              <div key={i} style={{display:"flex",gap:8,marginBottom:7}}>
                <span style={{color:"#30d158",flexShrink:0}}>→</span>
                <span style={{color:"#8a9ab0",fontSize:11,lineHeight:1.5}}>{s}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      {analysis.auto_fix?.length>0&&(
        <div style={{background:"#001a08",border:"1px solid #30d15844",borderRadius:10,padding:"14px 16px",marginBottom:12}}>
          <div style={{color:"#30d158",fontSize:9,letterSpacing:2,marginBottom:10}}>⚡ AUTO-FIX COMMANDS</div>
          {analysis.auto_fix.map((cmd,i)=>(
            <div key={i} style={{display:"flex",gap:8,marginBottom:6,alignItems:"center"}}>
              <code style={{flex:1,background:"#002a10",border:"1px solid #30d15822",borderRadius:5,
                padding:"5px 10px",color:"#30d158",fontSize:10,fontFamily:"monospace",wordBreak:"break-all"}}>{cmd}</code>
              <button onClick={()=>navigator.clipboard.writeText(cmd)}
                style={{background:"#30d15818",border:"1px solid #30d15844",color:"#30d158",
                  borderRadius:5,padding:"5px 10px",cursor:"pointer",fontSize:9,fontFamily:"monospace",flexShrink:0}}>
                COPY
              </button>
            </div>
          ))}
        </div>
      )}
      <div style={{textAlign:"center",color:"#2a3a4a",fontSize:10,marginBottom:16}}>
        Nächster Scan empfohlen: <span style={{color:"#60b4ff"}}>{analysis.next_scan}</span>
      </div>
    </div>
  );
}

// ── EXPORT BUTTON (used in Analyse Tab) ────────────────────────────
function ExportButton({onClick}) {
  const [h,setH]=useState(false);
  return (
    <div style={{marginTop:20,background:"#0d0a1a",border:"1px solid #bf9ffe44",
      borderRadius:12,padding:"16px 18px"}}>
      <div style={{color:"#bf9ffe",fontSize:9,letterSpacing:2,marginBottom:8}}>
        🤖 WEITER MIT CLAUDE AI
      </div>
      <div style={{color:"#3a3a5a",fontSize:11,marginBottom:14,lineHeight:1.6}}>
        Exportiere die komplette Analyse-Kette — Threat-Kontext, Gerätedaten, 
        Terminal-Output und Scan-Ergebnis — als Paket für Claude AI.
        Kopieren → claude.ai → einfügen → tiefere Analyse anfordern.
      </div>
      <button onClick={onClick}
        onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)}
        style={{width:"100%",background:h?"#bf9ffe28":"#bf9ffe18",
          border:"1px solid #bf9ffe",color:"#bf9ffe",borderRadius:9,
          padding:"14px",cursor:"pointer",fontFamily:"monospace",
          fontWeight:700,fontSize:13,letterSpacing:1,
          boxShadow:h?"0 0 20px #bf9ffe33":"none",transition:"all 0.2s"}}>
        🤖 EXPORT FÜR CLAUDE AI →
      </button>
      <div style={{display:"flex",gap:8,marginTop:8}}>
        {["📄 Markdown","{ } JSON","📋 Clipboard"].map(t=>(
          <div key={t} style={{flex:1,textAlign:"center",color:"#2a3a4a",
            fontSize:9,padding:"4px",background:"#080b12",borderRadius:5,
            border:"1px solid #1a2030"}}>
            {t}
          </div>
        ))}
      </div>
    </div>
  );
}


// ── WINDOWS REPORT PASTE ───────────────────────────────────────────
function WinReportPaste() {
  const [json,setJson]=useState("");
  const [err,setErr]=useState("");
  const [analysis,setAnalysis]=useState(null);
  const [analyzing,setAnalyzing]=useState(false);

  const analyze = async () => {
    setErr("");
    let parsed;
    try { parsed = JSON.parse(json.trim()); }
    catch { setErr("❌ Kein gültiges JSON. Gesamten Report-Inhalt kopieren."); return; }
    if(!parsed.dis_meta) { setErr("❌ Kein DIS Windows Report erkannt."); return; }
    setAnalyzing(true);
    try {
      const res = await fetch("https://api.anthropic.com/v1/messages",{
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          model:"claude-sonnet-4-20250514", max_tokens:1000,
          messages:[{role:"user", content:
`IrsanAI Security Analyst. Windows Report. JSON only, no markdown:
{
  "threat_active": true/false,
  "confidence": 0-100,
  "risk_score": 0-100,
  "risk_label": "KRITISCH|HOCH|MITTEL|NIEDRIG|SICHER",
  "summary": "Was wurde gefunden?",
  "active_indicators": ["konkreter Befund mit Wert aus dem Report"],
  "immediate_actions": ["Sofortmaßnahme — mit konkretem Befehl"],
  "hardening": ["Langzeit-Härtung"],
  "auto_fix": ["powershell Befehl zum Fixen"],
  "next_scan": "sofort|24h|7d|30d"
}
Report: ${JSON.stringify(parsed, null, 2)}`}]
        })
      });
      const d = await res.json();
      const txt = (d.content||[]).map(b=>b.text||"").join("").replace(/\`\`\`json|\`\`\`/g,"").trim();
      setAnalysis(JSON.parse(txt));
    } catch(e) { setErr("❌ KI-Fehler: "+e.message); }
    setAnalyzing(false);
  };

  const exportForClaude = () => {
    let parsed = {};
    try { parsed = JSON.parse(json); } catch {}
    const md = `# DIS Windows Security Report\n> IrsanAI Stack\n\n\`\`\`json\n${json}\n\`\`\`\n\n**Instruction:** Analysiere diesen Windows Security Report auf Deutsch. Risk-Score 0-100, Sofortmaßnahmen, Härtungsempfehlungen.`;
    navigator.clipboard.writeText(md);
  };

  const c = SEV[analysis?.risk_label] || "#0078d4";
  return (
    <div>
      <textarea value={json} onChange={e=>{setJson(e.target.value);setErr("");}}
        placeholder={'{
  "dis_meta": { "platform": "windows_powershell", ... },
  "system": { "os_name": "Windows 11", ... },
  ...
}'}
        style={{width:"100%",minHeight:160,background:"#030508",
          border:`1px solid ${err?"#ff2d5544":"#0078d422"}`,
          borderRadius:9,padding:"12px",color:"#5a8aaa",fontFamily:"monospace",
          fontSize:10,resize:"vertical",outline:"none",boxSizing:"border-box",
          lineHeight:1.6,marginBottom:8}}/>
      {err&&<div style={{color:"#ff2d55",fontSize:11,padding:"7px 12px",
        background:"#140507",borderRadius:6,marginBottom:8}}>{err}</div>}
      <div style={{display:"flex",gap:8,marginBottom:16}}>
        <button onClick={analyze} disabled={!json.trim()||analyzing}
          style={{flex:2,background:json.trim()?"#0078d418":"#0a0c14",
            border:`1px solid ${json.trim()?"#0078d4":"#1a2030"}`,
            color:json.trim()?"#0078d4":"#333",borderRadius:7,padding:"11px",
            cursor:json.trim()?"pointer":"not-allowed",fontFamily:"monospace",fontWeight:700,fontSize:12}}>
          {analyzing?"⏳ ANALYSIERT...":"🧠 MIT CLAUDE AI ANALYSIEREN →"}
        </button>
        {json.trim()&&<button onClick={exportForClaude}
          style={{flex:1,background:"#bf9ffe18",border:"1px solid #bf9ffe44",
            color:"#bf9ffe",borderRadius:7,padding:"11px",cursor:"pointer",
            fontFamily:"monospace",fontWeight:700,fontSize:11}}>
          🤖 FÜR CLAUDE EXPORTIEREN
        </button>}
      </div>
      {analysis&&(
        <div>
          <div style={{background:SEV_BG[analysis.risk_label]||"#0a0c14",
            border:`1px solid ${c}55`,borderRadius:12,padding:"14px 18px",marginBottom:12,
            display:"flex",alignItems:"center",gap:14}}>
            <div style={{textAlign:"center",minWidth:70}}>
              <div style={{color:c,fontSize:36,fontWeight:900,lineHeight:1}}>{analysis.risk_score}</div>
              <div style={{color:c,fontSize:9,letterSpacing:2,marginTop:3}}>RISK</div>
            </div>
            <div style={{flex:1,borderLeft:`1px solid ${c}33`,paddingLeft:14}}>
              <div style={{color:c,fontWeight:700,fontSize:13,marginBottom:4}}>{analysis.risk_label}</div>
              <div style={{color:"#c8d0e0",fontSize:11,lineHeight:1.6}}>{analysis.summary}</div>
            </div>
          </div>
          {analysis.active_indicators?.length>0&&(
            <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:10,
              padding:"12px 14px",marginBottom:10}}>
              <div style={{color:"#ff2d55",fontSize:9,letterSpacing:2,marginBottom:8}}>⚠️ BEFUNDE</div>
              {analysis.active_indicators.map((ind,i)=>(
                <div key={i} style={{display:"flex",gap:8,padding:"4px 0",borderBottom:"1px solid #0f1520"}}>
                  <span style={{color:"#ff2d55",fontSize:10}}>◆</span>
                  <span style={{color:"#c8d0e0",fontSize:11}}>{ind}</span>
                </div>
              ))}
            </div>
          )}
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
            {analysis.immediate_actions?.length>0&&(
              <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:9,padding:"12px"}}>
                <div style={{color:"#ff9500",fontSize:9,letterSpacing:2,marginBottom:8}}>🚨 SOFORT</div>
                {analysis.immediate_actions.map((a,i)=>(
                  <div key={i} style={{display:"flex",gap:6,marginBottom:6}}>
                    <span style={{color:"#ff9500",flexShrink:0}}>{i+1}.</span>
                    <span style={{color:"#c8d0e0",fontSize:10,lineHeight:1.5}}>{a}</span>
                  </div>
                ))}
              </div>
            )}
            {analysis.hardening?.length>0&&(
              <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:9,padding:"12px"}}>
                <div style={{color:"#30d158",fontSize:9,letterSpacing:2,marginBottom:8}}>🛡️ HÄRTUNG</div>
                {analysis.hardening.map((s,i)=>(
                  <div key={i} style={{display:"flex",gap:6,marginBottom:6}}>
                    <span style={{color:"#30d158",flexShrink:0}}>→</span>
                    <span style={{color:"#8a9ab0",fontSize:10,lineHeight:1.5}}>{s}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          {analysis.auto_fix?.length>0&&(
            <div style={{background:"#001a08",border:"1px solid #30d15844",borderRadius:9,padding:"12px"}}>
              <div style={{color:"#30d158",fontSize:9,letterSpacing:2,marginBottom:8}}>⚡ AUTO-FIX (PowerShell)</div>
              {analysis.auto_fix.map((cmd,i)=>(
                <div key={i} style={{display:"flex",gap:8,marginBottom:6,alignItems:"center"}}>
                  <code style={{flex:1,background:"#002a10",borderRadius:5,padding:"5px 10px",
                    color:"#30d158",fontSize:10,fontFamily:"monospace",wordBreak:"break-all",
                    border:"1px solid #30d15822"}}>{cmd}</code>
                  <button onClick={()=>navigator.clipboard.writeText(cmd)}
                    style={{background:"#30d15818",border:"1px solid #30d15844",color:"#30d158",
                      borderRadius:5,padding:"5px 10px",cursor:"pointer",fontSize:9,
                      fontFamily:"monospace",flexShrink:0}}>COPY</button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── MAIN ───────────────────────────────────────────────────────────
export default function App() {
  const [env,setEnv]=useState(null);
  const [tab,setTab]=useState("threats");
  const [catFilter,setCatFilter]=useState("all");
  const [platFilter,setPlatFilter]=useState("all");
  const [activeThreat,setActiveThreat]=useState(null);
  const [script,setScript]=useState("");
  const [showScript,setShowScript]=useState(false);
  const [pastedJson,setPastedJson]=useState("");
  const [parseErr,setParseErr]=useState("");
  const [analysis,setAnalysis]=useState(null);
  const [analyzing,setAnalyzing]=useState(false);
  const [termLines,setTermLines]=useState([]);
  const [showExport,setShowExport]=useState(false);
  const [rawReport,setRawReport]=useState(null);
  const addLine=(t,c="#7c82a8")=>setTermLines(l=>[...l,{t,c}]);

  // Fetch environment from server
  useEffect(()=>{
    fetch('/api/env')
      .then(r=>r.json())
      .then(d=>{
        setEnv(d);
        // Auto-set platform filter based on client OS
        if(d.client?.type&&d.client.type!=="unknown") setPlatFilter(d.client.type);
      })
      .catch(()=>setEnv({
        client:{type:"unknown",label:"Standalone Mode",icon:"💻",color:"#888",hint:"Server nicht erreichbar — Demo-Modus"},
        server:{osType:"unknown",osLabel:"Standalone",cpus:"?",totalMemGB:"?",uptime:"?"},
        lan:[]
      }));
  },[]);

  const handleScan=useCallback((threat)=>{
    setActiveThreat(threat);
    const pl=env?.client?.type==="windows"?"windows":env?.client?.type==="linux"?"linux":"android";
    setScript(buildScript(threat,pl));
    setAnalysis(null);
    setPastedJson("");
    setParseErr("");
    setRawReport(null);
    setTab("scan");
    setTermLines([]);
    setTimeout(()=>addLine(`$ dis_scout --threat ${threat.id}`,"#ff2d55"),100);
    setTimeout(()=>addLine(`→ ${threat.name} | ${threat.sev}`,[SEV[threat.sev]||"#888"]),400);
    setTimeout(()=>addLine(`→ Platform: ${pl} | CVEs: ${threat.cve.join(", ")}`,"#7c82a8"),800);
    setTimeout(()=>addLine(`✅ Script bereit`,"#00e5a0"),1300);
  },[env]);

  const handleAnalyze=useCallback(async()=>{
    setParseErr("");
    let parsed;
    try{parsed=JSON.parse(pastedJson.trim());setRawReport(parsed);}
    catch{setParseErr("❌ Kein gültiges JSON.");return;}
    if(!parsed.dis_meta&&!parsed.isu_meta&&!parsed.sis_meta){setParseErr("❌ Kein DIS-Report erkannt.");return;}
    setTab("analyze");
    setAnalyzing(true);
    setTermLines([]);
    const sys=parsed.system||parsed.system_context||{};
    [
      [`$ dis_analyze --report <json>`,"#ff2d55"],
      [`→ Gerät: ${sys.model||"?"} | Android ${sys.android||sys.android_version||"?"}`,"#60b4ff"],
      [`→ Patch: ${sys.patch||sys.security_patch||"?"}`,"#f7c07e"],
      [`→ Threat: ${parsed.dis_meta?.threat_name||parsed.isu_meta?.threat_name||"?"}`,"#ff9500"],
      [`→ Sende an Claude AI...`,"#7c82a8"],
    ].forEach(([t,c],i)=>setTimeout(()=>addLine(t,c),i*200));
    try{
      const r=await analyzeWithClaude(parsed,activeThreat);
      setAnalysis(r);
      addLine(`✅ ${r.risk_label} — Score: ${r.risk_score}`,"#00e5a0");
    }catch(e){setParseErr("❌ "+e.message);setTab("scan");}
    setAnalyzing(false);
  },[pastedJson,activeThreat]);

  const cats=["all","surveillance","windows","linux","os"];
  const plats=["all","android","windows","linux","ios"];
  const filtered=THREATS.filter(t=>
    (catFilter==="all"||t.cat===catFilter)&&
    (platFilter==="all"||t.platform===platFilter)
  );

  const TABS=[{id:"threats",icon:"🎯",label:"THREATS"},{id:"scan",icon:"🔬",label:"SCOUT"},
    {id:"analyze",icon:"🧠",label:"ANALYSE"},{id:"windows",icon:"🪟",label:"WINDOWS"},{id:"intel",icon:"📡",label:"INTEL"}];

  return (
    <div style={{minHeight:"100vh",background:"#04050a",color:"#c8d0e0",fontFamily:"'Courier New',monospace",paddingBottom:60}}>
      {showScript&&<ScriptModal script={script} threat={activeThreat} onClose={()=>setShowScript(false)}/> }
      {showExport&&rawReport&&<ExportModal threat={activeThreat} rawReport={rawReport} analysis={analysis} termLines={termLines} script={script} onClose={()=>setShowExport(false)}/>}

      {/* Header */}
      <div style={{background:"linear-gradient(180deg,#080b14,#04050a)",borderBottom:"1px solid #0f1520",padding:"14px 20px 0"}}>
        <div style={{maxWidth:1100,margin:"0 auto"}}>
          <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
            <div style={{width:38,height:38,background:"#ff2d5518",border:"1px solid #ff2d5544",
              borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18}}>🛡️</div>
            <div style={{flex:1}}>
              <div style={{color:"#ff2d55",fontWeight:900,fontSize:14,letterSpacing:3}}>DIS — DEVICE INTELLIGENCE SYSTEM</div>
              <div style={{color:"#1a2a1a",fontSize:9,letterSpacing:3}}>IRSANAI STACK · ANTI-SURVEILLANCE · CROSS-PLATFORM · LLM-NATIVE · v1.0</div>
            </div>
            {env&&<div style={{textAlign:"right"}}>
              <div style={{color:OS_COLOR[env.client?.type]||"#888",fontSize:11,fontWeight:700}}>{env.client?.icon} {env.client?.label}</div>
              <div style={{color:"#1a2a3a",fontSize:9}}>auto-detected</div>
            </div>}
          </div>
          <div style={{display:"flex",gap:0}}>
            {TABS.map(t=>(
              <button key={t.id} onClick={()=>setTab(t.id)}
                style={{background:"transparent",border:"none",borderBottom:`2px solid ${tab===t.id?"#ff2d55":"transparent"}`,
                  color:tab===t.id?"#ff2d55":"#2a3a4a",padding:"10px 16px",cursor:"pointer",
                  fontFamily:"monospace",fontSize:11,fontWeight:700,letterSpacing:1}}>
                {t.icon} {t.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div style={{maxWidth:1100,margin:"0 auto",padding:"20px 16px"}}>

        {/* ── THREATS ── */}
        {tab==="threats"&&(
          <div>
            <OsDetectBanner env={env}/>
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>
              {cats.map(c=>(
                <button key={c} onClick={()=>setCatFilter(c)}
                  style={{background:catFilter===c?"#ff2d5518":"#080b12",border:`1px solid ${catFilter===c?"#ff2d55":"#1a2030"}`,
                    color:catFilter===c?"#ff2d55":"#2a3a4a",borderRadius:6,padding:"6px 12px",
                    cursor:"pointer",fontFamily:"monospace",fontSize:10,fontWeight:700,letterSpacing:1}}>
                  {c.toUpperCase()}
                </button>
              ))}
              <div style={{width:1,background:"#1a2030",margin:"0 4px"}}/>
              {plats.map(p=>(
                <button key={p} onClick={()=>setPlatFilter(p)}
                  style={{background:platFilter===p?`${OS_COLOR[p]||"#888"}18`:"#080b12",
                    border:`1px solid ${platFilter===p?OS_COLOR[p]||"#888":"#1a2030"}`,
                    color:platFilter===p?OS_COLOR[p]||"#888":"#2a3a4a",borderRadius:6,padding:"6px 12px",
                    cursor:"pointer",fontFamily:"monospace",fontSize:10,fontWeight:700}}>
                  {p.toUpperCase()}
                </button>
              ))}
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(320px,1fr))",gap:12}}>
              {filtered.map(t=><ThreatCard key={t.id} threat={t} onScan={handleScan}/>)}
            </div>
          </div>
        )}

        {/* ── SCOUT ── */}
        {tab==="scan"&&(
          <div>
            {!activeThreat?(
              <div style={{textAlign:"center",padding:"60px 20px",color:"#2a3a4a"}}>
                <div style={{fontSize:40,marginBottom:12}}>🔬</div>
                <div>THREATS → Bedrohung wählen → SCAN STARTEN</div>
              </div>
            ):(
              <>
                <div style={{background:"#080b12",border:`1px solid ${SEV[activeThreat.sev]}33`,
                  borderRadius:10,padding:"12px 16px",marginBottom:16,
                  display:"flex",alignItems:"center",gap:12}}>
                  <span style={{fontSize:22}}>{activeThreat.icon}</span>
                  <div style={{flex:1}}>
                    <div style={{color:"#e2e5f0",fontWeight:700}}>{activeThreat.name}</div>
                    <div style={{color:SEV[activeThreat.sev],fontSize:10}}>{activeThreat.sev}</div>
                  </div>
                </div>
                <div style={{background:"#030508",border:"1px solid #0f1520",borderRadius:10,
                  padding:"14px 16px",marginBottom:16}}>
                  <div style={{display:"flex",gap:5,marginBottom:8}}>
                    {["#ff5f56","#ffbd2e","#27c93f"].map(c=>(<div key={c} style={{width:8,height:8,borderRadius:"50%",background:c}}/>))}
                  </div>
                  {termLines.map((l,i)=>(<div key={i} style={{color:l.c,fontSize:11,lineHeight:1.65}}>{l.t}</div>))}
                  <Blink/>
                </div>
                <div style={{background:"#030508",border:"1px solid #0f1520",borderRadius:10,
                  overflow:"hidden",marginBottom:16}}>
                  <div style={{padding:"8px 14px",borderBottom:"1px solid #0f1520",
                    display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <span style={{color:"#1a2a3a",fontSize:9}}>dis_scout_{activeThreat.id}.sh — {script.split("\n").length} Zeilen</span>
                    <button onClick={()=>setShowScript(true)}
                      style={{background:"#60b4ff18",border:"1px solid #60b4ff44",color:"#60b4ff",
                        borderRadius:5,padding:"4px 12px",cursor:"pointer",fontFamily:"monospace",fontSize:9,fontWeight:700}}>
                      VOLLBILD
                    </button>
                  </div>
                  <pre style={{color:"#2a4a2a",fontFamily:"monospace",fontSize:10,lineHeight:1.6,
                    margin:0,padding:"12px 14px",maxHeight:160,overflow:"auto",whiteSpace:"pre-wrap"}}>
                    {script.slice(0,600)}...
                  </pre>
                </div>
                <div style={{display:"flex",gap:10}}>
                  <button onClick={()=>{navigator.clipboard.writeText(script);setShowScript(true);}}
                    style={{flex:1,background:"#00ff9d18",border:"1px solid #00ff9d55",color:"#00ff9d",
                      borderRadius:7,padding:"12px",cursor:"pointer",fontFamily:"monospace",fontWeight:700,fontSize:12}}>
                    📋 SCRIPT KOPIEREN
                  </button>
                  <button onClick={()=>setTab("analyze")}
                    style={{flex:1,background:"#ff2d5518",border:"1px solid #ff2d5555",color:"#ff2d55",
                      borderRadius:7,padding:"12px",cursor:"pointer",fontFamily:"monospace",fontWeight:700,fontSize:12}}>
                    → ANALYSE
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {/* ── ANALYSE ── */}
        {tab==="analyze"&&(
          <div>
            {!activeThreat?(
              <div style={{textAlign:"center",padding:"60px 20px",color:"#2a3a4a"}}>
                <div style={{fontSize:40,marginBottom:12}}>🧠</div>
                <div>Erst Scout-Script ausführen</div>
              </div>
            ):(
              <>
                <div style={{color:"#2a3a4a",fontSize:11,marginBottom:12}}>
                  Scout ausführen → <code style={{color:"#60b4ff"}}>cat ~/dis_*.json</code> → hier einfügen
                </div>
                <textarea value={pastedJson} onChange={e=>{setPastedJson(e.target.value);setParseErr("");}}
                  placeholder='{ "dis_meta": { ... }, "system": { ... } }'
                  style={{width:"100%",minHeight:180,background:"#030508",
                    border:`1px solid ${parseErr?"#ff2d5544":"#1a2030"}`,
                    borderRadius:10,padding:"14px",color:"#5a8a5a",fontFamily:"monospace",
                    fontSize:11,resize:"vertical",outline:"none",boxSizing:"border-box",
                    lineHeight:1.6,marginBottom:8}}/>
                {parseErr&&<div style={{color:"#ff2d55",fontSize:11,padding:"8px 12px",background:"#140507",borderRadius:6,marginBottom:10}}>{parseErr}</div>}
                {termLines.length>0&&(
                  <div style={{background:"#030508",border:"1px solid #0f1520",borderRadius:10,padding:"14px 16px",marginBottom:14}}>
                    {termLines.map((l,i)=>(<div key={i} style={{color:l.c,fontSize:11,lineHeight:1.65}}>{l.t}</div>))}
                    {analyzing&&<Blink/>}
                  </div>
                )}
                {!analysis&&(
                  <button onClick={handleAnalyze} disabled={!pastedJson.trim()||analyzing}
                    style={{width:"100%",background:pastedJson.trim()?"#ff2d5518":"#0a0c14",
                      border:`1px solid ${pastedJson.trim()?"#ff2d5555":"#1a2030"}`,
                      color:pastedJson.trim()?"#ff2d55":"#333",borderRadius:7,padding:"13px",
                      cursor:pastedJson.trim()?"pointer":"not-allowed",fontFamily:"monospace",
                      fontWeight:700,fontSize:13}}>
                    {analyzing?"⏳ ANALYSIERT...":"🧠 MIT CLAUDE AI ANALYSIEREN →"}
                  </button>
                )}
                <AnalysisResult analysis={analysis} threat={activeThreat}/>
                {analysis&&<ExportButton onClick={()=>setShowExport(true)}/>}
              </>
            )}
          </div>
        )}

        {/* ── INTEL ── */}
        {tab==="intel"&&(
          <div>
            <OsDetectBanner env={env}/>
            <div style={{background:"#080b12",border:"1px solid #ff2d5522",borderRadius:12,padding:"20px",marginBottom:16}}>
              <div style={{color:"#ff2d55",fontSize:10,letterSpacing:2,marginBottom:16}}>IRSANAI DIS STACK — ARCHITEKTUR</div>
              {[
                ["LAYER 4","INTELLIGENCE","Claude AI · CVE Matching · Zero-Day · Pattern Recognition","#ff2d55"],
                ["LAYER 3","CONTROL CENTER","Dieses Dashboard · Auto-OS-Detect · WebSocket · LAN-Discovery","#ff9500"],
                ["LAYER 2","SCOUT AGENTS","Termux · PowerShell · Bash · ADB · iOS Shortcuts","#00c7be"],
                ["LAYER 1","SENSORS","Android · iPhone · Windows · Linux · Router · IoT","#30d158"],
              ].map(([l,n,d,c])=>(
                <div key={l} style={{display:"flex",gap:14,marginBottom:10,padding:"10px 14px",
                  background:"#04050a",borderRadius:8,border:`1px solid ${c}22`}}>
                  <div style={{color:c,fontSize:9,fontWeight:700,letterSpacing:1,minWidth:55,paddingTop:2}}>{l}</div>
                  <div>
                    <div style={{color:c,fontSize:12,fontWeight:700,marginBottom:2}}>{n}</div>
                    <div style={{color:"#2a3a4a",fontSize:11}}>{d}</div>
                  </div>
                </div>
              ))}
            </div>
            <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:12,padding:"20px",marginBottom:16}}>
              <div style={{color:"#30d158",fontSize:10,letterSpacing:2,marginBottom:12}}>🚀 QUICK START</div>
              {[
                ["Clone","git clone https://github.com/IrsanAI/dis-core"],
                ["Install","cd dis-core && npm install"],
                ["Build","npm run build"],
                ["Start","node server.js"],
                ["Open","http://localhost:3001"],
              ].map(([k,v])=>(
                <div key={k} style={{display:"flex",gap:12,marginBottom:8,alignItems:"center"}}>
                  <span style={{color:"#2a3a4a",fontSize:10,minWidth:60}}>{k}</span>
                  <code style={{color:"#30d158",fontSize:11,background:"#001a08",
                    border:"1px solid #30d15822",borderRadius:5,padding:"3px 10px",flex:1,wordBreak:"break-all"}}>
                    {v}
                  </code>
                  <button onClick={()=>navigator.clipboard.writeText(v)}
                    style={{background:"none",border:"1px solid #1a2030",color:"#2a3a4a",
                      borderRadius:5,padding:"3px 8px",cursor:"pointer",fontSize:9,fontFamily:"monospace"}}>
                    COPY
                  </button>
                </div>
              ))}
            </div>
            <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:12,padding:"16px 20px"}}>
              <div style={{color:"#60b4ff",fontSize:10,letterSpacing:2,marginBottom:12}}>THREAT MATRIX — {THREATS.length} MODULE</div>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                  <thead><tr style={{borderBottom:"1px solid #1a2030"}}>
                    {["Threat","Severity","Platform","CVEs"].map(h=>(
                      <th key={h} style={{textAlign:"left",padding:"6px 12px",color:"#2a3a4a",fontSize:9,letterSpacing:1}}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {THREATS.map(t=>(
                      <tr key={t.id} onClick={()=>{handleScan(t);setTab("scan");}}
                        style={{borderBottom:"1px solid #0f1520",cursor:"pointer"}}
                        onMouseEnter={e=>e.currentTarget.style.background="#0d1018"}
                        onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                        <td style={{padding:"7px 12px"}}><span style={{marginRight:6}}>{t.icon}</span><span style={{color:"#c8d0e0"}}>{t.name}</span></td>
                        <td style={{padding:"7px 12px"}}><span style={{color:SEV[t.sev],fontSize:10,fontWeight:700}}>{t.sev}</span></td>
                        <td style={{padding:"7px 12px",color:OS_COLOR[t.platform]||"#888",fontSize:10,fontFamily:"monospace"}}>{t.platform}</td>
                        <td style={{padding:"7px 12px",color:"#2a3a4a",fontSize:10}}>{t.cve.slice(0,2).join(", ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ══ WINDOWS TAB ══════════════════════════════════ */}
        {tab==="windows"&&(
          <div>
            <div style={{background:"#080b12",border:"1px solid #0078d444",borderRadius:12,
              padding:"20px",marginBottom:16}}>
              <div style={{color:"#0078d4",fontSize:13,fontWeight:700,marginBottom:4}}>
                🪟 DIS — Windows Security Scout
              </div>
              <div style={{color:"#2a3a4a",fontSize:11,marginBottom:16}}>
                Führe den PowerShell Scout Agent auf deinem Windows-PC aus. 
                Der Report wird automatisch in die Zwischenablage kopiert.
              </div>

              {/* Quick Start */}
              <div style={{background:"#04050a",border:"1px solid #0078d422",borderRadius:10,
                padding:"16px",marginBottom:16}}>
                <div style={{color:"#0078d4",fontSize:9,letterSpacing:2,marginBottom:12}}>⚡ QUICK START — 3 SCHRITTE</div>
                {[
                  {step:"01", title:"PowerShell öffnen", cmd:"Win + X → Windows PowerShell (Admin)",
                   note:"Als Administrator ausführen wichtig!"},
                  {step:"02", title:"Scout starten", cmd:`powershell -ExecutionPolicy Bypass -File scripts\windows\dis_scout.ps1`,
                   note:"Oder: Doppelklick auf install_windows.bat"},
                  {step:"03", title:"Report ins Dashboard", cmd:"Report wird automatisch kopiert → hier einfügen → Analysieren",
                   note:"Oder .json Datei direkt zu claude.ai hochladen"},
                ].map(({step,title,cmd,note})=>(
                  <div key={step} style={{display:"flex",gap:14,marginBottom:14,
                    padding:"12px",background:"#080b12",borderRadius:8,border:"1px solid #0078d422"}}>
                    <div style={{color:"#0078d4",fontSize:18,fontWeight:900,minWidth:28}}>{step}</div>
                    <div style={{flex:1}}>
                      <div style={{color:"#e2e5f0",fontWeight:700,fontSize:12,marginBottom:4}}>{title}</div>
                      <code style={{display:"block",color:"#60b4ff",fontSize:10,
                        background:"#04050a",borderRadius:5,padding:"6px 10px",
                        marginBottom:4,wordBreak:"break-all"}}>{cmd}</code>
                      <div style={{color:"#2a3a4a",fontSize:10}}>{note}</div>
                    </div>
                    <button onClick={()=>navigator.clipboard.writeText(cmd)}
                      style={{background:"#0078d418",border:"1px solid #0078d444",color:"#0078d4",
                        borderRadius:5,padding:"6px 10px",cursor:"pointer",
                        fontFamily:"monospace",fontSize:9,alignSelf:"flex-start",flexShrink:0}}>
                      COPY
                    </button>
                  </div>
                ))}
              </div>

              {/* What it scans */}
              <div style={{background:"#04050a",border:"1px solid #0078d422",borderRadius:10,padding:"16px",marginBottom:16}}>
                <div style={{color:"#0078d4",fontSize:9,letterSpacing:2,marginBottom:12}}>📊 WAS GESCANNT WIRD</div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:8}}>
                  {[
                    ["🛡️","Windows Defender","Status, Signature-Alter, Tamper Protection"],
                    ["🔥","Firewall","Alle Profile (Domain/Private/Public)"],
                    ["🌐","Netzwerk","Aktive Verbindungen, DNS, Proxy, Hosts-File"],
                    ["⚡","Prozesse","High-CPU, Autorun, Suspicious Services"],
                    ["📋","Scheduled Tasks","Nicht-Microsoft Tasks die laufen"],
                    ["🔒","Zertifikate","User/Machine Root Certs (MITM-Check)"],
                    ["💾","Shadow Copies","Ransomware-Indikator: Anzahl Backups"],
                    ["🔑","UAC & SecureBoot","Sicherheits-Grundeinstellungen"],
                    ["📦","Remote Tools","TeamViewer, AnyDesk, VNC Detection"],
                    ["🔐","BitLocker","Festplatten-Verschlüsselung Status"],
                  ].map(([icon,title,desc])=>(
                    <div key={title} style={{background:"#080b12",borderRadius:7,
                      padding:"10px 12px",border:"1px solid #0078d418"}}>
                      <div style={{fontSize:16,marginBottom:4}}>{icon}</div>
                      <div style={{color:"#c8d0e0",fontSize:11,fontWeight:700,marginBottom:2}}>{title}</div>
                      <div style={{color:"#2a3a4a",fontSize:9,lineHeight:1.5}}>{desc}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Paste Area */}
              <div style={{background:"#04050a",border:"1px solid #0078d422",borderRadius:10,padding:"16px"}}>
                <div style={{color:"#0078d4",fontSize:9,letterSpacing:2,marginBottom:10}}>
                  📋 REPORT EINFÜGEN → KI ANALYSE
                </div>
                <WinReportPaste/>
              </div>
            </div>

            {/* Threat list for Windows */}
            <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:12,padding:"16px 18px"}}>
              <div style={{color:"#0078d4",fontSize:10,letterSpacing:2,marginBottom:14}}>
                🪟 WINDOWS THREAT MODULES
              </div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:10}}>
                {THREATS.filter(t=>t.platform==="windows").map(t=>(
                  <ThreatCard key={t.id} threat={t} onScan={handleScan}/>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
