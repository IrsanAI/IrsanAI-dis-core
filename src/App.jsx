import { useState, useEffect, useCallback } from "react";
import { detectEnvironment, detectEnvironmentSync, ENV_TYPES } from "./utils/envDetector.js";
import { buildRobustScript } from "./utils/scriptBuilder.js";
import { safeClipboardWrite, safeJsonParse, buildClaudeExport, info, warn } from "./utils/helpers.js";

// ╔══════════════════════════════════════════════════════════════════╗
// ║  DIS — Device Intelligence System v1.1                         ║
// ║  Auto-OS-Detect · Anti-Surveillance · LLM-Native               ║
// ║  IrsanAI Stack · github.com/IrsanAI/IrsanAI-dis-core           ║
// ╚══════════════════════════════════════════════════════════════════╝

const SEV     = { CRITICAL:"#ff2d55", HIGH:"#ff9500", MEDIUM:"#f7c07e", LOW:"#30d158", SAFE:"#00c7be" };
const SEV_BG  = { CRITICAL:"#1a0508", HIGH:"#1a0e00", MEDIUM:"#1a1500", LOW:"#001a08", SAFE:"#001a1a" };
const OS_CLR  = { android:"#30d158", ios:"#60b4ff", windows:"#0078d4",
                  linux:"#ff9472", macos:"#ff9500", termux:"#30d158", unknown:"#888" };

// ── THREATS ───────────────────────────────────────────────────────
const THREATS = [
  { id:"sim_swap", cat:"surveillance", name:"SIM-Swap Detection", icon:"📵",
    sev:"CRITICAL", platform:"android",
    desc:"Carrier-Übernahme deiner Nummer → 2FA-Bypass → Account-Takeover in Minuten",
    indicators:["Netz-Verlust ohne Grund","SMS nicht empfangbar","Carrier zeigt fremde SIM","Google meldet Fremd-Login"],
    cve:["SS7-Exploit","SIM-Cloning","IMSI-Takeover"],
    fixes:["2FA auf Authenticator-App umstellen (nie SMS)","Carrier: SIM-Lock aktivieren","Google: Backup-Phone entfernen","Passkey statt Passwort aktivieren"],
    termux:"SIM_STATE=$(getprop gsm.sim.state 2>/dev/null||echo N/A)\nSIM_OP=$(getprop gsm.operator.alpha 2>/dev/null||echo N/A)\nNET_TYPE=$(dumpsys telephony.registry 2>/dev/null|grep mNetworkType|head -1||echo N/A)\nDUAL_SIM=$(getprop ro.telephony.sim_slots.count 2>/dev/null||echo N/A)" },

  { id:"imsi_catcher", cat:"surveillance", name:"IMSI-Catcher / Stingray", icon:"📡",
    sev:"HIGH", platform:"android",
    desc:"Falsche Basisstation → Standort-Tracking + 2G-Downgrade → Gesprächsentschlüsselung",
    indicators:["2G/EDGE-Downgrade trotz 4G","Starkes Signal unbekannter Zelle","Akku-Drain ohne Nutzung","Anrufe mit Echo"],
    cve:["IMSI-Grabber","Stingray","SS7-Cell-Fake"],
    fixes:["VoLTE aktivieren (verhindert 2G-Downgrade)","4G/5G Only in Entwickleroptionen","Signal-App für Kommunikation","Risikogebiet: Flugmodus"],
    termux:"NET_TYPE=$(dumpsys telephony.registry 2>/dev/null|grep mNetworkType|head -3||echo N/A)\nSIGNAL=$(dumpsys telephony.registry 2>/dev/null|grep mSignalStrength|head -1||echo N/A)\nIMS_REG=$(dumpsys ims 2>/dev/null|grep -E 'isRegistered|regState'|head -3||echo N/A)\nMCC=$(getprop gsm.operator.numeric 2>/dev/null|cut -c1-3||echo N/A)" },

  { id:"stalkerware", cat:"surveillance", name:"Stalkerware Deep Scan", icon:"🔬",
    sev:"CRITICAL", platform:"android",
    desc:"Unsichtbare APK — Mikrofon/GPS/SMS live zum Angreifer. Installiert mit physischem Zugriff.",
    indicators:["Akku-Drain ohne Grund","Datenverbrauch hoch","Gerät warm ohne Nutzung","Fremder kennt private Infos"],
    cve:["FlexiSpy","mSpy","Cerberus-RAT","AndroRAT","AhMyth"],
    fixes:["Device-Admin-Apps prüfen: Einstellungen → Sicherheit","Unbekannte Accessibility Services deaktivieren","Factory Reset wenn bestätigt","Knox-aktivierter Neuaufbau"],
    termux:"DEV_ADMINS=$(dumpsys device_policy 2>/dev/null|grep -oP 'com\\.[a-zA-Z0-9._]+'|sort -u||echo none)\nACCESSIBILITY=$(settings get secure enabled_accessibility_services 2>/dev/null||echo N/A)\nNOTIF_LISTEN=$(settings get secure enabled_notification_listeners 2>/dev/null||echo N/A)\nWAKELOCKS=$(dumpsys power 2>/dev/null|grep PARTIAL_WAKE_LOCK|grep -oP 'com\\.[a-zA-Z0-9._]+'|sort|uniq -c|sort -rn|head -10||echo N/A)\nOVERLAY=$(dumpsys window 2>/dev/null|grep TYPE_APPLICATION_OVERLAY|grep -oP 'com\\.[a-zA-Z0-9._]+'|sort -u|head -10||echo none)" },

  { id:"phone_clone", cat:"surveillance", name:"Phone Clone / Mirror", icon:"👥",
    sev:"CRITICAL", platform:"android",
    desc:"Physischer ADB-Zugriff → Backup-Extraktion → identisches Gerät beim Angreifer",
    indicators:["Nachrichten gelesen ohne Wissen","Fotos in Cloud die du nicht machtest","Fremdes Gerät in Google/Samsung","ADB war aktiviert"],
    cve:["ADB-Backup-Exploit","Samsung-Cloud-Mirror"],
    fixes:["ADB sofort deaktivieren","Developer Options ausschalten","Google: myaccount.google.com/device-activity","Samsung: Find My Mobile → Geräte-Liste"],
    termux:"ADB_EN=$(settings get global adb_enabled 2>/dev/null||echo N/A)\nADB_TCP=$(getprop service.adb.tcp.port 2>/dev/null||echo N/A)\nUSB_CFG=$(getprop sys.usb.config 2>/dev/null||echo N/A)\nBACKUP_EN=$(settings get secure backup_enabled 2>/dev/null||echo N/A)\nUSB_STATE=$(getprop sys.usb.state 2>/dev/null||echo N/A)" },

  { id:"mitm", cat:"surveillance", name:"MITM / Netzwerk-Interception", icon:"🕸️",
    sev:"HIGH", platform:"android",
    desc:"Evil-Twin WLAN · Root-Zertifikat · DNS-Hijacking · Malicious VPN",
    indicators:["User-Zertifikate installiert","Unbekannte VPN läuft","HTTP-Proxy gesetzt","DNS auf fremde IPs"],
    cve:["Evil-Twin-AP","SSL-Strip","DNS-Hijack","Rogue-CA"],
    fixes:["User-Zertifikate löschen: Einstellungen → Sicherheit","Private DNS: dns.google oder 1.1.1.1","Vertrauenswürdiges VPN (ProtonVPN/Mullvad)","WLAN Auto-Connect deaktivieren"],
    termux:"USER_CERTS=$(ls /data/misc/user/0/cacerts-added/ 2>/dev/null|wc -l||echo 0)\nPROXY=$(settings get global global_http_proxy 2>/dev/null||echo N/A)\nPRIV_DNS=$(settings get global private_dns_mode 2>/dev/null||echo N/A)\nALWAYS_VPN=$(settings get secure always_on_vpn_app 2>/dev/null||echo N/A)" },

  { id:"patch_status", cat:"os", name:"Security Patch Status", icon:"📋",
    sev:"HIGH", platform:"android",
    desc:"Patch-Level vs. aktuelle Samsung/Google CVE-Bulletins — Zero-Day-Risiko",
    indicators:["Patch > 60 Tage = Warnung","Patch > 90 Tage = Kritisch","Bekannte CVEs ungepatcht"],
    cve:["Samsung-SVE-Bulletins","Google-Android-Bulletins"],
    fixes:["Einstellungen → Software-Update → Herunterladen","Knox Auto-Update aktivieren","Samsung Members: Sicherheits-Bulletins"],
    termux:"PATCH=$(getprop ro.build.version.security_patch 2>/dev/null||echo N/A)\nBUILD=$(getprop ro.build.display.id 2>/dev/null||echo N/A)\nONEUI=$(getprop ro.build.version.oneui 2>/dev/null||echo N/A)\nBASEBAND=$(getprop gsm.version.baseband 2>/dev/null||echo N/A)" },

  { id:"knox_integrity", cat:"os", name:"Knox / Boot Integrity", icon:"🔐",
    sev:"HIGH", platform:"android",
    desc:"Verified Boot · Knox Warranty · SELinux · dm-verity",
    indicators:["warranty_bit=1 Knox dauerhaft void","SELinux Permissive","Verified Boot nicht GREEN"],
    cve:["Knox-Bypass","SELinux-Exploit","dm-verity-Bypass"],
    fixes:["warranty_bit=1: Nicht reparierbar — Gerät tauschen für Banking","SELinux Permissive: Stock ROM flashen","Verified Boot: Odin Stock Recovery"],
    termux:"WARRANTY=$(getprop ro.boot.warranty_bit 2>/dev/null||echo N/A)\nBOOT_ST=$(getprop ro.boot.verifiedbootstate 2>/dev/null||echo N/A)\nTIMA=$(getprop ro.tima.version 2>/dev/null||echo N/A)\nBUILD_TAGS=$(getprop ro.build.tags 2>/dev/null||echo N/A)" },

  { id:"win_rat", cat:"windows", name:"Windows RAT / Backdoor", icon:"🐀",
    sev:"CRITICAL", platform:"windows",
    desc:"Remote-Access-Trojaner · versteckte RDP · PowerShell-Backdoor · Scheduled Tasks",
    indicators:["Unbekannte Prozesse mit Netzwerk","RDP offen","PowerShell Unrestricted","Unbekannte Scheduled Tasks"],
    cve:["Cobalt-Strike","QuasarRAT","AsyncRAT","njRAT"],
    fixes:["RDP deaktivieren wenn nicht gebraucht","PS ExecutionPolicy: RemoteSigned setzen","Windows Defender vollständiger Scan","Suspicious Tasks löschen"],
    powershell:"$r = @{}\n$r.connections = Get-NetTCPConnection -State Established -EA SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -EA SilentlyContinue; \"$($p.Name):$($_.RemoteAddress):$($_.RemotePort)\" } | Where-Object { $_ -notmatch '^(::|127\\.)' } | Select-Object -First 20\n$r.tasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskPath -notmatch 'Microsoft' } | Select-Object TaskName,State | Select-Object -First 20\n$r.rdp = ((Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -EA SilentlyContinue).fDenyTSConnections -eq 0)\n$r.ps_policy = Get-ExecutionPolicy" },

  { id:"win_ransomware", cat:"windows", name:"Ransomware Indicators", icon:"💰",
    sev:"CRITICAL", platform:"windows",
    desc:"Datei-Verschlüsselung · Shadow-Copy-Deletion · Lateral Movement",
    indicators:["VSS Shadow Copies gelöscht","Massenhaft File-Writes","vssadmin.exe unerwartet","Unbekannte SYSTEM-Dienste"],
    cve:["WannaCry","LockBit","BlackCat","Conti","REvil"],
    fixes:["Sofort Offline: Netzwerk trennen","Shadow Copies sichern","Windows Defender Offline Scan","Backup wiederherstellen"],
    powershell:"$r = @{}\n$r.shadow_count = (Get-WmiObject Win32_ShadowCopy -EA SilentlyContinue | Measure-Object).Count\n$r.defender = Get-MpComputerStatus -EA SilentlyContinue | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated" },

  { id:"linux_rootkit", cat:"linux", name:"Linux Rootkit Detection", icon:"🌱",
    sev:"CRITICAL", platform:"linux",
    desc:"Kernel-Rootkit · LD_PRELOAD-Hijack · Hidden Processes · Cron-Backdoor",
    indicators:["Prozesse in /proc die ps nicht zeigt","Unbekannte Kernel-Module","ld.so.preload hat Einträge","Unbekannte Cron-Jobs"],
    cve:["Diamorphine","Reptile","Azazel","Necurs"],
    fixes:["rkhunter --check --sk ausführen","chkrootkit ausführen","/etc/ld.so.preload leeren wenn verdächtig","Kernel-Update: apt upgrade"],
    bash:"echo '[1] Kernel Modules'\nMODS=$(lsmod 2>/dev/null|grep -vE '^(Module|bridge|xt_|nf_|ip_|veth|tun|loop|dm_|ext4|usb|pci|drm|e1000|cfg80211)'|awk '{print $1}'|tr '\\n' ',')\necho '[2] LD_PRELOAD'\nLD_PRE=$(cat /etc/ld.so.preload 2>/dev/null||echo empty)\necho '[3] SUID outside standard'\nSUID=$(find / -perm -4000 2>/dev/null|grep -vE '^/(bin|usr/bin|usr/sbin|sbin|usr/lib)'|tr '\\n' ',')\necho '[4] Open listeners'\nLISTEN=$(ss -tlnp 2>/dev/null|grep -v '127\\|::1'|tail -n +2)" },
];

// ── CLAUDE ANALYSIS ───────────────────────────────
async function analyzeWithClaude(report, threat) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514", max_tokens: 1000,
      messages: [{ role: "user", content:
        "IrsanAI Security Analyst. JSON only, no markdown:\n" +
        "{\n" +
        '  "threat_active": true,\n' +
        '  "confidence": 0,\n' +
        '  "risk_score": 0,\n' +
        '  "risk_label": "KRITISCH|HOCH|MITTEL|NIEDRIG|SICHER",\n' +
        '  "summary": "Was wurde gefunden?",\n' +
        '  "active_indicators": ["konkreter Befund"],\n' +
        '  "immediate_actions": ["Sofortmassnahme mit Befehl"],\n' +
        '  "hardening": ["Langzeit-Haertung"],\n' +
        '  "auto_fix": ["adb shell ... oder powershell ..."],\n' +
        '  "next_scan": "sofort|24h|7d|30d"\n' +
        "}\n\n" +
        "Threat: " + (threat?.name||"?") + " | Severity: " + (threat?.sev||"?") + "\n" +
        "Patterns: " + JSON.stringify(threat?.cve||[]) + "\n" +
        "Report:\n" + JSON.stringify(report, null, 2)
      }]
    })
  });
  const d = await res.json();
  return safeJsonParse((d.content||[]).map(b=>b.text||"").join(""));
}

// ── UI COMPONENTS ─────────────────────────────────
function Blink() {
  const [v,setV]=useState(true);
  useEffect(()=>{const t=setInterval(()=>setV(x=>!x),500);return()=>clearInterval(t);},[]);
  return <span style={{opacity:v?1:0,color:"#00ff9d"}}>█</span>;
}

function Pulse({color="#ff2d55"}) {
  const [s,setS]=useState(1);
  useEffect(()=>{const t=setInterval(()=>setS(x=>x===1?1.4:1),900);return()=>clearInterval(t);},[]);
  return <div style={{width:8,height:8,borderRadius:"50%",background:color,
    transform:"scale("+s+")",transition:"transform 0.4s",
    boxShadow:"0 0 8px "+color,flexShrink:0}}/>;
}

function OsDetectBanner({env}) {
  if(!env) return null;
  const c  = OS_CLR[env.client?.type] || "#888";
  const sc = OS_CLR[env.server?.osType] || "#888";
  return (
    <div style={{background:"#080b12",border:"1px solid "+c+"33",borderRadius:10,
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
          <div style={{color:"#2a3a4a",fontSize:10}}>
            {env.server?.cpus} CPUs · {env.server?.totalMemGB}GB · up {env.server?.uptime}
          </div>
        </div>
      </div>
      {env.lan?.length>0 && (
        <>
          <div style={{width:1,background:"#1a2030",alignSelf:"stretch"}}/>
          <div>
            <div style={{color:"#2a3a4a",fontSize:9,letterSpacing:2,marginBottom:4}}>LAN ACCESS</div>
            {env.lan.map(l=>(
              <div key={l.address} style={{color:"#60b4ff",fontSize:11,fontFamily:"monospace"}}>
                {l.dashboardUrl}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function ThreatCard({threat, onScan}) {
  const [exp,setExp]=useState(false);
  const c = SEV[threat.sev]||"#888";
  return (
    <div style={{background:"#080b12",border:"1px solid "+c+"22",borderRadius:10,overflow:"hidden",
      transition:"border-color 0.2s"}}
      onMouseEnter={e=>e.currentTarget.style.borderColor=c+"66"}
      onMouseLeave={e=>e.currentTarget.style.borderColor=c+"22"}>
      <div style={{padding:"14px 16px",cursor:"pointer",display:"flex",gap:12,alignItems:"flex-start"}}
        onClick={()=>setExp(x=>!x)}>
        <span style={{fontSize:20}}>{threat.icon}</span>
        <div style={{flex:1}}>
          <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
            <span style={{color:"#e2e5f0",fontWeight:700,fontSize:13}}>{threat.name}</span>
            <span style={{background:SEV_BG[threat.sev],color:c,
              border:"1px solid "+c+"44",borderRadius:4,
              padding:"1px 7px",fontSize:9,fontWeight:700,letterSpacing:1}}>{threat.sev}</span>
            <span style={{color:OS_CLR[threat.platform]||"#888",fontSize:9,fontFamily:"monospace",
              background:"#0d0f1a",border:"1px solid "+(OS_CLR[threat.platform]||"#888")+"33",
              borderRadius:4,padding:"1px 6px"}}>{threat.platform}</span>
          </div>
          <div style={{color:"#2a3a4a",fontSize:11}}>{threat.desc}</div>
        </div>
        <span style={{color:"#2a3a4a",fontSize:11}}>{exp?"▲":"▼"}</span>
      </div>
      {exp&&(
        <div style={{borderTop:"1px solid "+c+"22",padding:"14px 16px"}}>
          <div style={{marginBottom:10}}>
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
              <span key={p} style={{background:c+"18",color:c,
                border:"1px solid "+c+"33",borderRadius:4,
                padding:"2px 7px",fontSize:9,fontFamily:"monospace"}}>{p}</span>
            ))}
          </div>
          <button onClick={()=>onScan(threat)}
            style={{width:"100%",background:c+"18",border:"1px solid "+c+"55",
              color:c,borderRadius:7,padding:"10px",cursor:"pointer",
              fontFamily:"monospace",fontWeight:700,fontSize:12,letterSpacing:1}}>
            🔬 SCAN STARTEN →
          </button>
        </div>
      )}
    </div>
  );
}

function ScriptModal({script, threat, onClose}) {
  const [ok,setOk]=useState(false);
  const c = SEV[threat?.sev]||"#00ff9d";
  const copy=async()=>{
    const ok=await safeClipboardWrite(script);
    if(ok){setOk(true);setTimeout(()=>setOk(false),2200);}
  };
  return (
    <div style={{position:"fixed",inset:0,background:"#000000f0",zIndex:300,
      display:"flex",alignItems:"center",justifyContent:"center",padding:16}}>
      <div style={{background:"#06080f",border:"1px solid "+c+"44",borderRadius:14,
        maxWidth:800,width:"100%",maxHeight:"90vh",display:"flex",flexDirection:"column",
        boxShadow:"0 0 80px "+c+"18"}}>
        <div style={{padding:"14px 20px",borderBottom:"1px solid #0f1520",
          display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div>
            <div style={{color:c,fontWeight:700,fontSize:13}}>
              {threat?.icon} {threat?.name} — Scout Script
            </div>
            <div style={{color:"#2a3a4a",fontSize:10,marginTop:2}}>
              Kopieren → Terminal ausführen → JSON zurück ins Dashboard
            </div>
          </div>
          <button onClick={onClose}
            style={{background:"none",border:"none",color:"#555",cursor:"pointer",fontSize:18}}>✕</button>
        </div>
        <div style={{flex:1,overflow:"auto",padding:"16px 20px"}}>
          <pre style={{color:"#5a8a5a",fontFamily:"'Courier New',monospace",fontSize:10.5,
            lineHeight:1.7,margin:0,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{script}</pre>
        </div>
        <div style={{padding:"12px 20px",borderTop:"1px solid #0f1520",display:"flex",gap:10}}>
          <button onClick={copy}
            style={{flex:1,background:ok?"#00e5a022":"#00ff9d18",
              border:"1px solid "+(ok?"#00e5a0":"#00ff9d"),
              color:ok?"#00e5a0":"#00ff9d",borderRadius:7,padding:"11px",
              cursor:"pointer",fontFamily:"monospace",fontWeight:700,fontSize:12}}>
            {ok?"✅ KOPIERT!":"📋 SCRIPT KOPIEREN"}
          </button>
          <button onClick={onClose}
            style={{background:"#ff2d5518",border:"1px solid #ff2d55",
              color:"#ff2d55",borderRadius:7,padding:"11px 18px",
              cursor:"pointer",fontFamily:"monospace",fontWeight:700}}>✕</button>
        </div>
      </div>
    </div>
  );
}

function ExportModal({threat, rawReport, termLines, script, onClose}) {
  const [mode,setMode]=useState("preview");
  const [fmt,setFmt]=useState("markdown");
  const [ok,setOk]=useState(false);

  const mdContent   = buildClaudeExport(threat, rawReport, null, termLines, script);
  const jsonContent = JSON.stringify({
    dis_export:{
      version:"1.1",
      generated_at:new Date().toISOString(),
      threat:{id:threat?.id,name:threat?.name,severity:threat?.sev,platform:threat?.platform},
      device_report:rawReport,
      terminal_log:(termLines||[]).map(l=>l.t),
      fix_playbook:threat?.fixes,
      known_patterns:threat?.cve,
      llm_instruction:"Analyze this DIS security scan. Threat: "+(threat?.name||"?")+" on "+(rawReport?.system?.model||"?")+" Android "+(rawReport?.system?.android||"?")+" Patch: "+(rawReport?.system?.patch||"?")+" Respond in German. Risk 0-100, active findings, immediate actions, next scan script."
    }
  }, null, 2);

  const content = fmt==="json" ? jsonContent : mdContent;

  const handleCopy=async()=>{
    const copied=await safeClipboardWrite(content);
    if(copied){setOk(true);setTimeout(()=>setOk(false),2500);}
  };

  const handleDownload=()=>{
    const ext = fmt==="json" ? "json" : "md";
    const fname = "dis_claude_"+(threat?.id||"scan")+"_"+Date.now()+"."+ext;
    const blob = new Blob([content],{type:"text/plain"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href=url; a.download=fname; a.click();
    URL.revokeObjectURL(url);
    setMode("downloaded");
    setTimeout(()=>setMode("preview"),2000);
  };

  return (
    <div style={{position:"fixed",inset:0,background:"#000000f2",zIndex:400,
      display:"flex",alignItems:"center",justifyContent:"center",padding:12}}>
      <div style={{background:"#06080f",border:"1px solid #bf9ffe44",borderRadius:14,
        maxWidth:820,width:"100%",maxHeight:"92vh",display:"flex",flexDirection:"column",
        boxShadow:"0 0 80px #bf9ffe18"}}>
        <div style={{padding:"14px 18px",borderBottom:"1px solid #0f1520",
          display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div>
            <div style={{color:"#bf9ffe",fontWeight:700,fontSize:14}}>🤖 EXPORT FOR CLAUDE AI</div>
            <div style={{color:"#2a3a4a",fontSize:10,marginTop:2}}>
              Komplette Analyse-Kette → Kopieren → claude.ai einfügen oder hochladen
            </div>
          </div>
          <button onClick={onClose}
            style={{background:"none",border:"none",color:"#555",cursor:"pointer",fontSize:18}}>✕</button>
        </div>

        <div style={{padding:"12px 18px",borderBottom:"1px solid #0f1520",display:"flex",gap:8}}>
          {[["markdown","📄 Markdown","Für claude.ai Chat / File Upload"],
            ["json","{ } JSON","Für API / LLM-Integration"]].map(([val,label,desc])=>(
            <button key={val} onClick={()=>setFmt(val)}
              style={{flex:1,background:fmt===val?"#bf9ffe18":"#0a0c14",
                border:"1px solid "+(fmt===val?"#bf9ffe":"#1a2030"),
                color:fmt===val?"#bf9ffe":"#2a3a4a",borderRadius:8,
                padding:"10px 14px",cursor:"pointer",textAlign:"left",fontFamily:"monospace"}}>
              <div style={{fontSize:12,fontWeight:700,marginBottom:2}}>{label}</div>
              <div style={{fontSize:9,opacity:0.7}}>{desc}</div>
            </button>
          ))}
        </div>

        <div style={{padding:"10px 18px",borderBottom:"1px solid #0f1520",
          display:"flex",gap:14,flexWrap:"wrap"}}>
          {[["🎯","Threat",threat?.name],
            ["📱","Device",rawReport?.system?.model||"?"],
            ["🔒","Patch",rawReport?.system?.patch||rawReport?.system?.security_patch||"?"],
            ["📊","Size",Math.round(content.length/1024)+" KB"],
            ["🖥️","Terminal",(termLines?.length||0)+" lines"],
          ].map(([icon,label,val])=>(
            <div key={label} style={{display:"flex",alignItems:"center",gap:6}}>
              <span>{icon}</span>
              <div>
                <div style={{color:"#2a3a4a",fontSize:8,letterSpacing:1}}>{label}</div>
                <div style={{color:"#c8d0e0",fontSize:10,fontFamily:"monospace"}}>{val||"?"}</div>
              </div>
            </div>
          ))}
        </div>

        <div style={{flex:1,overflow:"auto",padding:"14px 18px"}}>
          <pre style={{color:"#5a7a5a",fontFamily:"'Courier New',monospace",fontSize:10,
            lineHeight:1.7,margin:0,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
            {content.slice(0,2500)}
            {content.length>2500?"\n...("+Math.round(content.length/1024)+"KB total)":""}
          </pre>
        </div>

        <div style={{padding:"14px 18px",borderTop:"1px solid #0f1520"}}>
          <div style={{background:"#0d0f1a",border:"1px solid #bf9ffe22",borderRadius:8,
            padding:"10px 14px",marginBottom:12}}>
            <div style={{color:"#bf9ffe",fontSize:9,letterSpacing:2,marginBottom:6}}>
              WIE ZU CLAUDE SCHICKEN
            </div>
            {["1. Auf KOPIEREN tippen",
              "2. claude.ai im Browser öffnen",
              "3. Neuer Chat → Text einfügen (lange drücken → Paste)",
              "4. Oder: DOWNLOAD → bei claude.ai per 📎 hochladen"
            ].map((s,i)=>(
              <div key={i} style={{color:"#4a5a6a",fontSize:11}}>{s}</div>
            ))}
          </div>
          <div style={{display:"flex",gap:10}}>
            <button onClick={handleCopy}
              style={{flex:2,background:ok?"#00e5a022":"#bf9ffe18",
                border:"1px solid "+(ok?"#00e5a0":"#bf9ffe"),
                color:ok?"#00e5a0":"#bf9ffe",
                borderRadius:8,padding:"13px",cursor:"pointer",
                fontFamily:"monospace",fontWeight:700,fontSize:13}}>
              {ok?"✅ KOPIERT — claude.ai öffnen!":"📋 KOPIEREN (Zwischenablage)"}
            </button>
            <button onClick={handleDownload}
              style={{flex:1,background:"#30d15818",border:"1px solid #30d15844",
                color:mode==="downloaded"?"#30d158":"#30d15888",
                borderRadius:8,padding:"13px",cursor:"pointer",
                fontFamily:"monospace",fontWeight:700,fontSize:12}}>
              {mode==="downloaded"?"✅ GESPEICHERT":"⬇️ DOWNLOAD"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AnalysisResult({analysis, threat}) {
  if(!analysis) return null;
  const c = SEV[analysis.risk_label]||SEV[threat?.sev]||"#888";
  return (
    <div style={{marginTop:20}}>
      <div style={{background:SEV_BG[analysis.risk_label]||"#0a0c14",
        border:"1px solid "+c+"55",borderRadius:12,padding:"16px 20px",marginBottom:14,
        display:"flex",alignItems:"center",gap:16}}>
        <div style={{textAlign:"center",minWidth:80}}>
          <div style={{color:c,fontSize:40,fontWeight:900,lineHeight:1}}>{analysis.risk_score}</div>
          <div style={{color:c,fontSize:9,letterSpacing:2,marginTop:4}}>RISK</div>
        </div>
        <div style={{flex:1,borderLeft:"1px solid "+c+"33",paddingLeft:16}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            {analysis.threat_active&&<Pulse color={c}/>}
            <span style={{color:c,fontWeight:700,fontSize:14}}>{analysis.risk_label}</span>
            <span style={{color:"#2a3a4a",fontSize:11}}>| {analysis.confidence}% Konfidenz</span>
          </div>
          <div style={{color:"#c8d0e0",fontSize:12,lineHeight:1.6}}>{analysis.summary}</div>
        </div>
      </div>

      {analysis.active_indicators?.length>0&&(
        <div style={{background:"#080b12",border:"1px solid #1a2030",borderRadius:10,
          padding:"14px 16px",marginBottom:12}}>
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
        <div style={{background:"#001a08",border:"1px solid #30d15844",borderRadius:10,
          padding:"14px 16px",marginBottom:12}}>
          <div style={{color:"#30d158",fontSize:9,letterSpacing:2,marginBottom:10}}>⚡ AUTO-FIX COMMANDS</div>
          {analysis.auto_fix.map((cmd,i)=>(
            <div key={i} style={{display:"flex",gap:8,marginBottom:6,alignItems:"center"}}>
              <code style={{flex:1,background:"#002a10",border:"1px solid #30d15822",
                borderRadius:5,padding:"5px 10px",color:"#30d158",
                fontSize:10,fontFamily:"monospace",wordBreak:"break-all"}}>{cmd}</code>
              <button onClick={()=>safeClipboardWrite(cmd)}
                style={{background:"#30d15818",border:"1px solid #30d15844",color:"#30d158",
                  borderRadius:5,padding:"5px 10px",cursor:"pointer",
                  fontSize:9,fontFamily:"monospace",flexShrink:0}}>COPY</button>
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

function ExportButton({onClick}) {
  return (
    <div style={{marginTop:20,background:"#0d0a1a",border:"1px solid #bf9ffe44",
      borderRadius:12,padding:"16px 18px"}}>
      <div style={{color:"#bf9ffe",fontSize:9,letterSpacing:2,marginBottom:8}}>
        🤖 WEITER MIT CLAUDE AI
      </div>
      <div style={{color:"#3a3a5a",fontSize:11,marginBottom:14,lineHeight:1.6}}>
        Exportiere die komplette Analyse-Kette als Paket für Claude AI.
        Kopieren → claude.ai → einfügen → tiefere Analyse anfordern.
      </div>
      <button onClick={onClick}
        style={{width:"100%",background:"#bf9ffe18",border:"1px solid #bf9ffe",
          color:"#bf9ffe",borderRadius:9,padding:"14px",cursor:"pointer",
          fontFamily:"monospace",fontWeight:700,fontSize:13,letterSpacing:1}}>
        🤖 EXPORT FÜR CLAUDE AI →
      </button>
      <div style={{display:"flex",gap:8,marginTop:8}}>
        {["📄 Markdown","{ } JSON","📋 Clipboard","⬇️ Download"].map(t=>(
          <div key={t} style={{flex:1,textAlign:"center",color:"#2a3a4a",
            fontSize:9,padding:"4px",background:"#080b12",borderRadius:5,
            border:"1px solid #1a2030"}}>{t}</div>
        ))}
      </div>
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────
export default function App() {
  const [env,setEnv]                   = useState(null);
  const [clientEnv,setClientEnv]       = useState(null);
  const [tab,setTab]                   = useState("threats");
  const [catFilter,setCatFilter]       = useState("all");
  const [platFilter,setPlatFilter]     = useState("all");
  const [activeThreat,setActiveThreat] = useState(null);
  const [script,setScript]             = useState("");
  const [showScript,setShowScript]     = useState(false);
  const [pastedJson,setPastedJson]     = useState("");
  const [parseErr,setParseErr]         = useState("");
  const [analysis,setAnalysis]         = useState(null);
  const [analyzing,setAnalyzing]       = useState(false);
  const [rawReport,setRawReport]       = useState(null);
  const [showExport,setShowExport]     = useState(false);
  const [termLines,setTermLines]       = useState([]);

  const addLine = (t,c="#7c82a8") => setTermLines(l=>[...l,{t,c}]);

  // Fetch server env + detect client env
  useEffect(()=>{
    // Client-side env detection
    detectEnvironment().then(e=>{
      setClientEnv(e);
      if(e.type!=="unknown") setPlatFilter(e.type==="termux"?"android":e.type);
    }).catch(()=>{});

    // Server env via API
    fetch("/api/env")
      .then(r=>r.json())
      .then(d=>setEnv(d))
      .catch(()=>setEnv({
        client:{type:"unknown",label:"Standalone Mode",icon:"💻",
                color:"#888",hint:"Server nicht erreichbar — Demo-Modus"},
        server:{osType:"unknown",osLabel:"Standalone",cpus:"?",totalMemGB:"?",uptime:"?"},
        lan:[]
      }));
  },[]);

  const handleScan = useCallback(async(threat)=>{
    setActiveThreat(threat);
    setAnalysis(null);
    setPastedJson("");
    setParseErr("");
    setRawReport(null);
    setTab("scan");
    setTermLines([]);

    // Use detected client env for script generation
    const envForScript = clientEnv || detectEnvironmentSync();
    // For android threats always use termux script
    const scriptEnv = threat.platform==="windows"
      ? { type: ENV_TYPES.WINDOWS_PS }
      : threat.platform==="linux"
        ? { type: ENV_TYPES.LINUX_BASH }
        : { type: ENV_TYPES.TERMUX };

    const generated = buildRobustScript(threat, scriptEnv);
    setScript(generated);

    // Terminal simulation
    setTimeout(()=>addLine("$ dis_scout --threat "+threat.id+" --v1.1","#ff2d55"),100);
    setTimeout(()=>addLine("→ "+threat.name+" | "+threat.sev,SEV[threat.sev]||"#888"),400);
    setTimeout(()=>addLine("→ Env: "+envForScript.type+" | Shell: "+envForScript.shell,"#7c82a8"),700);
    setTimeout(()=>addLine("→ Fallbacks: "+(envForScript.fallbacks||[]).join(", "),"#f7c07e"),1000);
    setTimeout(()=>addLine("✅ Script generiert ("+generated.split("\n").length+" Zeilen)","#00e5a0"),1400);

    // Auto-copy
    setTimeout(async()=>{
      const copied = await safeClipboardWrite(generated);
      if(copied) addLine("📋 Script automatisch in Zwischenablage kopiert","#30d158");
    },1800);
  },[clientEnv]);

  const handleAnalyze = useCallback(async()=>{
    setParseErr("");
    const parsed = safeJsonParse(pastedJson);
    if(!parsed){ setParseErr("❌ Kein gültiges JSON. Gesamten Report-Inhalt kopieren."); return; }
    if(!parsed.dis_meta&&!parsed.isu_meta&&!parsed.sis_meta){
      setParseErr("❌ Kein DIS-Report erkannt. Bitte Scout-Script ausführen."); return;
    }
    setRawReport(parsed);
    setTab("analyze");
    setAnalyzing(true);
    setTermLines([]);
    const sys = parsed.system||parsed.system_context||{};
    [
      ["$ dis_analyze --report <json>","#ff2d55"],
      ["→ Gerät: "+(sys.model||"?")+" | Android "+(sys.android||sys.android_version||"?"),"#60b4ff"],
      ["→ Patch: "+(sys.patch||sys.security_patch||"?"),"#f7c07e"],
      ["→ Threat: "+(parsed.dis_meta?.threat_name||parsed.isu_meta?.threat_name||"?"),"#ff9500"],
      ["→ Sende an Claude AI...","#7c82a8"],
    ].forEach(([t,c],i)=>setTimeout(()=>addLine(t,c),i*200));
    try {
      const r = await analyzeWithClaude(parsed, activeThreat);
      setAnalysis(r);
      addLine("✅ "+r.risk_label+" — Score: "+r.risk_score,"#00e5a0");
    } catch(e) {
      setParseErr("❌ KI-Fehler: "+e.message);
      setTab("scan");
    }
    setAnalyzing(false);
  },[pastedJson,activeThreat]);

  const cats  = ["all","surveillance","windows","linux","os"];
  const plats = ["all","android","windows","linux","ios"];
  const filtered = THREATS.filter(t=>
    (catFilter==="all"||t.cat===catFilter)&&
    (platFilter==="all"||t.platform===platFilter)
  );

  const TABS=[
    {id:"threats",icon:"🎯",label:"THREATS"},
    {id:"scan",   icon:"🔬",label:"SCOUT"},
    {id:"analyze",icon:"🧠",label:"ANALYSE"},
    {id:"intel",  icon:"📡",label:"INTEL"},
  ];

  return (
    <div style={{minHeight:"100vh",background:"#04050a",color:"#c8d0e0",
      fontFamily:"'Courier New',monospace",paddingBottom:60}}>

      {showScript&&(
        <ScriptModal script={script} threat={activeThreat}
          onClose={()=>setShowScript(false)}/>
      )}
      {showExport&&rawReport&&(
        <ExportModal threat={activeThreat} rawReport={rawReport}
          termLines={termLines} script={script}
          onClose={()=>setShowExport(false)}/>
      )}

      {/* Header */}
      <div style={{background:"linear-gradient(180deg,#080b14,#04050a)",
        borderBottom:"1px solid #0f1520",padding:"14px 20px 0"}}>
        <div style={{maxWidth:1100,margin:"0 auto"}}>
          <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
            <div style={{width:38,height:38,background:"#ff2d5518",
              border:"1px solid #ff2d5544",borderRadius:8,
              display:"flex",alignItems:"center",justifyContent:"center",fontSize:18}}>🛡️</div>
            <div style={{flex:1}}>
              <div style={{color:"#ff2d55",fontWeight:900,fontSize:14,letterSpacing:3}}>
                DIS — DEVICE INTELLIGENCE SYSTEM
              </div>
              <div style={{color:"#1a2a1a",fontSize:9,letterSpacing:3}}>
                IRSANAI STACK · v1.1 · AUTO-OS-DETECT · ANTI-SURVEILLANCE · LLM-NATIVE
              </div>
            </div>
            {env&&(
              <div style={{textAlign:"right"}}>
                <div style={{color:OS_CLR[env.client?.type]||"#888",fontSize:11,fontWeight:700}}>
                  {env.client?.icon} {env.client?.label}
                </div>
                <div style={{color:"#1a2a3a",fontSize:9}}>auto-detected</div>
              </div>
            )}
          </div>
          <div style={{display:"flex",gap:0}}>
            {TABS.map(t=>(
              <button key={t.id} onClick={()=>setTab(t.id)}
                style={{background:"transparent",border:"none",
                  borderBottom:"2px solid "+(tab===t.id?"#ff2d55":"transparent"),
                  color:tab===t.id?"#ff2d55":"#2a3a4a",
                  padding:"10px 16px",cursor:"pointer",
                  fontFamily:"monospace",fontSize:11,fontWeight:700,letterSpacing:1}}>
                {t.icon} {t.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div style={{maxWidth:1100,margin:"0 auto",padding:"20px 16px"}}>

        {/* THREATS TAB */}
        {tab==="threats"&&(
          <div>
            <OsDetectBanner env={env}/>
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>
              {cats.map(c=>(
                <button key={c} onClick={()=>setCatFilter(c)}
                  style={{background:catFilter===c?"#ff2d5518":"#080b12",
                    border:"1px solid "+(catFilter===c?"#ff2d55":"#1a2030"),
                    color:catFilter===c?"#ff2d55":"#2a3a4a",borderRadius:6,
                    padding:"6px 12px",cursor:"pointer",fontFamily:"monospace",
                    fontSize:10,fontWeight:700,letterSpacing:1}}>
                  {c.toUpperCase()}
                </button>
              ))}
              <div style={{width:1,background:"#1a2030",margin:"0 4px"}}/>
              {plats.map(p=>(
                <button key={p} onClick={()=>setPlatFilter(p)}
                  style={{background:platFilter===p?(OS_CLR[p]||"#888")+"18":"#080b12",
                    border:"1px solid "+(platFilter===p?OS_CLR[p]||"#888":"#1a2030"),
                    color:platFilter===p?OS_CLR[p]||"#888":"#2a3a4a",borderRadius:6,
                    padding:"6px 12px",cursor:"pointer",fontFamily:"monospace",
                    fontSize:10,fontWeight:700}}>
                  {p.toUpperCase()}
                </button>
              ))}
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:12}}>
              {filtered.map(t=><ThreatCard key={t.id} threat={t} onScan={handleScan}/>)}
            </div>
          </div>
        )}

        {/* SCOUT TAB */}
        {tab==="scan"&&(
          <div>
            {!activeThreat?(
              <div style={{textAlign:"center",padding:"60px 20px",color:"#2a3a4a"}}>
                <div style={{fontSize:40,marginBottom:12}}>🔬</div>
                <div>THREATS → Bedrohung wählen → SCAN STARTEN</div>
              </div>
            ):(
              <>
                <div style={{background:"#080b12",
                  border:"1px solid "+(SEV[activeThreat.sev]||"#888")+"33",
                  borderRadius:10,padding:"12px 16px",marginBottom:16,
                  display:"flex",alignItems:"center",gap:12}}>
                  <span style={{fontSize:22}}>{activeThreat.icon}</span>
                  <div style={{flex:1}}>
                    <div style={{color:"#e2e5f0",fontWeight:700}}>{activeThreat.name}</div>
                    <div style={{color:SEV[activeThreat.sev],fontSize:10}}>{activeThreat.sev}</div>
                  </div>
                  {clientEnv&&(
                    <div style={{color:OS_CLR[clientEnv.type]||"#888",fontSize:10,
                      fontFamily:"monospace",textAlign:"right"}}>
                      <div>{clientEnv.type}</div>
                      <div style={{color:"#2a3a4a"}}>{clientEnv.interpreter}</div>
                    </div>
                  )}
                </div>

                <div style={{background:"#030508",border:"1px solid #0f1520",
                  borderRadius:10,padding:"14px 16px",marginBottom:16}}>
                  <div style={{display:"flex",gap:5,marginBottom:8}}>
                    {["#ff5f56","#ffbd2e","#27c93f"].map(c=>(
                      <div key={c} style={{width:8,height:8,borderRadius:"50%",background:c}}/>
                    ))}
                  </div>
                  {termLines.map((l,i)=>(
                    <div key={i} style={{color:l.c,fontSize:11,lineHeight:1.65}}>{l.t}</div>
                  ))}
                  <Blink/>
                </div>

                <div style={{background:"#030508",border:"1px solid #0f1520",
                  borderRadius:10,overflow:"hidden",marginBottom:16}}>
                  <div style={{padding:"8px 14px",borderBottom:"1px solid #0f1520",
                    display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <span style={{color:"#1a2a3a",fontSize:9}}>
                      dis_scout_{activeThreat.id}{clientEnv?.scriptExt||".sh"} — {script.split("\n").length} Zeilen
                    </span>
                    <button onClick={()=>setShowScript(true)}
                      style={{background:"#60b4ff18",border:"1px solid #60b4ff44",
                        color:"#60b4ff",borderRadius:5,padding:"4px 12px",
                        cursor:"pointer",fontFamily:"monospace",fontSize:9,fontWeight:700}}>
                      VOLLBILD
                    </button>
                  </div>
                  <pre style={{color:"#2a4a2a",fontFamily:"monospace",fontSize:10,lineHeight:1.6,
                    margin:0,padding:"12px 14px",maxHeight:160,overflow:"auto",whiteSpace:"pre-wrap"}}>
                    {script.slice(0,600)}...
                  </pre>
                </div>

                <div style={{display:"flex",gap:10}}>
                  <button onClick={()=>{safeClipboardWrite(script);setShowScript(true);}}
                    style={{flex:1,background:"#00ff9d18",border:"1px solid #00ff9d55",
                      color:"#00ff9d",borderRadius:7,padding:"12px",cursor:"pointer",
                      fontFamily:"monospace",fontWeight:700,fontSize:12}}>
                    📋 SCRIPT KOPIEREN
                  </button>
                  <button onClick={()=>setTab("analyze")}
                    style={{flex:1,background:"#ff2d5518",border:"1px solid #ff2d5555",
                      color:"#ff2d55",borderRadius:7,padding:"12px",cursor:"pointer",
                      fontFamily:"monospace",fontWeight:700,fontSize:12}}>
                    → ANALYSE
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {/* ANALYSE TAB */}
        {tab==="analyze"&&(
          <div>
            {!activeThreat?(
              <div style={{textAlign:"center",padding:"60px 20px",color:"#2a3a4a"}}>
                <div style={{fontSize:40,marginBottom:12}}>🧠</div>
                <div>Erst Scout-Script ausführen (THREATS → SCAN STARTEN)</div>
              </div>
            ):(
              <>
                <div style={{color:"#2a3a4a",fontSize:11,marginBottom:12}}>
                  Scout ausführen →{" "}
                  <code style={{color:"#60b4ff"}}>cat ~/dis_*.json</code>
                  {" "}→ hier einfügen → Analysieren.
                  Oder: JSON direkt zu{" "}
                  <span style={{color:"#bf9ffe"}}>claude.ai</span> — das{" "}
                  <code style={{color:"#bf9ffe"}}>llm_instruction</code> Feld erklärt alles.
                </div>

                <textarea value={pastedJson}
                  onChange={e=>{setPastedJson(e.target.value);setParseErr("");}}
                  placeholder='{ "dis_meta": { "threat_id": "...", "platform": "termux_android" }, "system": { ... } }'
                  style={{width:"100%",minHeight:180,background:"#030508",
                    border:"1px solid "+(parseErr?"#ff2d5544":"#1a2030"),
                    borderRadius:10,padding:"14px",color:"#5a8a5a",fontFamily:"monospace",
                    fontSize:11,resize:"vertical",outline:"none",
                    boxSizing:"border-box",lineHeight:1.6,marginBottom:8}}/>

                {parseErr&&(
                  <div style={{color:"#ff2d55",fontSize:11,padding:"8px 12px",
                    background:"#140507",borderRadius:6,marginBottom:10}}>{parseErr}</div>
                )}

                {termLines.length>0&&(
                  <div style={{background:"#030508",border:"1px solid #0f1520",
                    borderRadius:10,padding:"14px 16px",marginBottom:14}}>
                    {termLines.map((l,i)=>(
                      <div key={i} style={{color:l.c,fontSize:11,lineHeight:1.65}}>{l.t}</div>
                    ))}
                    {analyzing&&<Blink/>}
                  </div>
                )}

                {!analysis&&(
                  <button onClick={handleAnalyze}
                    disabled={!pastedJson.trim()||analyzing}
                    style={{width:"100%",
                      background:pastedJson.trim()?"#ff2d5518":"#0a0c14",
                      border:"1px solid "+(pastedJson.trim()?"#ff2d5555":"#1a2030"),
                      color:pastedJson.trim()?"#ff2d55":"#333",
                      borderRadius:7,padding:"13px",
                      cursor:pastedJson.trim()?"pointer":"not-allowed",
                      fontFamily:"monospace",fontWeight:700,fontSize:13}}>
                    {analyzing?"⏳ CLAUDE ANALYSIERT...":"🧠 MIT CLAUDE AI ANALYSIEREN →"}
                  </button>
                )}

                <AnalysisResult analysis={analysis} threat={activeThreat}/>
                {analysis&&<ExportButton onClick={()=>setShowExport(true)}/>}
              </>
            )}
          </div>
        )}

        {/* INTEL TAB */}
        {tab==="intel"&&(
          <div>
            <OsDetectBanner env={env}/>

            <div style={{background:"#080b12",border:"1px solid #ff2d5522",
              borderRadius:12,padding:"20px",marginBottom:16}}>
              <div style={{color:"#ff2d55",fontSize:10,letterSpacing:2,marginBottom:16}}>
                IRSANAI DIS STACK — ARCHITEKTUR v1.1
              </div>
              {[
                ["LAYER 4","INTELLIGENCE","Claude AI · CVE Matching · Zero-Day · Pattern Recognition","#ff2d55"],
                ["LAYER 3","CONTROL CENTER","React Dashboard · Auto-OS-Detect · WebSocket · LAN-Discovery","#ff9500"],
                ["LAYER 2","SCOUT AGENTS","Termux · PowerShell · Bash · ADB · iOS Shortcuts","#00c7be"],
                ["LAYER 1","SENSORS","Android · iPhone · Windows · Linux · Router · IoT","#30d158"],
              ].map(([l,n,d,c])=>(
                <div key={l} style={{display:"flex",gap:14,marginBottom:10,
                  padding:"10px 14px",background:"#04050a",
                  borderRadius:8,border:"1px solid "+c+"22"}}>
                  <div style={{color:c,fontSize:9,fontWeight:700,letterSpacing:1,
                    minWidth:55,paddingTop:2}}>{l}</div>
                  <div>
                    <div style={{color:c,fontSize:12,fontWeight:700,marginBottom:2}}>{n}</div>
                    <div style={{color:"#2a3a4a",fontSize:11}}>{d}</div>
                  </div>
                </div>
              ))}
            </div>

            <div style={{background:"#080b12",border:"1px solid #1a2030",
              borderRadius:12,padding:"20px",marginBottom:16}}>
              <div style={{color:"#30d158",fontSize:10,letterSpacing:2,marginBottom:12}}>
                🚀 QUICK START
              </div>
              {[
                ["Clone","git clone https://github.com/IrsanAI/IrsanAI-dis-core"],
                ["Install","cd IrsanAI-dis-core && npm install"],
                ["Build","npm run build"],
                ["Start","node server.js"],
                ["Open","http://localhost:3001"],
              ].map(([k,v])=>(
                <div key={k} style={{display:"flex",gap:12,marginBottom:8,alignItems:"center"}}>
                  <span style={{color:"#2a3a4a",fontSize:10,minWidth:60}}>{k}</span>
                  <code style={{color:"#30d158",fontSize:11,background:"#001a08",
                    border:"1px solid #30d15822",borderRadius:5,padding:"3px 10px",
                    flex:1,wordBreak:"break-all"}}>{v}</code>
                  <button onClick={()=>safeClipboardWrite(v)}
                    style={{background:"none",border:"1px solid #1a2030",color:"#2a3a4a",
                      borderRadius:5,padding:"3px 8px",cursor:"pointer",
                      fontSize:9,fontFamily:"monospace"}}>COPY</button>
                </div>
              ))}
            </div>

            <div style={{background:"#080b12",border:"1px solid #1a2030",
              borderRadius:12,padding:"16px 20px"}}>
              <div style={{color:"#60b4ff",fontSize:10,letterSpacing:2,marginBottom:12}}>
                THREAT MATRIX — {THREATS.length} MODULE
              </div>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                  <thead>
                    <tr style={{borderBottom:"1px solid #1a2030"}}>
                      {["Threat","Severity","Platform","CVEs"].map(h=>(
                        <th key={h} style={{textAlign:"left",padding:"6px 12px",
                          color:"#2a3a4a",fontSize:9,letterSpacing:1}}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {THREATS.map(t=>(
                      <tr key={t.id}
                        onClick={()=>{handleScan(t);setTab("scan");}}
                        style={{borderBottom:"1px solid #0f1520",cursor:"pointer"}}
                        onMouseEnter={e=>e.currentTarget.style.background="#0d1018"}
                        onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                        <td style={{padding:"7px 12px"}}>
                          <span style={{marginRight:6}}>{t.icon}</span>
                          <span style={{color:"#c8d0e0"}}>{t.name}</span>
                        </td>
                        <td style={{padding:"7px 12px"}}>
                          <span style={{color:SEV[t.sev]||"#888",fontSize:10,fontWeight:700}}>
                            {t.sev}
                          </span>
                        </td>
                        <td style={{padding:"7px 12px",
                          color:OS_CLR[t.platform]||"#888",fontSize:10,fontFamily:"monospace"}}>
                          {t.platform}
                        </td>
                        <td style={{padding:"7px 12px",color:"#2a3a4a",fontSize:10}}>
                          {t.cve.slice(0,2).join(", ")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
