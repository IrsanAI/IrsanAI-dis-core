# ╔══════════════════════════════════════════════════════════════════╗
# ║  DIS — Device Intelligence System                              ║
# ║  Windows Scout Agent v1.0                                      ║
# ║  IrsanAI Stack · github.com/IrsanAI/IrsanAI-dis-core           ║
# ╚══════════════════════════════════════════════════════════════════╝
# Run: powershell -ExecutionPolicy Bypass -File dis_scout.ps1
# Or:  Right-click → Run with PowerShell

param(
  [string]$ThreatId   = "full_scan",
  [string]$OutputDir  = "$env:USERPROFILE\DIS_Reports"
)

$TS  = Get-Date -Format "yyyyMMdd_HHmmss"
$Out = "$OutputDir\dis_windows_${ThreatId}_$TS.json"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$C = @{ Red="`e[31m"; Green="`e[32m"; Cyan="`e[36m"; Yellow="`e[33m"; Reset="`e[0m" }

Write-Host ""
Write-Host "$($C.Cyan)╔══════════════════════════════════════════════════════╗$($C.Reset)"
Write-Host "$($C.Cyan)║  🛡️  DIS Windows Scout Agent                        ║$($C.Reset)"
Write-Host "$($C.Cyan)║  IrsanAI Stack v1.0                                 ║$($C.Reset)"
Write-Host "$($C.Cyan)╚══════════════════════════════════════════════════════╝$($C.Reset)"
Write-Host ""

function safe { param($sb) try { & $sb } catch { "N/A" } }

# ── [1] SYSTEM ───────────────────────────────────────────────────────
Write-Host "$($C.Yellow)[1/7] System Info...$($C.Reset)"
$os  = Get-WmiObject Win32_OperatingSystem
$cs  = Get-WmiObject Win32_ComputerSystem
$sys = @{
  os_name        = $os.Caption
  os_version     = $os.Version
  build_number   = $os.BuildNumber
  architecture   = $os.OSArchitecture
  hostname       = $env:COMPUTERNAME
  last_boot      = $os.LastBootUpTime
  install_date   = $os.InstallDate
  total_ram_gb   = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
  cpu            = (Get-WmiObject Win32_Processor | Select-Object -First 1).Name
  uptime_hours   = [math]::Round((New-TimeSpan -Start $os.ConvertToDateTime($os.LastBootUpTime)).TotalHours, 1)
}

# ── [2] SECURITY ─────────────────────────────────────────────────────
Write-Host "$($C.Yellow)[2/7] Security Settings...$($C.Reset)"
$defender = safe { Get-MpComputerStatus | Select-Object `
  AMServiceEnabled, RealTimeProtectionEnabled,
  AntivirusSignatureLastUpdated, AntivirusSignatureVersion,
  IsTamperProtected, IoavProtectionEnabled }

$firewall = safe { Get-NetFirewallProfile | Select-Object Name, Enabled }

$sec = @{
  defender                   = $defender
  firewall_profiles          = $firewall
  uac_enabled                = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).EnableLUA
  secure_boot                = (Confirm-SecureBootUEFI -EA SilentlyContinue)
  tpm_present                = (Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -EA SilentlyContinue).IsEnabled_InitialValue
  ps_execution_policy        = (Get-ExecutionPolicy -List | ForEach-Object { "$($_.Scope): $($_.ExecutionPolicy)" }) -join "; "
  rdp_enabled                = ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -EA SilentlyContinue).fDenyTSConnections -eq 0)
  smb1_enabled               = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -EA SilentlyContinue).State
  autoplay_disabled          = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -EA SilentlyContinue).NoDriveTypeAutoRun
  pending_reboot             = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
}

# ── [3] NETWORK ──────────────────────────────────────────────────────
Write-Host "$($C.Yellow)[3/7] Network...$($C.Reset)"
$net = @{
  active_connections = (Get-NetTCPConnection -State Established -EA SilentlyContinue |
    ForEach-Object {
      $p = Get-Process -Id $_.OwningProcess -EA SilentlyContinue
      "$($p.Name):$($_.RemoteAddress):$($_.RemotePort)"
    } | Where-Object { $_ -notmatch "^(::|127\.)" } | Select-Object -First 20)
  dns_client_servers = (Get-DnsClientServerAddress -EA SilentlyContinue |
    Where-Object AddressFamily -eq 2 | Select-Object -ExpandProperty ServerAddresses | Select-Object -First 4)
  wifi_profiles      = (netsh wlan show profiles 2>$null | Select-String "Profile" | ForEach-Object { $_ -replace ".*: " })
  proxy_settings     = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue |
    Select-Object ProxyEnable, ProxyServer, AutoConfigURL)
  hosts_custom       = (Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -EA SilentlyContinue |
    Where-Object { $_ -notmatch "^#" -and $_ -match "\S" } | Select-Object -First 10)
}

# ── [4] PROCESSES & AUTORUN ──────────────────────────────────────────
Write-Host "$($C.Yellow)[4/7] Processes & Autorun...$($C.Reset)"
$procs = @{
  high_cpu_processes = (Get-Process -EA SilentlyContinue | Sort-Object CPU -Descending |
    Select-Object Name, Id, @{N='CPU';E={[math]::Round($_.CPU,1)}}, @{N='MemMB';E={[math]::Round($_.WorkingSet/1MB,1)}} |
    Select-Object -First 15)
  autorun_hklm       = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -EA SilentlyContinue)
  autorun_hkcu       = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -EA SilentlyContinue)
  scheduled_tasks    = (Get-ScheduledTask -EA SilentlyContinue |
    Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -ne "Disabled" } |
    Select-Object TaskName, TaskPath, State | Select-Object -First 20)
  suspicious_services = (Get-Service -EA SilentlyContinue |
    Where-Object { $_.Status -eq "Running" -and $_.StartType -eq "Automatic" } |
    Where-Object { $_.Name -notmatch "^(W32Time|wlan|AudioSrv|Dhcp|Dnscache|EventLog|PlugPlay|RpcSs|SamSs|Schedule|SENS|Themes|winmgmt|WSearch|WinDefend|MpsSvc|BFE|mpssvc|wscsvc|SecurityHealthService|Appinfo|CryptSvc|DPS|gpsvc|LanmanWorkstation|LanmanServer|lmhosts|netlogon|NlaSvc|nsi|ProfSvc|SessionEnv|SgrmBroker|ShellHWDetection|Spooler|StateRepository|SysMain|SystemEventsBroker|TabletInputService|TermService|TimeBrokerSvc|TrkWks|UserManager|UsoSvc|VaultSvc|WdNisSvc|WdiServiceHost|WdiSystemHost|WinHttpAutoProxySvc|wuauserv|WpnService)" } |
    Select-Object Name, DisplayName | Select-Object -First 25)
}

# ── [5] INSTALLED SOFTWARE ───────────────────────────────────────────
Write-Host "$($C.Yellow)[5/7] Installed Software...$($C.Reset)"
$sw = @{
  installed_count = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue).Count
  security_tools  = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
    Where-Object { $_.DisplayName -match "antivirus|firewall|vpn|malware|security|protect|kaspersky|norton|avast|bitdefender|malwarebytes|sentinel|crowdstrike" } |
    Select-Object DisplayName, DisplayVersion | Select-Object -First 10)
  remote_tools    = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
    Where-Object { $_.DisplayName -match "teamviewer|anydesk|vnc|rdp|remote|ultraviewer|logmein|connectwise" } |
    Select-Object DisplayName, DisplayVersion)
}

# ── [6] CERTIFICATES ────────────────────────────────────────────────
Write-Host "$($C.Yellow)[6/7] Certificates...$($C.Reset)"
$certs = @{
  user_root_certs  = (Get-ChildItem Cert:\CurrentUser\Root -EA SilentlyContinue |
    Select-Object Subject, Thumbprint, NotAfter | Select-Object -First 10)
  machine_root_count = (Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue).Count
  user_root_count    = (Get-ChildItem Cert:\CurrentUser\Root  -EA SilentlyContinue).Count
}

# ── [7] SHADOW COPIES & BACKUP ──────────────────────────────────────
Write-Host "$($C.Yellow)[7/7] Shadow Copies & Backup...$($C.Reset)"
$backup = @{
  shadow_copies_count = (Get-WmiObject Win32_ShadowCopy -EA SilentlyContinue | Measure-Object).Count
  shadow_copies       = (Get-WmiObject Win32_ShadowCopy -EA SilentlyContinue |
    Select-Object InstallDate, VolumeName | Select-Object -First 5)
  bitlocker_status    = (manage-bde -status 2>$null | Select-String "Protection Status" | Select-Object -First 3)
}

# ── BUILD REPORT ────────────────────────────────────────────────────
$report = @{
  dis_meta = @{
    version       = "1.0"
    platform      = "windows_powershell"
    generated_at  = (Get-Date -Format "o")
    threat_id     = $ThreatId
    threat_name   = "Windows Security Scan"
    severity      = "HIGH"
    llm_instruction = "Du bist IrsanAI Security Analyst. Analysiere diesen Windows Security Report. Threat-ID: $ThreatId. Beantworte auf Deutsch: 1) Kritische Sicherheitsprobleme? 2) Risk-Score 0-100. 3) Sofortmassnahmen. 4) Härtungsempfehlungen. Referenziere konkrete Werte aus dem Scan."
    dsgvo         = "Nur technische Systemmetadaten. Keine personenbezogenen Daten (keine Dokumente, Fotos, Nachrichten, Passwörter)."
  }
  system    = $sys
  security  = $sec
  network   = $net
  processes = $procs
  software  = $sw
  certificates = $certs
  backup    = $backup
} | ConvertTo-Json -Depth 6

# ── SAVE ────────────────────────────────────────────────────────────
$report | Out-File -FilePath $Out -Encoding UTF8
$sizeKB = [math]::Round((Get-Item $Out).Length / 1KB, 1)

Write-Host ""
Write-Host "$($C.Green)╔══════════════════════════════════════════════════════╗$($C.Reset)"
Write-Host "$($C.Green)║  ✅  DIS Windows Report erstellt!                   ║$($C.Reset)"
Write-Host "$($C.Green)╠══════════════════════════════════════════════════════╣$($C.Reset)"
Write-Host "$($C.Green)║  Datei : $($Out.PadRight(44))║$($C.Reset)"
Write-Host "$($C.Green)║  Größe : $("${sizeKB} KB".PadRight(44))║$($C.Reset)"
Write-Host "$($C.Green)╠══════════════════════════════════════════════════════╣$($C.Reset)"
Write-Host "$($C.Green)║  NÄCHSTE SCHRITTE:                                  ║$($C.Reset)"
Write-Host "$($C.Green)║  1. Datei öffnen: notepad $Out$($C.Reset)"
Write-Host "$($C.Green)║  2. Inhalt kopieren → DIS Dashboard → Analyse       ║$($C.Reset)"
Write-Host "$($C.Green)║  3. Oder direkt zu claude.ai hochladen              ║$($C.Reset)"
Write-Host "$($C.Green)╚══════════════════════════════════════════════════════╝$($C.Reset)"
Write-Host ""

# Auto-copy to clipboard
try {
  Get-Content $Out | Set-Clipboard
  Write-Host "$($C.Cyan)📋 Report automatisch in Zwischenablage kopiert!$($C.Reset)"
} catch {
  Write-Host "$($C.Yellow)→ Manuell kopieren: Get-Content '$Out' | Set-Clipboard$($C.Reset)"
}

# Open file location
try {
  explorer.exe /select,"$Out"
} catch {}
