<#
.SYNOPSIS
WinSentry v1 - Local Windows Security Posture Auditor

.DESCRIPTION
A read-only, zero-network-footprint security auditor for Windows.
Collects state on Defender, Remote Access, Network, Persistence, Accounts, and Patching.
Generates winsentry_report.json and a SHA-256 sidecar file.

SECURITY NOTE:
This script performs NO network calls, process injection, or state mutation.
For network-based hash lookups, use the standalone winsentry-lookup.ps1 manually.
For distribution, it is highly recommended to sign this script with Set-AuthenticodeSignature.

.PARAMETER CompareTo
Optional path to a prior winsentry_report.json file to generate a diff in the output.

.EXAMPLE
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\WinSentry.ps1
.\WinSentry.ps1 -CompareTo "C:\path\to\old_winsentry_report.json"
#>
param(
    [string]$CompareTo = "",
    [string]$Password = "",
    [switch]$NoPrompt = $false
)

# WinSentry v1 (Secure PDF Generation)
# Author: Akul Attre

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "         WinSentry v1 - Scanner          " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

if ($Password) {
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
} elseif ($NoPrompt) {
    $Password = "WinSentry2026!"
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
} else {
    $securePassword = Read-Host "Enter a password to encrypt the PDF report" -AsSecureString
}

if (-not $securePassword -or $securePassword.Length -eq 0) {
    Write-Error "Password is required for PDF encryption."
    exit
}

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Enforce Self-Targeting: Implicitly local by design (no -ComputerName parameters used).

# --- Configuration & Helpers ---

$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

$ScoringWeights = [ordered]@{
    "_comment" = "Published alongside every report so the 0-100 score is auditable. Define per-module max-contribution weights here:"
    "defender_health" = 20
    "remote_access" = 15
    "network" = 15
    "persistence" = 15
    "accounts" = 10
    "patching" = 5
    "defender_activity" = 5
    "system_health" = 5
    "behavioral_analysis" = 10
}

# Common System Process Names for Typosquat Detection
$SystemProcesses = @(
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe", 
    "services.exe", "spoolsv.exe", "taskhostw.exe", "smss.exe", "wininit.exe",
    "conhost.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "taskmgr.exe"
)

# Helper: Edit Distance (Levenshtein)
function Get-EditDistance {
    param([string]$s1, [string]$s2)
    $s1 = $s1.ToLowerInvariant()
    $s2 = $s2.ToLowerInvariant()
    $len1 = $s1.Length
    $len2 = $s2.Length
    $d = New-Object 'int[,]' ($len1 + 1), ($len2 + 1)
    for ($i = 0; $i -le $len1; $i++) { $d[$i, 0] = $i }
    for ($j = 0; $j -le $len2; $j++) { $d[0, $j] = $j }
    for ($i = 1; $i -le $len1; $i++) {
        for ($j = 1; $j -le $len2; $j++) {
            $cost = if ($s1[$i - 1] -eq $s2[$j - 1]) { 0 } else { 1 }
            $i1 = $i - 1
            $j1 = $j - 1
            $min1 = $d[$i1, $j] + 1
            $min2 = $d[$i, $j1] + 1
            $min3 = $d[$i1, $j1] + $cost
            $tempMin = [Math]::Min($min1, $min2)
            $d[$i, $j] = [Math]::Min($tempMin, $min3)
        }
    }
    return $d[$len1, $len2]
}

# Helper: Truncate string
function Truncate-String {
    param([string]$str, [int]$maxLength = 1000)
    if ([string]::IsNullOrEmpty($str)) { return "" }
    if ($str.Length -gt $maxLength) { return $str.Substring(0, $maxLength) + "..." }
    return $str
}

# Helper: Create finding
function New-Finding {
    param(
        [string]$Id,
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$Recommendation,
        [string]$RemediationCommand = $null,
        [string]$SignatureStatus = $null,
        [string]$SignerSubject = $null,
        [string]$LookalikeMatch = $null
    )
    $finding = [ordered]@{
        id = $Id
        severity = $Severity
        title = Truncate-String $Title
        detail = Truncate-String $Detail
        recommendation = Truncate-String $Recommendation
    }
    if ($null -ne $RemediationCommand) { $finding["remediation_command"] = $RemediationCommand }
    if ($null -ne $SignatureStatus) { $finding["signature_status"] = $SignatureStatus }
    if ($null -ne $SignerSubject)   { $finding["signer_subject"] = $SignerSubject }
    if ($null -ne $LookalikeMatch)  { $finding["lookalike_match"] = $LookalikeMatch }
    return $finding
}

# Helper: Extract executable path from a command-line string
function Get-ExecutableFromCommandLine {
    param([string]$CmdLine)
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return $null }
    $trimmed = $CmdLine.Trim()
    if ($trimmed -match '^"([^"]+\.exe)"') {
        return $matches[1]
    } elseif ($trimmed -match '(?i)^([a-zA-Z]:\\[^"]+?\.exe)(?:\s.*)?$') {
        return $matches[1]
    } elseif ($trimmed -match '(?i)^(%[^%]+%\\.+?\.exe)(?:\s.*)?$') {
        return $matches[1]
    } elseif ($trimmed -match '(?i)^(\\\\.+?\.exe)(?:\s.*)?$') {
        return $matches[1]
    } elseif ($trimmed -match '^([^\s]+\.exe)') {
        return $matches[1]
    }
    return $null
}

# Helper: Analyze Binary (Signature, Masquerading & Typosquat)
function Analyze-Binary {
    param([string]$Path)
    
    $result = @{
        SignatureStatus = "Unknown"
        SignerSubject = $null
        LookalikeMatch = $null
        BumpSeverity = $false
        IsHighSeverity = $false
    }
    
    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    
    # Strip enclosing quotes and expand environment variables
    $cleanPath = $Path.Trim().Trim('"', "'")
    $cleanPath = [Environment]::ExpandEnvironmentVariables($cleanPath)
    
    if (-not (Test-Path -LiteralPath $cleanPath -PathType Leaf)) { return $result }
    
    try {
        $item = Get-Item -LiteralPath $cleanPath -ErrorAction Stop
        $resolvedPath = $item.FullName
    } catch {
        return $result
    }
    
    $fileName = [System.IO.Path]::GetFileName($resolvedPath)
    $sys32Dir = "$env:SystemRoot\System32\"
    $sysWow64Dir = "$env:SystemRoot\SysWOW64\"
    $isOutsideSystem32 = (-not $resolvedPath.StartsWith($sys32Dir, [System.StringComparison]::InvariantCultureIgnoreCase)) -and
                         (-not $resolvedPath.StartsWith($sysWow64Dir, [System.StringComparison]::InvariantCultureIgnoreCase))
    
    # 1. Signature Check
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $resolvedPath -ErrorAction SilentlyContinue
        if ($sig) {
            $result.SignatureStatus = $sig.Status.ToString()
            if ($sig.SignerCertificate) {
                $result.SignerSubject = $sig.SignerCertificate.Subject
            }
            if ($sig.Status -ne 'Valid' -and $isOutsideSystem32) {
                # Only bump if it's not a known Microsoft signed binary
                if (-not ($result.SignerSubject -match "O=Microsoft Corporation")) {
                    $result.BumpSeverity = $true
                }
            }
        } else {
            $result.SignatureStatus = "NotSigned"
            if ($isOutsideSystem32) { $result.BumpSeverity = $true }
        }
    } catch {
        $result.SignatureStatus = "Error"
    }

    # 2. Masquerading & Typosquat Check
    if ($isOutsideSystem32) {
        foreach ($sysProc in $SystemProcesses) {
            if ($fileName -ieq $sysProc) {
                # Exact match outside system directories is a critical masquerading threat
                $result.LookalikeMatch = "$sysProc (Masquerading)"
                $result.IsHighSeverity = $true
                break
            }
            
            # Edit distance check: threshold is 1 for short names, 2 for longer names
            $baseProc = [System.IO.Path]::GetFileNameWithoutExtension($sysProc)
            $maxDist = if ($baseProc.Length -le 4) { 1 } else { 2 }
            $dist = Get-EditDistance -s1 $fileName -s2 $sysProc
            if ($dist -le $maxDist) {
                $result.LookalikeMatch = $sysProc
                $result.IsHighSeverity = $true
                break
            }
        }
    }
    
    return $result
}

# --- Module Implementations ---

$Modules = [ordered]@{
    defender_health = @{ status = "ok"; findings = @() }
    remote_access = @{ status = "ok"; findings = @() }
    network = @{ status = "ok"; findings = @() }
    persistence = @{ status = "ok"; findings = @() }
    accounts = @{ status = "ok"; findings = @() }
    patching = @{ status = "ok"; findings = @() }
    defender_activity = @{ status = "ok"; findings = @() }
    system_health = @{ status = "ok"; findings = @() }
    behavioral_analysis = @{ status = "ok"; findings = @() }
}

# 1. Defender Health
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $mpPref = Get-MpPreference -ErrorAction Stop
    
    if (-not $mpStatus.RealTimeProtectionEnabled) {
        $Modules.defender_health.findings += New-Finding -Id "DEF-01" -Severity "CRITICAL" -Title "Real-Time Protection Disabled" -Detail "Defender Real-Time Protection is off." -Recommendation "Enable Real-Time Protection immediately." -RemediationCommand "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    if (-not $mpStatus.IsTamperProtected) {
        $Modules.defender_health.findings += New-Finding -Id "DEF-02" -Severity "HIGH" -Title "Tamper Protection Disabled" -Detail "Defender Tamper Protection is not active." -Recommendation "Enable Tamper Protection to prevent malware from disabling Defender." -RemediationCommand "Set-MpPreference -DisableTamperProtection `$false"
    }
    
    $sigAge = (Get-Date) - $mpStatus.AntispywareSignatureLastUpdated
    if ($sigAge.TotalDays -gt 7) {
        $Modules.defender_health.findings += New-Finding -Id "DEF-03" -Severity "MEDIUM" -Title "Outdated Signatures" -Detail "Defender signatures are $($sigAge.Days) days old." -Recommendation "Force a definition update." -RemediationCommand "Update-MpSignature"
    }
    
    if ($mpPref.ExclusionPath -or $mpPref.ExclusionExtension -or $mpPref.ExclusionProcess) {
        $exclDetails = "Paths: $($mpPref.ExclusionPath -join ', '); Exts: $($mpPref.ExclusionExtension -join ', '); Procs: $($mpPref.ExclusionProcess -join ', ')"
        $Modules.defender_health.findings += New-Finding -Id "DEF-04" -Severity "MEDIUM" -Title "Defender Exclusions Configured" -Detail $exclDetails -Recommendation "Review exclusions to ensure they are not masking malware directories."
    }
} catch {
    $Modules.defender_health.status = "skipped"
    $Modules.defender_health.findings += New-Finding -Id "DEF-ERR" -Severity "INFO" -Title "Defender Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator or ensure Defender is installed."
}

# 2. Remote Access & Malicious Remote Control Detection
try {
    # 2.1 Active Reverse Shells & C2 Connections (CRITICAL)
    $tcpEst = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $shellExes = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'cscript.exe', 'wscript.exe', 'mshta.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe', 'bash.exe', 'wsl.exe')
    if ($tcpEst) {
        $foundShellPids = @{}
        foreach ($conn in $tcpEst) {
            if ($conn.RemoteAddress -notin @('127.0.0.1', '::1', '0.0.0.0')) {
                $ownerProc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($ownerProc) {
                    $pName = $ownerProc.ProcessName.ToLower() + '.exe'
                    if ($shellExes -contains $pName -and -not $foundShellPids.ContainsKey($ownerProc.Id)) {
                        $foundShellPids[$ownerProc.Id] = $true
                        $Modules.remote_access.findings += New-Finding `
                            -Id "REM-SHELL" `
                            -Severity "CRITICAL" `
                            -Title "Active Remote Reverse Shell / Command Stream" `
                            -Detail "Process: $($ownerProc.ProcessName) (PID: $($ownerProc.Id))`nRemote Endpoint: $($conn.RemoteAddress):$($conn.RemotePort)`nPath: $($ownerProc.Path)`nAn interactive command interpreter has established an active outbound network socket, indicating an active reverse shell or remote attacker controlling the machine." `
                            -Recommendation "Immediately terminate this process, disconnect network, and investigate the remote IP address." `
                            -RemediationCommand "Stop-Process -Id $($ownerProc.Id) -Force"
                    }
                }
            }
        }
    }

    # 2.2 Active Remote Access & Tunneling Tools in Memory (HIGH / CRITICAL)
    $suspiciousRemoteTools = @(
        'anydesk', 'teamviewer', 'rustdesk', 'screenconnect', 'ateraagent', 'splashtop',
        'ultraviewer', 'ammyy', 'supremo', 'vnc', 'winvnc', 'tv_w32', 'ngrok', 'cloudflared',
        'chisel', 'plink', 'frpc', 'nps', 'meshcentral', 'dwagent', 'parsec', 'kaseya'
    )
    $runningProcs = Get-Process -ErrorAction SilentlyContinue
    foreach ($rp in $runningProcs) {
        $pNameLower = $rp.ProcessName.ToLower()
        foreach ($tool in $suspiciousRemoteTools) {
            if ($pNameLower -match $tool) {
                $procPath = $rp.Path
                $isTempOrUser = $false
                if ($procPath -match '(?i)AppData\\Local\\Temp|AppData\\Roaming|Downloads|Users\\Public') {
                    $isTempOrUser = $true
                }
                
                $remoteConnStr = ""
                if ($tcpEst) {
                    $pConns = $tcpEst | Where-Object { $_.OwningProcess -eq $rp.Id }
                    if ($pConns) {
                        $remotes = $pConns | Select-Object -ExpandProperty RemoteAddress -Unique
                        $remoteConnStr = "Connected to: $($remotes -join ', ')"
                    }
                }

                $sev = if ($isTempOrUser) { "CRITICAL" } else { "HIGH" }
                $titlePrefix = if ($isTempOrUser) { "Unauthorized / Portable Remote Control Tool" } else { "Remote Control Tool Active in Memory" }

                $Modules.remote_access.findings += New-Finding `
                    -Id "REM-ACT-$(('{0:D2}' -f ($Modules.remote_access.findings.Count + 1)))" `
                    -Severity $sev `
                    -Title "$($titlePrefix): $($rp.ProcessName)" `
                    -Detail "Tool: $($rp.ProcessName) (PID: $($rp.Id))`nPath: $procPath`n$remoteConnStr`nRemote administration and support tools are frequently deployed by attackers or scammers for unauthorized remote control." `
                    -Recommendation "If you did not initiate this remote session, terminate the process immediately." `
                    -RemediationCommand "Stop-Process -Id $($rp.Id) -Force"
                break
            }
        }
    }

    # 2.3 Covert RDP Desktop Shadowing (CRITICAL)
    $shadowKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
    if ($shadowKey -and $shadowKey.Shadow) {
        $shadowVal = $shadowKey.Shadow
        if ($shadowVal -eq 1 -or $shadowVal -eq 3) {
            $desc = if ($shadowVal -eq 1) { "Full Control without user permission" } else { "View Session without user permission" }
            $Modules.remote_access.findings += New-Finding `
                -Id "REM-SHADOW" `
                -Severity "CRITICAL" `
                -Title "Covert RDP Desktop Shadowing Configured" `
                -Detail "Terminal Services policy is configured to allow remote control or surveillance without the active user's knowledge or consent (Shadow = $($shadowVal): $desc)." `
                -Recommendation "Disable unauthorized desktop shadowing to prevent covert remote surveillance." `
                -RemediationCommand "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'Shadow' -Value 0"
        }
    }

    # 2.4 Concurrent RDP Multi-User Backdoor (HIGH)
    $tsKey = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
    if ($tsKey -and $tsKey.fSingleSessionPerUser -eq 0) {
        $Modules.remote_access.findings += New-Finding `
            -Id "REM-CONCUR" `
            -Severity "HIGH" `
            -Title "Concurrent RDP Sessions Allowed" `
            -Detail "fSingleSessionPerUser is disabled. An unauthorized remote operator can log into this PC in the background without disconnecting the current user." `
            -Recommendation "Enforce single session per user." `
            -RemediationCommand "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fSingleSessionPerUser' -Value 1"
    }

    # 2.5 Standard RDP & WinRM Checks
    if ($tsKey -and $tsKey.fDenyTSConnections -eq 0) {
        $rdpPort = 3389
        $rdpPortKey = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
        if ($rdpPortKey -and $rdpPortKey.PortNumber) { $rdpPort = $rdpPortKey.PortNumber }
        $Modules.remote_access.findings += New-Finding -Id "REM-01" -Severity "MEDIUM" -Title "RDP Enabled" -Detail "Remote Desktop is enabled on port $rdpPort." -Recommendation "Ensure RDP is required and restricted by firewall."
    }
    
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -eq 'Running') {
        $Modules.remote_access.findings += New-Finding -Id "REM-02" -Severity "INFO" -Title "WinRM Running" -Detail "Windows Remote Management service is running." -Recommendation "Ensure WinRM is required for administration."
    }
    
    # 2.6 Installed Remote Access Software in Registry
    $knownSoftware = @("AnyDesk", "TeamViewer", "RustDesk", "ScreenConnect", "Chrome Remote Desktop", "VNC", "LogMeIn", "Atera", "Splashtop", "UltraViewer", "Ammyy")
    $installed = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Select-Object DisplayName
    foreach ($soft in $installed) {
        if ([string]::IsNullOrWhiteSpace($soft.DisplayName)) { continue }
        foreach ($target in $knownSoftware) {
            if ($soft.DisplayName -match $target) {
                $Modules.remote_access.findings += New-Finding -Id "REM-SOFT" -Severity "MEDIUM" -Title "Remote Access Software Installed" -Detail "Found installed: $($soft.DisplayName)" -Recommendation "Verify if this software is authorized."
            }
        }
    }
    
    # 2.7 Active Interactive Sessions
    $sessions = Get-CimInstance Win32_LogonSession -Filter "LogonType = 10" -ErrorAction SilentlyContinue # 10 = RemoteInteractive
    if ($sessions) {
        $Modules.remote_access.findings += New-Finding -Id "REM-04" -Severity "HIGH" -Title "Active Remote Desktop Sessions" -Detail "Found $($sessions.Count) active RemoteInteractive sessions connected right now." -Recommendation "Review currently logged-on users immediately."
    }
} catch {
    $Modules.remote_access.status = "skipped"
    $Modules.remote_access.findings += New-Finding -Id "REM-ERR" -Severity "INFO" -Title "Remote Access Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 3. Network
try {
    $tcp = Get-NetTCPConnection -ErrorAction Stop
    $listening = @()
    $unowned = @()
    
    foreach ($conn in $tcp) {
        if ($conn.State -eq 'Listen') {
            $listening += $conn.LocalPort
        } elseif ($conn.State -eq 'Established') {
            if ($conn.OwningProcess -eq 0) {
                $unowned += "$($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
            } else {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if (-not $proc) {
                    $unowned += "PID $($conn.OwningProcess) (Process not found): $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                }
            }
        }
    }
    
    $listening = $listening | Select-Object -Unique
    if ($listening.Count -gt 0) {
        $Modules.network.findings += New-Finding -Id "NET-01" -Severity "INFO" -Title "Listening Ports" -Detail "Listening on ports: $($listening -join ', ')" -Recommendation "Review exposed services."
    }
    if ($unowned.Count -gt 0) {
        $Modules.network.findings += New-Finding -Id "NET-02" -Severity "HIGH" -Title "Unresolvable Network Connections" -Detail "Established connections without a valid owning process: $($unowned -join '; ')" -Recommendation "Investigate hidden or terminated processes communicating on the network."
    }
} catch {
    $Modules.network.status = "skipped"
    $Modules.network.findings += New-Finding -Id "NET-ERR" -Severity "INFO" -Title "Network Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 4. Persistence
try {
    $idCounter = 1
    
    # Run Keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $runKeys) {
        $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $val = $prop.Value
                    if ($val -is [string]) {
                        $exePath = Get-ExecutableFromCommandLine -CmdLine $val
                        if ($exePath) {
                            $analysis = Analyze-Binary -Path $exePath
                            
                            $sev = "INFO"
                            if ($analysis.BumpSeverity) { $sev = "MEDIUM" }
                            if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                            
                            $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Run Key Entry" -Detail "Key: $key`nName: $($prop.Name)`nValue: $val" -Recommendation "Verify auto-start program." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                            $idCounter++
                        }
                    }
                }
            }
        }
    }
    
    # Startup Folders
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupPaths) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ($file.Extension -in @(".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")) {
                    $analysis = @{ SignatureStatus="Unknown"; SignerSubject=$null; LookalikeMatch=$null; BumpSeverity=$false; IsHighSeverity=$false }
                    if ($file.Extension -eq ".exe") { $analysis = Analyze-Binary -Path $file.FullName }
                    
                    $sev = "LOW"
                    if ($analysis.BumpSeverity) { $sev = "MEDIUM" }
                    if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                    
                    $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Startup Folder Script/Executable" -Detail "Path: $($file.FullName)" -Recommendation "Verify startup file." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                    $idCounter++
                }
            }
        }
    }
    
    # Scheduled Tasks
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        if ($task.Author -notmatch "Microsoft" -and $task.Source -notmatch "Microsoft") {
            foreach ($action in $task.Actions) {
                if ($action.Execute) {
                    $exePath = Get-ExecutableFromCommandLine -CmdLine $action.Execute
                    if (-not $exePath) { $exePath = $action.Execute }
                    $analysis = Analyze-Binary -Path $exePath
                    
                    $sev = "INFO"
                    if ($analysis.BumpSeverity) { $sev = "MEDIUM" }
                    if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                    
                    $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Non-Microsoft Scheduled Task" -Detail "Task Name: $($task.TaskName)`nAuthor: $($task.Author)`nExecute: $($action.Execute) $($action.Arguments)" -Recommendation "Verify task purpose." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                    $idCounter++
                }
            }
        }
    }
    
    # Services outside System32
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    $sys32Prefix = "$env:SystemRoot\System32\"
    $sysWow64Prefix = "$env:SystemRoot\SysWOW64\"
    foreach ($svc in $services) {
        if (-not [string]::IsNullOrWhiteSpace($svc.PathName)) {
            $exePath = Get-ExecutableFromCommandLine -CmdLine $svc.PathName
            if ($exePath) {
                $cleanSvcPath = [Environment]::ExpandEnvironmentVariables($exePath.Trim().Trim('"', "'"))
                $isSystemDir = $cleanSvcPath.StartsWith($sys32Prefix, [System.StringComparison]::InvariantCultureIgnoreCase) -or
                               $cleanSvcPath.StartsWith($sysWow64Prefix, [System.StringComparison]::InvariantCultureIgnoreCase)
                if (-not $isSystemDir) {
                    $analysis = Analyze-Binary -Path $cleanSvcPath
                    
                    $sev = "INFO"
                    if ($analysis.BumpSeverity) { $sev = "LOW" } # Services are common, keep base low
                    if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                    
                    $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Service outside System32" -Detail "Name: $($svc.Name)`nPath: $($svc.PathName)" -Recommendation "Verify service origin." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                    $idCounter++
                }
            }
        }
    }

    # WMI Event Consumers
    try {
        $consumers = Get-CimInstance -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
        foreach ($c in $consumers) {
            $Modules.persistence.findings += New-Finding -Id "PER-WMI" -Severity "HIGH" -Title "WMI Event Consumer Detected" -Detail "Name: $($c.Name)`nType: $($c.CimClass.CimClassName)" -Recommendation "WMI Event Consumers are commonly used by advanced malware for fileless persistence. Investigate immediately."
        }
    } catch {}

    # Image File Execution Options (IFEO) Hijacking
    try {
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        if (Test-Path $ifeoPath) {
            $subkeys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue
            foreach ($sk in $subkeys) {
                $debugger = Get-ItemProperty -Path $sk.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
                if ($debugger) {
                    $Modules.persistence.findings += New-Finding -Id "PER-IFEO" -Severity "HIGH" -Title "IFEO Debugger Hijack" -Detail "Process: $($sk.PSChildName)`nDebugger: $($debugger.Debugger)" -Recommendation "A debugger is attached to this process via IFEO. This is a known persistence technique. Investigate the debugger binary."
                }
            }
        }
    } catch {}

} catch {
    $Modules.persistence.status = "skipped"
    $Modules.persistence.findings += New-Finding -Id "PER-ERR" -Severity "INFO" -Title "Persistence Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 5. Accounts
try {
    $users = Get-LocalUser -ErrorAction Stop
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    
    $adminNames = $admins | Select-Object -ExpandProperty Name
    $Modules.accounts.findings += New-Finding -Id "ACC-01" -Severity "INFO" -Title "Local Administrators" -Detail "Members: $($adminNames -join ', ')" -Recommendation "Ensure least privilege principle is maintained."
    
    foreach ($user in $users) {
        if ($user.PasswordRequired -eq $false) {
            $Modules.accounts.findings += New-Finding -Id "ACC-02" -Severity "MEDIUM" -Title "Password Not Required" -Detail "User: $($user.Name)" -Recommendation "Enforce password requirements."
        }
        if ($user.PasswordNeverExpires -or $null -eq $user.PasswordExpires) {
            $Modules.accounts.findings += New-Finding -Id "ACC-03" -Severity "LOW" -Title "Password Never Expires" -Detail "User: $($user.Name)" -Recommendation "Implement password expiration policies if applicable."
        }
    }
} catch {
    $Modules.accounts.status = "skipped"
    $Modules.accounts.findings += New-Finding -Id "ACC-ERR" -Severity "INFO" -Title "Accounts Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 6. Patching
try {
    $rawHotfixes = Get-HotFix -ErrorAction SilentlyContinue
    if ($rawHotfixes) {
        $sorted = $rawHotfixes | Sort-Object {
            try { [datetime]::Parse($_.InstalledOn) } catch { [datetime]::MinValue }
        } -Descending | Select-Object -First 5
        $details = @()
        foreach ($hf in $sorted) {
            $details += "KB: $($hf.HotFixID), Date: $($hf.InstalledOn)"
        }
        $Modules.patching.findings += New-Finding -Id "PAT-01" -Severity "INFO" -Title "Recent Patches" -Detail ($details -join "`n") -Recommendation "Ensure system is regularly updated."
    } else {
        $Modules.patching.findings += New-Finding -Id "PAT-02" -Severity "LOW" -Title "No Patch Records Found" -Detail "Unable to retrieve recent hotfix history." -Recommendation "Check Windows Update service."
    }
} catch {
    $Modules.patching.status = "skipped"
    $Modules.patching.findings += New-Finding -Id "PAT-ERR" -Severity "INFO" -Title "Patching Check Failed" -Detail $_.Exception.Message -Recommendation "WMI may be disabled or blocked."
}

# 7. Defender Activity
try {
    $detections = Get-MpThreatDetection -ErrorAction Stop
    $detId = 1
    foreach ($det in $detections) {
        $sevName = "INFO"
        if ($det.SeverityID -eq 4 -or $det.SeverityID -eq 5) { $sevName = "HIGH" }
        $Modules.defender_activity.findings += New-Finding -Id "ACT-$(('{0:D3}' -f $detId))" -Severity $sevName -Title "Defender Detection History" -Detail "Threat: $($det.ThreatName)`nAction: $($det.ActionSuccess)`nPath: $($det.Resources)`nTime: $($det.InitialDetectionTime)" -Recommendation "Review Defender history for false positives or lingering infections."
        $detId++
    }
} catch {
    $Modules.defender_activity.status = "skipped"
    $Modules.defender_activity.findings += New-Finding -Id "ACT-ERR" -Severity "INFO" -Title "Defender Activity Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 8. System Health
try {
    # Disk Health
    $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    foreach ($d in $disks) {
        if ($d.HealthStatus -ne 'Healthy') {
            $Modules.system_health.findings += New-Finding -Id "SYS-01" -Severity "HIGH" -Title "Disk Not Healthy" -Detail "Disk $($d.DeviceId) Status: $($d.HealthStatus)" -Recommendation "Check physical disk health."
        }
    }
    
    # TPM
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm -or -not $tpm.TpmPresent) {
        $Modules.system_health.findings += New-Finding -Id "SYS-02" -Severity "MEDIUM" -Title "TPM Not Present" -Detail "No Trusted Platform Module detected or TPM status unavailable." -Recommendation "Enable TPM in BIOS or ensure TPM driver is working."
    } elseif (-not $tpm.TpmReady) {
        $Modules.system_health.findings += New-Finding -Id "SYS-03" -Severity "LOW" -Title "TPM Not Ready" -Detail "TPM is present but not ready/activated." -Recommendation "Initialize TPM."
    }
    
    # Restore Point
    $restore = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending | Select-Object -First 1
    if (-not $restore) {
        $Modules.system_health.findings += New-Finding -Id "SYS-04" -Severity "MEDIUM" -Title "No System Restore Points" -Detail "No recent restore points exist." -Recommendation "Enable System Restore or run a backup." -RemediationCommand "Enable-ComputerRestore -Drive '$($env:SystemDrive)\'"
    } else {
        try {
            $parsedDate = $null
            if ($restore.CreationTime -is [datetime]) {
                $parsedDate = $restore.CreationTime
            } else {
                try {
                    $parsedDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($restore.CreationTime)
                } catch {
                    $parsedDate = [datetime]::Parse($restore.CreationTime)
                }
            }
            if ($parsedDate) {
                $age = (Get-Date) - $parsedDate
                if ($age.TotalDays -gt 30) {
                    $Modules.system_health.findings += New-Finding -Id "SYS-05" -Severity "LOW" -Title "Stale System Restore Point" -Detail "Last restore point is $([math]::Round($age.TotalDays, 0)) days old." -Recommendation "Create a new restore point." -RemediationCommand "Checkpoint-Computer -Description 'WinSentry Manual Checkpoint' -RestorePointType 'MODIFY_SETTINGS'"
                }
            }
        } catch {
            # Silently fallback if date parsing fails
        }
    }
    
    # Update Readiness / Info
    $info = Get-ComputerInfo -Property OsBuildNumber, OsVersion -ErrorAction SilentlyContinue
    if ($info) {
        $Modules.system_health.findings += New-Finding -Id "SYS-06" -Severity "INFO" -Title "OS Version Info" -Detail "Build: $($info.OsBuildNumber), Version: $($info.OsVersion)" -Recommendation "Ensure build is supported."
    }
    
    # Volume
    $sysVol = Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveLetter -eq $env:SystemDrive[0] | Select-Object -First 1
    if ($sysVol -and $sysVol.Size -gt 0) {
        $freePct = ($sysVol.SizeRemaining / $sysVol.Size) * 100
        if ($freePct -lt 10) {
            $Modules.system_health.findings += New-Finding -Id "SYS-07" -Severity "HIGH" -Title "Low Disk Space" -Detail "System drive has $([math]::Round($freePct, 1))% free space." -Recommendation "Free up disk space to prevent update failures."
        }
    }
} catch {
    $Modules.system_health.status = "skipped"
    $Modules.system_health.findings += New-Finding -Id "SYS-ERR" -Severity "INFO" -Title "System Health Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 9. Behavioral Analysis (Offline Anomaly Detection)
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$baselineFile = Join-Path $scriptDir "winsentry_baseline.json"
$behScript = Join-Path $scriptDir "winsentry_behavioral.py"
if (Test-Path -LiteralPath $baselineFile) {
    try {
        if (Test-Path -LiteralPath $behScript) {
            $behOutput = & python $behScript --scan --json 2>$null | Out-String
            if ($behOutput -and $behOutput.Trim().StartsWith("[")) {
                $behFindings = $behOutput | ConvertFrom-Json -ErrorAction Stop
                foreach ($bf in $behFindings) {
                    $Modules.behavioral_analysis.findings += New-Finding -Id $bf.id -Severity $bf.severity -Title $bf.title -Detail $bf.detail -Recommendation $bf.recommendation -RemediationCommand $bf.remediation_command
                }
            }
        }
    } catch {
        $Modules.behavioral_analysis.status = "skipped"
        $Modules.behavioral_analysis.findings += New-Finding -Id "BEH-ERR" -Severity "INFO" -Title "Behavioral Scan Skipped" -Detail $_.Exception.Message -Recommendation "Ensure python is installed."
    }
} else {
    $Modules.behavioral_analysis.findings += New-Finding -Id "BEH-INFO" -Severity "INFO" -Title "No Behavioral Baseline Found" -Detail "System baseline profile not yet learned. Calibration recommended." -Recommendation "Click 'Learn Normal Baseline' in the WinSentry app or run 'python winsentry_behavioral.py --learn'."
}

# --- Risk Scoring ---

# module_score = max_weight - (critical_count * 15 + high_count * 10 + medium_count * 5 + low_count * 2)
# floored at 0. Total score is sum of module scores.
function Calculate-Score {
    $totalScore = 0
    foreach ($key in $Modules.Keys) {
        $weight = $ScoringWeights[$key]
        if ($null -eq $weight) { continue }
        
        $cCount = 0; $hCount = 0; $mCount = 0; $lCount = 0
        foreach ($f in $Modules[$key].findings) {
            switch ($f.severity) {
                "CRITICAL" { $cCount++ }
                "HIGH"     { $hCount++ }
                "MEDIUM"   { $mCount++ }
                "LOW"      { $lCount++ }
            }
        }
        
        $penalty = ($cCount * 15) + ($hCount * 10) + ($mCount * 5) + ($lCount * 2)
        $modScore = [Math]::Max(0, $weight - $penalty)
        $totalScore += $modScore
    }
    return $totalScore
}

$RiskScore = Calculate-Score

# --- Diff Mode (-CompareTo) ---
$DiffOutput = $null
if (-not [string]::IsNullOrWhiteSpace($CompareTo) -and (Test-Path $CompareTo)) {
    try {
        $oldReport = Get-Content $CompareTo -Raw | ConvertFrom-Json
        $DiffOutput = @{
            new = @()
            resolved = @()
            unchanged = @()
        }
        
        $oldFindings = @{}
        foreach ($modProp in $oldReport.modules.PSObject.Properties) {
            foreach ($f in $modProp.Value.findings) {
                # Create a composite key to uniquely identify findings
                $key = "$($f.id)|$($f.title)|$($f.detail)"
                $oldFindings[$key] = $f
            }
        }
        
        $newFindings = @{}
        foreach ($key in $Modules.Keys) {
            foreach ($f in $Modules[$key].findings) {
                $compKey = "$($f.id)|$($f.title)|$($f.detail)"
                $newFindings[$compKey] = $f
            }
        }
        
        # Determine New & Unchanged
        foreach ($k in $newFindings.Keys) {
            if ($oldFindings.ContainsKey($k)) {
                $DiffOutput.unchanged += $newFindings[$k]
            } else {
                $DiffOutput.new += $newFindings[$k]
            }
        }
        
        # Determine Resolved
        foreach ($k in $oldFindings.Keys) {
            if (-not $newFindings.ContainsKey($k)) {
                $DiffOutput.resolved += $oldFindings[$k]
            }
        }
    } catch {
        Write-Warning "Failed to parse -CompareTo file for diff mode: $_"
    }
}

# --- Output Generation ---

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Report = [ordered]@{
    scan_metadata = [ordered]@{
        hostname = $env:COMPUTERNAME
        scan_time_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        ran_as_admin = $isAdmin
        winsentry_version = "1.0.0"
        operator = $env:USERNAME
    }
    risk_score = $RiskScore
    scoring_weights = $ScoringWeights
    modules = $Modules
}

if ($DiffOutput) {
    $Report["diff"] = $DiffOutput
}

# Write JSON
$reportJson = $Report | ConvertTo-Json -Depth 10 -Compress:$false

Write-Host "Scan complete. Preparing to generate PDF..." -ForegroundColor Green

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$exePath = Join-Path $scriptDir "winsentry_report.exe"
$pyPath = Join-Path $scriptDir "winsentry_report.py"

# Save JSON report artifact
$jsonFile = Join-Path $scriptDir "winsentry_report.json"
try {
    [System.IO.File]::WriteAllText($jsonFile, $reportJson, [System.Text.Encoding]::UTF8)
} catch {}

if (Test-Path -LiteralPath $exePath) {
    # Prepend the plaintext password to the JSON payload, separated by a newline
    $payload = $plainPassword + "`n" + $reportJson
    
    # Pipe the payload securely to the executable via STDIN and capture the output
    $output = $payload | & $exePath - BASE64
    
    # Wipe the plaintext password from memory
    $plainPassword = $null
    $payload = $null
    
    $base64Data = ""
    $inBase64 = $false
    foreach ($line in $output) {
        if ($line -match "BASE64_PDF_START") {
            $inBase64 = $true
            continue
        }
        if ($line -match "BASE64_PDF_END") {
            $inBase64 = $false
            continue
        }
        if ($inBase64) {
            $base64Data += $line.Trim()
        }
    }
    
    if ($base64Data) {
        try {
            $bytes = [Convert]::FromBase64String($base64Data)
            $outPath = Join-Path $scriptDir "WinSentry_Report_Encrypted.pdf"
            [IO.File]::WriteAllBytes($outPath, $bytes)
            Write-Host "Report secured at: $outPath" -ForegroundColor Green
        } catch {
            Write-Host "Failed to decode and write PDF: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Failed to generate PDF. Check winsentry_report.exe output." -ForegroundColor Red
        $output | Out-String | Write-Host
    }
} elseif (Test-Path -LiteralPath $pyPath) {
    Write-Host "winsentry_report.exe not found. Attempting generation via python..." -ForegroundColor Yellow
    $payload = $plainPassword + "`n" + $reportJson
    try {
        $output = $payload | python $pyPath - BASE64 2>&1
        $plainPassword = $null
        $payload = $null
        
        $base64Data = ""
        $inBase64 = $false
        foreach ($line in $output) {
            if ($line -match "BASE64_PDF_START") {
                $inBase64 = $true
                continue
            }
            if ($line -match "BASE64_PDF_END") {
                $inBase64 = $false
                continue
            }
            if ($inBase64) {
                $base64Data += $line.Trim()
            }
        }
        
        if ($base64Data) {
            $bytes = [Convert]::FromBase64String($base64Data)
            $outPath = Join-Path $scriptDir "WinSentry_Report_Encrypted.pdf"
            [IO.File]::WriteAllBytes($outPath, $bytes)
            Write-Host "Report secured at: $outPath" -ForegroundColor Green
        } else {
            Write-Host "Failed to generate PDF with Python. Output:" -ForegroundColor Red
            $output | Out-String | Write-Host
        }
    } catch {
        Write-Host "Python invocation failed: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Error: Neither winsentry_report.exe nor winsentry_report.py found in script directory. Cannot generate report." -ForegroundColor Red
}

# Also generate interactive HTML dashboard report if python is available
if (Test-Path -LiteralPath $pyPath) {
    $htmlOut = Join-Path $scriptDir "WinSentry_Report.html"
    try {
        $payload = "`n" + $reportJson
        $payload | python $pyPath - NONE --html $htmlOut 2>&1 | Out-Null
        if (Test-Path -LiteralPath $htmlOut) {
            Write-Host "HTML dashboard generated at: $htmlOut" -ForegroundColor Green
        }
    } catch {}
}

# Helper to open report in a browser
function Open-Report {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { return }
    $browsers = @(
        "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    )
    $launched = $false
    foreach ($b in $browsers) {
        if (Test-Path -LiteralPath $b) {
            Start-Process -FilePath $b -ArgumentList "`"$FilePath`""
            $launched = $true
            break
        }
    }
    if (-not $launched) {
        try { Start-Process $FilePath } catch {}
    }
}

# Open the report in browser
$htmlFile = Join-Path $scriptDir "WinSentry_Report.html"
$pdfFile = Join-Path $scriptDir "WinSentry_Report_Encrypted.pdf"
if (Test-Path -LiteralPath $htmlFile) {
    Open-Report -FilePath $htmlFile
} elseif (Test-Path -LiteralPath $pdfFile) {
    Open-Report -FilePath $pdfFile
}
