#!/usr/bin/env python3
"""
WinSentry Behavioral Engine - Offline Behavioral Profiling & Anomaly Detection
Author: WinSentry Defensive Team
Zero network footprint, 100% offline local telemetry analysis.
"""

import json
import os
import sys
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone

DEFAULT_BASELINE_FILE = "winsentry_baseline.json"

# Core Windows processes that malware often masquerades as
SYSTEM_PROCESSES = {
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "spoolsv.exe", "taskhostw.exe", "smss.exe", "wininit.exe",
    "conhost.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "taskmgr.exe"
}

# Suspicious parent processes that should typically NOT spawn command shells
HIGH_RISK_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrobat.exe", "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "iexplore.exe", "wmiprvse.exe", "sqlservr.exe"
}

# Dangerous shells / script runners that indicate living-off-the-land attacks when spawned abnormally
SUSPICIOUS_SPAWNS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "vbc.exe", "csc.exe", "bash.exe", "wmic.exe", "schtasks.exe"
}

# Remote Access, Tunneling & Remote Management tools frequently abused for malicious control
REMOTE_CONTROL_TOOLS = {
    "anydesk.exe", "teamviewer.exe", "rustdesk.exe", "screenconnect.client.exe",
    "screenconnect.windowsclient.exe", "ateraagent.exe", "splashtop.exe",
    "ultraviewer.exe", "ammyyadmin.exe", "supremo.exe", "winvnc.exe", "vncviewer.exe",
    "ngrok.exe", "cloudflared.exe", "chisel.exe", "plink.exe", "frpc.exe", "nps.exe",
    "meshcentral.exe", "nc.exe", "ncat.exe", "socat.exe", "kaseya.exe", "parsec.exe"
}

# High-risk execution directories
SUSPICIOUS_DIRS = [
    os.path.expandvars(r"%TEMP%").lower(),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp").lower(),
    os.path.expandvars(r"%APPDATA%").lower(),
    r"c:\users\public",
    os.path.expandvars(r"%USERPROFILE%\Downloads").lower()
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates edit distance between two strings for typosquatting detection."""
    s1, s2 = s1.lower(), s2.lower()
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def collect_process_telemetry() -> list:
    """
    Collects live running process telemetry using PowerShell CIM / WMI.
    Zero network calls, purely local.
    """
    ps_cmd = (
        "$procs = Get-CimInstance Win32_Process | "
        "Select-Object ProcessId, Name, ParentProcessId, ExecutablePath, CommandLine; "
        "$procs | ConvertTo-Json -Compress"
    )
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            startupinfo=startupinfo,
            timeout=15
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        data = json.loads(result.stdout.strip())
        if isinstance(data, dict):
            data = [data]

        # Build PID -> Name mapping for resolving parent names
        pid_to_name = {p.get("ProcessId"): p.get("Name") for p in data if p.get("ProcessId")}

        # Attach ParentName
        for p in data:
            parent_pid = p.get("ParentProcessId")
            p["ParentName"] = pid_to_name.get(parent_pid, "Unknown")
            if not p.get("ExecutablePath") and p.get("Name"):
                p["ExecutablePath"] = ""
            if not p.get("CommandLine"):
                p["CommandLine"] = ""

        return data
    except Exception as e:
        sys.stderr.write(f"Telemetry collection error: {e}\n")
        return []


def collect_listening_ports() -> set:
    """Collects all currently active listening TCP ports."""
    ps_cmd = "(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).LocalPort | Select-Object -Unique | ConvertTo-Json -Compress"
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            startupinfo=startupinfo,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            ports = json.loads(result.stdout.strip())
            if isinstance(ports, int):
                return {ports}
            elif isinstance(ports, list):
                return set(ports)
    except Exception:
        pass
    return set()


def collect_established_connections() -> dict:
    """Collects active established non-loopback TCP connections mapped to OwningProcess ID."""
    ps_cmd = "(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue) | Select-Object OwningProcess, RemoteAddress, RemotePort | ConvertTo-Json -Compress"
    conns_by_pid = {}
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            startupinfo=startupinfo,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            for c in data:
                pid = c.get("OwningProcess")
                r_addr = str(c.get("RemoteAddress", ""))
                r_port = c.get("RemotePort")
                if pid and r_addr and r_addr not in ("127.0.0.1", "::1", "0.0.0.0"):
                    if pid not in conns_by_pid:
                        conns_by_pid[pid] = []
                    conns_by_pid[pid].append(f"{r_addr}:{r_port}")
    except Exception:
        pass
    return conns_by_pid


class BehavioralEngine:
    def __init__(self, baseline_path: str = DEFAULT_BASELINE_FILE):
        self.baseline_path = Path(baseline_path)

    def learn_baseline(self, duration_seconds: int = 30, interval_seconds: int = 5, callback=None):
        """
        Phase 1: Profiles legitimate system behavior over a learning window.
        Saves normal processes, parent-child relationships, paths, and listening ports.
        """
        print(f"[*] Starting Baseline Learning Mode for {duration_seconds}s...")
        known_processes = {}
        all_listening_ports = set()
        
        start_time = time.time()
        sample_count = 0

        while (time.time() - start_time) < duration_seconds:
            procs = collect_process_telemetry()
            ports = collect_listening_ports()
            all_listening_ports.update(ports)

            for p in procs:
                name = (p.get("Name") or "").lower()
                path = p.get("ExecutablePath") or ""
                parent = (p.get("ParentName") or "unknown").lower()

                if not name:
                    continue

                if name not in known_processes:
                    known_processes[name] = {
                        "known_paths": set(),
                        "known_parents": set(),
                        "count": 0
                    }

                if path:
                    known_processes[name]["known_paths"].add(path)
                if parent and parent != "unknown":
                    known_processes[name]["known_parents"].add(parent)
                known_processes[name]["count"] += 1

            sample_count += 1
            elapsed = int(time.time() - start_time)

            if callback:
                callback(elapsed, duration_seconds, len(known_processes))
            else:
                print(f" -> Sampling ({elapsed}/{duration_seconds}s) - {len(known_processes)} unique processes profiled...", end="\r")

            time.sleep(interval_seconds)

        print()

        # Serialize sets to lists for JSON compatibility
        serialized_procs = {}
        for name, data in known_processes.items():
            serialized_procs[name] = {
                "known_paths": list(data["known_paths"]),
                "known_parents": list(data["known_parents"]),
                "count": data["count"]
            }

        baseline_data = {
            "metadata": {
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "sample_duration_sec": duration_seconds,
                "total_samples": sample_count,
                "total_unique_processes": len(serialized_procs)
            },
            "known_processes": serialized_procs,
            "known_listening_ports": sorted(list(all_listening_ports))
        }

        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=2)

        print(f"[+] Baseline saved offline to: {self.baseline_path.resolve()}")
        return baseline_data

    def load_baseline(self) -> dict:
        if not self.baseline_path.exists():
            return None
        with open(self.baseline_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def detect_anomalies(self, sensitivity: str = "medium") -> list:
        """
        Phase 2: Offline Anomaly Detection.
        Evaluates current processes against the learned baseline profile.
        """
        baseline = self.load_baseline()
        has_baseline = baseline is not None
        known_procs = baseline.get("known_processes", {}) if has_baseline else {}

        current_procs = collect_process_telemetry()
        active_conns = collect_established_connections()
        findings = []
        finding_id_counter = 1

        sys32_dir = os.path.expandvars(r"%SystemRoot%\System32").lower()
        syswow_dir = os.path.expandvars(r"%SystemRoot%\SysWOW64").lower()
        win_dir = os.path.expandvars(r"%SystemRoot%").lower()

        # Sensitivity thresholds
        score_threshold = {"low": 60, "medium": 45, "high": 30}.get(sensitivity.lower(), 45)

        for p in current_procs:
            pid = p.get("ProcessId")
            name = (p.get("Name") or "").strip()
            name_lower = name.lower()
            path = (p.get("ExecutablePath") or "").strip()
            path_lower = path.lower()
            if path_lower.startswith("\\\\?\\"):
                path_lower = path_lower[4:]
            parent = (p.get("ParentName") or "").strip()
            parent_lower = parent.lower()
            cmdline = p.get("CommandLine") or ""
            cmdline_lower = cmdline.lower()

            anomaly_score = 0
            reasons = []

            # 0. Active Reverse Shell / Remote C2 Socket (CRITICAL)
            if pid in active_conns and name_lower in SUSPICIOUS_SPAWNS:
                anomaly_score += 90
                endpoints = ", ".join(active_conns[pid][:3])
                reasons.append(f"Active Reverse Shell / Remote C2: Process '{name}' is communicating with remote endpoint ({endpoints})")

            # 0b. Known Remote Access / RAT / Tunneling Tool
            if name_lower in REMOTE_CONTROL_TOOLS:
                anomaly_score += 75
                conn_str = f" [Connected to: {', '.join(active_conns[pid][:2])}]" if pid in active_conns else ""
                reasons.append(f"Remote Administration / Tunneling Tool active in memory: '{name}'{conn_str}")
                if any(path_lower.startswith(d) for d in SUSPICIOUS_DIRS):
                    anomaly_score += 20
                    reasons.append(f"Portable / Scammer Deployment: Executing from temp/user path ({path})")

            # 1. High-risk parent spawning a shell/script host (Living-off-the-land)
            if parent_lower in HIGH_RISK_PARENTS and name_lower in SUSPICIOUS_SPAWNS:
                anomaly_score += 65
                reasons.append(f"High-Risk Ancestry: Application '{parent}' spawned shell '{name}'")

            # 2. Masquerading as core Windows system process outside System32
            if name_lower in SYSTEM_PROCESSES:
                if path and not (path_lower.startswith(sys32_dir) or path_lower.startswith(syswow_dir) or path_lower.startswith(win_dir)):
                    anomaly_score += 70
                    reasons.append(f"Masquerading: System binary name '{name}' executing outside System32 ({path})")

            # 3. Typosquatting of System Processes
            if name_lower not in SYSTEM_PROCESSES and path_lower and not path_lower.startswith(sys32_dir):
                for sys_proc in SYSTEM_PROCESSES:
                    dist = levenshtein_distance(name_lower, sys_proc)
                    if dist in (1, 2) and abs(len(name_lower) - len(sys_proc)) <= 2:
                        anomaly_score += 55
                        reasons.append(f"Typosquat Suspect: '{name}' closely resembles core binary '{sys_proc}'")
                        break

            # 4. Execution from suspicious / user-writable temp directories
            for s_dir in SUSPICIOUS_DIRS:
                if path_lower and path_lower.startswith(s_dir):
                    # Check if this was an already known legitimate process in the baseline
                    if has_baseline and name_lower in known_procs and path in known_procs[name_lower].get("known_paths", []):
                        # Known in baseline
                        pass
                    else:
                        anomaly_score += 40
                        reasons.append(f"Suspicious Execution Path: Running from temporary/user directory ({path})")
                    break

            # 5. Suspicious Command Line Arguments
            if "-enc" in cmdline_lower or "-encodedcommand" in cmdline_lower or "frombase64string" in cmdline_lower:
                anomaly_score += 45
                reasons.append("Base64 Encoded Command Line detected")
            if "-w hidden" in cmdline_lower or "-windowstyle hidden" in cmdline_lower:
                anomaly_score += 25
                reasons.append("Hidden Execution Window requested")
            if "downloadstring" in cmdline_lower or "invoke-webrequest" in cmdline_lower or "certutil -urlcache" in cmdline_lower:
                anomaly_score += 40
                reasons.append("Network Download Cradle detected in command line")

            # 6. Baseline Deviations (if baseline is trained)
            if has_baseline:
                if name_lower not in known_procs:
                    # Brand new unseen executable
                    if any(path_lower.startswith(d) for d in SUSPICIOUS_DIRS) or not path:
                        anomaly_score += 35
                        reasons.append(f"Unseen Process in Baseline running from non-standard location ({name})")
                    else:
                        anomaly_score += 15
                        reasons.append(f"Unseen Process (Not present during baseline learning)")
                else:
                    profile = known_procs[name_lower]
                    known_parents = [kp.lower() for kp in profile.get("known_parents", [])]
                    if parent_lower and known_parents and parent_lower not in known_parents and parent_lower != "unknown":
                        anomaly_score += 35
                        reasons.append(f"Unusual Parent Process: '{parent}' (Expected: {', '.join(known_parents[:3])})")

            # Evaluate against threshold
            if anomaly_score >= score_threshold:
                if anomaly_score >= 70:
                    sev = "CRITICAL"
                elif anomaly_score >= 50:
                    sev = "HIGH"
                elif anomaly_score >= 35:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"

                findings.append({
                    "id": f"BEH-{finding_id_counter:03d}",
                    "severity": sev,
                    "title": f"Behavioral Anomaly: {name} (Score: {min(100, anomaly_score)}/100)",
                    "detail": (
                        f"Process: {name} (PID: {pid})\n"
                        f"Parent: {parent}\n"
                        f"Path: {path}\n"
                        f"Reasons:\n - " + "\n - ".join(reasons) + "\n"
                        f"Command Line: {cmdline[:250]}"
                    ),
                    "recommendation": f"Inspect PID {pid} ({name}). If unauthorized, terminate the process.",
                    "remediation_command": f"Stop-Process -Id {pid} -Force",
                    "process_name": name,
                    "pid": pid,
                    "anomaly_score": min(100, anomaly_score)
                })
                finding_id_counter += 1

        # Sort by anomaly score descending
        findings.sort(key=lambda x: x.get("anomaly_score", 0), reverse=True)
        return findings


def main():
    parser = argparse.ArgumentParser(description="WinSentry Offline Behavioral Anomaly Engine")
    parser.add_argument("--learn", action="store_true", help="Start baseline learning mode")
    parser.add_argument("--duration", type=int, default=30, help="Learning duration in seconds (default: 30)")
    parser.add_argument("--scan", action="store_true", help="Run behavioral anomaly scan against baseline")
    parser.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium", help="Detection sensitivity")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE_FILE, help="Path to baseline file")
    args = parser.parse_args()

    engine = BehavioralEngine(baseline_path=args.baseline)

    if args.learn:
        engine.learn_baseline(duration_seconds=args.duration)
        sys.exit(0)

    if args.scan:
        findings = engine.detect_anomalies(sensitivity=args.sensitivity)
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            print("=" * 60)
            print("         WinSentry Behavioral Anomaly Scanner")
            print("=" * 60)
            if not findings:
                print("[+] No behavioral anomalies detected! All processes align with baseline.")
            else:
                print(f"[!] Detected {len(findings)} behavioral anomalies:\n")
                for f in findings:
                    print(f"[{f['severity']}] {f['title']}")
                    print(f" -> Details: {f['detail']}")
                    print(f" -> Remediation: {f['remediation_command']}\n")
        sys.exit(0)

    parser.print_help()


if __name__ == "__main__":
    main()
