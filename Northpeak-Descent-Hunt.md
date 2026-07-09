# Threat Hunt Report: Northpeak Descent Investigation

**Participant:** Lea Angeline Escober

**Date:** July 2026

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace
* Windows 11-based workstation

**Languages/Tools:**

* Kusto Query Language (KQL)
  
---

## Scenario
During a post-incident investigation, the SOC received intelligence that an attacker had compromised the Northpeak Logistics environment on June 16, 2026. The objective was to reconstruct the complete attack chain by analyzing telemetry collected in Microsoft Defender XDR and Microsoft Sentinel.

Unlike a typical intrusion, the environment contained a large number of failed logon attempts that were intentionally generated as a distraction. The real compromise occurred through a successful authentication using valid credentials. The attacker maintained access across both Windows and Linux systems, established persistence, communicated with command-and-control (C2) infrastructure, moved laterally through the network, and eventually exfiltrated sensitive customer data.

The investigation relied on several Defender XDR tables, including:

* DeviceLogonEvents
* DeviceProcessEvents
* DeviceNetworkEvents
* DeviceRegistryEvents
* DeviceFileEvents
* DeviceEvents

## Investigation Summary
### Phase 1 - Initial Access
The investigation began by reviewing successful logon events instead of failed authentication attempts.
The attacker authenticated successfully from the external IP address: `148.64.103.173`
Using the account: `sancadmin`

Three hosts were accessed in chronological order:
* First foothold: **npt-ws01** at 20:57 UTC
* Then **npt-srv01** at 21:58 UTC
* Then **npt-linux01** at 22:01 UTC

**Query used to locate events:**
```kql
let NorthpeakHosts = dynamic(["npt-ws01","npt-srv01","npt-linux01"]);
DeviceLogonEvents
| where DeviceName has_any (NorthpeakHosts)
| where ActionType == "LogonSuccess"
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where isnotempty(RemoteIP)
| where RemoteIP !startswith "10."
  and RemoteIP !startswith "172.16."
  and RemoteIP !startswith "192.168."
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP
| order by Timestamp asc
```

<img width="975" height="369" alt="image" src="https://github.com/user-attachments/assets/2a6c48bd-f344-4b77-b8e0-5209510cf007" />

---
### Phase 2 - Hands-on-Keyboard Reconnaissance
After obtaining access, the attacker performed manual reconnaissance on each system.

## **Windows**
The attacker first verified network connectivity by executing:
* `PowerShell`
* `ipconfig`

on both Windows hosts.

On `npt-ws01`:

21:54:45 - powershell.exe

21:54:48 - ipconfig.exe

<img width="975" height="70" alt="image" src="https://github.com/user-attachments/assets/97f37a93-a2f9-4d8b-a3a8-ad94f8839668" />

On `npt-srv01`:

21:59:02 - powershell.exe

21:59:13 - ipconfig.exe

<img width="975" height="70" alt="image" src="https://github.com/user-attachments/assets/2e5075ef-0315-4762-afbf-25bab12dd7f9" />


## **Linux**
Once connected to the Linux server, the attacker performed extensive enumeration by running commands such as:

* `hostname -I`
* `whoami`
* `id`
* `hostname`
* `uname -a`
* `ip a`
* `cat /etc/passwd`
* `last`
* `sudo -l`

These commands demonstrate classic post-compromise discovery activity, allowing the attacker to identify local users, operating system information, IP addresses, login history, and privilege escalation opportunities.

**Query used to locate events:**
```kql
let NorthpeakHosts = dynamic(["npt-ws01","npt-srv01","npt-linux01"]);
DeviceProcessEvents
| where DeviceName has_any (NorthpeakHosts)
| where Timestamp between (datetime(2026-06-16 20:57:00) .. datetime(2026-06-16 22:15:00))
| where AccountName == "sancadmin"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="975" height="279" alt="image" src="https://github.com/user-attachments/assets/c1d0f9cb-ec68-4830-bd8c-fa30fa43279b" />

---
### Phase 3 - Privilege Enumeration
The attacker immediately checked which administrative privileges were available.
On Linux, the attacker executed: `sudo -l`
to enumerate commands that could be executed with elevated privileges.

Later, on the Windows workstation, the attacker confirmed whether the compromised account belonged to the local Administrators group by checking for the SID: `S-1-5-32-544`

This confirmed whether the account had local administrator rights before continuing with later stages of the intrusion.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

<img width="975" height="221" alt="image" src="https://github.com/user-attachments/assets/d04686e4-fdd0-429a-8a38-566dab8ed7dd" />

---
## Phase 4 - Linux Tooling
Before pivoting further into the environment, the attacker prepared the Linux host.
The investigation showed the installation of `netexec` along with supporting Python packages.

This tool was likely used to facilitate authentication testing and lateral movement into Windows systems.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| where Timestamp > datetime(2026-06-16 22:27:55)
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="975" height="263" alt="image" src="https://github.com/user-attachments/assets/48c3f935-27f7-47c1-8d00-7094119ab16b" />

---
## Phase 5 — Internal Lateral Movement
After completing reconnaissance, the attacker pivoted through the internal network using legitimate credentials.

The sequence of movement was: 

`Internet` --> `npt-ws01` --> `npt-srv01` --> `npt-linux01`

Rather than exploiting vulnerabilities, the attacker authenticated successfully using valid credentials throughout the environment.

---
## Phase 6 — PowerShell Execution
The Windows workstation generated a significant amount of PowerShell activity.
By separating operator activity from normal system operations, it became clear that:
* SYSTEM-generated PowerShell executions were launched repeatedly by Microsoft's Defender extension.
* Only a small number of PowerShell executions belonged to the attacker.

This distinction prevented normal Defender telemetry from being mistaken for malicious activity.

```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc")
| summarize Count=count(),
            FirstSeen=min(Timestamp),
            LastSeen=max(Timestamp)
    by AccountName, InitiatingProcessFileName
| order by Count desc
```
<img width="975" height="83" alt="image" src="https://github.com/user-attachments/assets/665a1e2f-8879-4a3d-a978-2d58b5ce9156" />

---
## Phase 7 — Persistence
The attacker established persistence using a Windows Run Registry key.
Instead of installing a service or scheduled task, a PowerShell command was configured to automatically launch `NorthpeakSyncTray.ps1` whenever the user logged in.
This ensured the beacon would survive system reboots while remaining relatively inconspicuous.

**Query used to locate events:**
```kql
let NorthPeakHosts = dynamic(["npt-ws01","npt-srv01","npt-linux01"]);
DeviceRegistryEvents
| where DeviceName has_any (NorthPeakHosts)
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where RegistryKey endswith "Run"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, RegistryKey, RegistryValueData
```
<img width="975" height="65" alt="image" src="https://github.com/user-attachments/assets/870e1926-d687-4d8f-81a2-c45ee4f08c1a" />

---
## Phase 8 — Command and Control
The attacker communicated with three look-alike subdomains:
* `status.sync-northpeak.com`
* `updates.sync-northpeak.com`
* `cdn.sync-northpeak.com`
Interestingly, `DeviceNetworkEvents` recorded only one of these domains.
The remaining two were recovered from PowerShell command lines stored in `DeviceProcessEvents`, demonstrating why process telemetry is often critical when network visibility is incomplete.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where AccountName == "sancadmin"
| where InitiatingProcessFileName has "powershell.exe"
| project Timestamp, AccountDomain, AccountName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
| order by Timestamp asc
```
<img width="975" height="288" alt="image" src="https://github.com/user-attachments/assets/9986d90f-0344-40d2-9eb7-2f5129c38c2e" />

---
## Phase 9 — Encoded PowerShell
One of the PowerShell commands was executed using `-EncodedCommand`.
After decoding the Base64 string as UTF-16LE, the command revealed an HTTP beacon directed toward the attacker's infrastructure.
This technique obscured the destination URL from casual inspection while remaining easily executable by PowerShell.
The HTTP revealed was: `https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09`
<img width="975" height="161" alt="image" src="https://github.com/user-attachments/assets/e0fe1c54-3aa4-4b9f-bcc5-a879c5f05a99" />

---
## Phase 10 — Beacon Analysis
Reviewing the timestamps of the initial check-ins revealed that beacon traffic occurred at consistent intervals.
The predictable spacing indicated that the communication was generated by an automated script rather than by interactive user activity.
This regular cadence is characteristic of scripted command-and-control communications.

---
## Phase 11 — Data Exfiltration
The final stage of the intrusion involved exfiltrating sensitive customer information.

The attacker uploaded `customer_data_export_20260616.csv` from `npt-srv01` to `cdn.sync-northpeak.com` using PowerShell's `Invoke-WebRequest`.

The command uploaded the file directly to the attacker's infrastructure without requiring any additional malware.

```kql
DeviceProcessEvents
| where DeviceName == "npt-srv01"
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where AccountName == "sancadmin"
| where InitiatingProcessFileName has "powershell.exe"
| project Timestamp, AccountName, ProcessCommandLine
| order by Timestamp asc 
```
<img width="975" height="100" alt="image" src="https://github.com/user-attachments/assets/bf8ee0be-f265-42c3-9a1c-e6b94a72de9c" />

---
## Phase 12 — Defensive Assessment
One of the most important findings came from what did not happen.

Throughout the investigation there was no evidence that the attacker:

* Disabled Microsoft Defender
* Modified security configurations
* Stopped security services
* Dropped traditional malware
* Installed persistence through services or scheduled tasks

Instead, the attacker relied entirely on:

* Valid credentials
* Built-in Windows tools
* Native Linux utilities
* PowerShell
* Registry Run keys
* Legitimate remote administration

This represents a classic Living-off-the-Land (LotL) approach, where trusted system tools are abused to minimize detection.

---
## Key Takeaways
* The intrusion relied on valid credentials, not exploitation.
* The attacker intentionally created failed logon noise to distract defenders from successful authentication.
* Windows was the initial foothold, followed by movement to the server and Linux host.
* Linux was used for reconnaissance and tooling before pivoting back into the Windows environment.
* Persistence was established through a Registry Run key executing a PowerShell script.
* Three C2 domains were recovered only by correlating process and network telemetry.
* Encoded PowerShell concealed beacon destinations but was easily recovered by decoding UTF-16LE Base64.
* Customer data was exfiltrated directly over HTTPS using built-in PowerShell functionality.
* The attacker avoided disabling security controls and instead relied on living-off-the-land techniques, allowing the intrusion to remain stealthy throughout the operation.

---
