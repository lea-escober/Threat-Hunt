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

