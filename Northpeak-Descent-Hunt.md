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
First foothold: **npt-ws01** at 20:57 UTC
Then **npt-srv01** at 21:58 UTC
Then **npt-linux01** at 22:01 UTC

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


