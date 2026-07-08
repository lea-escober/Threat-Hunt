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

DeviceLogonEvents
DeviceProcessEvents
DeviceNetworkEvents
DeviceRegistryEvents
DeviceFileEvents
DeviceEvents

## Investigation Summary
### Phase 1 - Initial Access
The investigation began by reviewing successful logon events instead of failed authentication attempts.
The attacker authenticated successfully from the external IP address:
