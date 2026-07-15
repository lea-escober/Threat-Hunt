# Just Another Day – Nimbus Health Threat Hunt
## Overview
This investigation focused on a suspicious billing account (j.morris) at Nimbus Health after unusual activity was detected. Although the initial assumption was that a former employee still had access, the telemetry revealed a different story. The account was being remotely operated using valid credentials from a public IP address, allowing the attacker to move across multiple systems, collect sensitive data, and stage stolen files without deploying malware.

The investigation used Microsoft Defender for Endpoint (MDE) telemetry within Microsoft Sentinel and correlated evidence across `DeviceLogonEvents`, `DeviceProcessEvents`, and `DeviceFileEvents` to reconstruct the attack timeline.

## Investigation Timeline
### 1. Suspicious Billing Account Identified
The investigation began by reviewing successful logon events across all Nimbus (`nh-*`) hosts. The billing account `j.morris` immediately stood out because it authenticated to multiple systems using `RemoteInteractive` logons instead of the expected local interactive sessions.

The successful logons also originated from public IP addresses, indicating that someone outside the organization's internal network was driving the account rather than the legitimate billing employee.

**Finding**
* Compromised billing account: `j.morris`
* RemoteInteractive logons
* Public source IP addresses
* Multiple host access

```kql
DeviceLogonEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where ActionType == "LogonSuccess"
| summarize
    LogonCount = count(),
    Devices = make_set(DeviceName),
    DeviceCount = dcount(DeviceName),
    LogonTypes = make_set(LogonType),
    RemoteIPs = make_set(RemoteIP)
    by AccountName
| order by DeviceCount desc, LogonCount desc
```
<img width="975" height="214" alt="image" src="https://github.com/user-attachments/assets/39a2beb2-a1f3-4568-a1be-da6cec518c09" />

---
