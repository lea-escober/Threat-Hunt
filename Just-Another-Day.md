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
### 2. Initial Activity Was Noise
The first command-line activity appeared suspicious because numerous delete commands executed through `cmd.exe`.

Further analysis showed these commands were simply Microsoft OneDrive cleanup operations, removing temporary installation files and old update folders from the user's AppData directory.

These deletions were normal application maintenance and unrelated to attacker activity.

**Finding**
* OneDrive cache cleanup
* Routine operating system/application maintenance
* False lead

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where AccountName == "j.morris"
| where FileName == "cmd.exe"
| project Timestamp, AccountName, ActionType, DeviceName, ProcessCommandLine
| order by Timestamp asc
```
<img width="975" height="208" alt="image" src="https://github.com/user-attachments/assets/616472fa-1767-4d88-9f74-6a30ab3dbec8" />

---
### 3. Hands-on Reconnaissance
Immediately after the routine cleanup, the attacker began manually enumerating the environment using native Windows utilities.

The sequence included:
* `whoami`
* `hostname`
* `net use`
* `net view`
* `net view \\NH-FS-01`

This confirmed that the activity was interactive and deliberate rather than automated malware. The attacker was identifying the current user, system identity, available network resources, and the primary file server before moving further into the environment.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where AccountName == "j.morris"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="975" height="227" alt="image" src="https://github.com/user-attachments/assets/bb591285-8df8-416a-bcf9-780b11642eea" />

---
### 4. Mapping the Network
Next, the attacker expanded reconnaissance by identifying systems on the local network.

Native Windows commands included:

* `net view /domain:nimbus`
* `arp -a`
* Multiple `nslookup` commands

These commands resolved nearby IP addresses and identified potential targets before lateral movement.

This sequence demonstrated a classic reconnaissance phase immediately before pivoting to additional hosts.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where AccountName == "j.morris"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="975" height="83" alt="image" src="https://github.com/user-attachments/assets/59d0c6ed-b5f9-4bf2-856d-a4e25d16f452" />

---
### 5. Access Beyond the Billing Role
Reviewing file activity showed the account browsing outside its normal responsibilities.

Rather than remaining within the Pending billing workflow, the attacker accessed the Approved billing folder, which represented the sign-off stage of the billing process and should not have been accessible during normal billing submissions.

This was the first clear indication that the account was operating outside its legitimate business role.

```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where FolderPath contains @"\\NH-FS-01\Billing\2026-03\"
| distinct FolderPath
```
<img width="975" height="431" alt="image" src="https://github.com/user-attachments/assets/6f4f58af-b8d5-4dff-8548-c3cd6fa3b92f" />
