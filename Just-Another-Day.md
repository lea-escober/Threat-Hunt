# Just Another Day – Nimbus Health Threat Hunt
## Overview
This investigation focused on a suspicious billing account (`j.morris`) at Nimbus Health after unusual activity was detected. Although the initial assumption was that a former employee still had access, the telemetry revealed a different story. The account was being remotely operated using valid credentials from a public IP address, allowing the attacker to move across multiple systems, collect sensitive data, and stage stolen files without deploying malware.

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

---
### 6. Invoice Manipulation
Inside the Approved workflow, the account modified billing data.

The investigation identified activity involving:

* `approved_pending_invoice_INV-773221_20260311.txt`

This demonstrated that the attacker was interacting with billing records rather than simply browsing folders.

```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where FolderPath contains @"\Approved\"
| where FileName contains "invoice"
| where RequestAccountName == "j.morris"
| project Timestamp, ActionType, FileName, RequestAccountName
```
<img width="975" height="129" alt="image" src="https://github.com/user-attachments/assets/c3f87d4e-211c-4a68-8ff9-a0c3aea93f13" />

---
### 7. Staging Sensitive HR Data
The investigation then shifted from billing activity to data theft.

The attacker copied payroll information from the HR share into the Billing Exceptions folder and deliberately renamed it to resemble a legitimate billing exception.

The staged filename became:
`payroll_exception_reference_20260311.txt.txt`

The double .txt.txt extension attempted to disguise sensitive payroll information as an ordinary text document, allowing it to blend into existing billing files.

```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where RequestAccountName =~ "j.morris"
| where FolderPath contains @"\Exceptions\"
| project Timestamp,
          ActionType,
          FileName,
          FolderPath,
          PreviousFileName,
          PreviousFolderPath,
          RequestAccountName
| order by Timestamp asc
```
<img width="975" height="44" alt="image" src="https://github.com/user-attachments/assets/fc9cf34d-158a-4f4f-a41b-f9bd8c3ce411" />

---
### 8. Additional HR Collection
The payroll file was not the only HR information accessed.

Reviewing HR file activity showed that the attacker also collected additional HR-related documents, including employee awards information.

This demonstrated that the attacker was collecting multiple categories of HR information rather than targeting a single payroll document.

```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-"
| where RequestAccountName =~ "j.morris"
| where ActionType == "FileModified"
| project Timestamp,
          ActionType,
          FileName,
          FolderPath,
          PreviousFileName,
          PreviousFolderPath,
          RequestAccountName
| order by Timestamp asc
```
<img width="975" height="98" alt="image" src="https://github.com/user-attachments/assets/175362cb-6382-41fd-a7bd-dde1f7851f1f" />

---
### 9. Lateral Movement
After reconnaissance, the attacker initiated Remote Desktop sessions to additional systems.

Successful pivots included:

* `nh-wks-it-01`
* `nh-fs-01`

Although three RDP connections were attempted, only two resulted in successful remote sessions.

---
### 10. The Red Herring
The IT workstation initially appeared suspicious because it received a successful Remote Desktop connection.

However, reviewing process activity showed only normal Windows session initialization processes such as:

* userinit.exe
* explorer.exe
* rdpclip.exe
* ctfmon.exe
* taskhostw.exe

No command execution, reconnaissance, file access, or attacker tooling followed.

The IT workstation represented a successful connection but no meaningful activity.

---
### 11. File Server Enumeration
Once on the file server, the attacker verified available privileges before enumerating shared resources.

Rather than deploying malware, the attacker continued using legitimate Windows administration commands to determine accessible shares and available data.

This reinforced that the intrusion relied entirely on valid credentials and built-in Windows utilities.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-03-08)
| where Timestamp < datetime(2026-03-19)
| where DeviceName startswith "nh-fs-01"
| where AccountName =~ "j.morris"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
<img width="975" height="148" alt="image" src="https://github.com/user-attachments/assets/19600ae2-963c-4515-b8c6-085863b49e07" />

---
### Conclusion
This investigation demonstrated a hands-on-keyboard intrusion conducted with compromised credentials rather than malware. The attacker remotely operated the billing account from external IP addresses, performed deliberate reconnaissance using native Windows tools, pivoted through the environment with Remote Desktop, accessed billing data beyond the user's role, and staged sensitive HR information under misleading filenames to reduce suspicion.

The attack succeeded because the attacker possessed valid credentials, allowing normal Windows administration features to be abused without triggering malware-based detections. The strongest indicators of compromise were the unusual RemoteInteractive logons, cross-department access, manual reconnaissance, and unauthorized collection of HR and billing information—not malicious binaries or exploit activity.

---
