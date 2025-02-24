# 🚨 Internal Network Threat Investigation

## 📌 Scenario
The **server team** has observed significant network performance degradation on older devices attached to the `10.0.0.0/16` network.  
After ruling out **external DDoS attacks**, the **security team** suspects unauthorized internal activity.

## 🔎 Description
- **All internal traffic is allowed** by default.  
- **Unrestricted** use of PowerShell and other administrative tools.  
- Possible causes: **large file downloads** or **port scanning** against internal hosts.  

---

## 🕵️ Timeline & Findings

### **1. Failed Connection Requests**
Several internal devices are failing connection requests. To investigate, we focused on **king-vm**.

#### 📜 Query:
```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by ActionType, DeviceName, LocalIP
| sort by ConnectionCount desc
```
 ![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Network-Degradation/blob/main/img1.png?raw=true)

### 2. Identifying a Port Scan
Examining **king-vm**, we discovered failed connection requests occurring sequentially across ports, indicating an internal port scan.

📜 Query:
```kusto

let DeviceInQuestion = "10.0.0.84";
DeviceNetworkEvents
| where ActionType == "connection failed"
| where LocalIP == DeviceInQuestion
| order by Timestamp desc
```
 ![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Network-Degradation/blob/main/img2.png?raw=true)

### 3. Suspicious PowerShell Execution
Investigating logs around the suspected port scan (2025-02-12T16:15:37Z), we discovered an unauthorized PowerShell script execution:

"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
Execution Time: 2025-02-12T16:12:38Z

📜 Query:
```kusto
let DeviceInQuestion = "king-vm-final";
let specificTime = datetime(2025-02-12T16:15:37.0904749Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == DeviceInQuestion
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
 ![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Network-Degradation/blob/main/img3.png?raw=true)

### 4. Identifying the Responsible User
By extending the query, we identified the account responsible for launching the process.

📜 Query:
```kusto
let DeviceInQuestion = "king-vm-final";
let specificTime = datetime(2025-02-12T16:15:37.0904749Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where InitiatingProcessCommandLine contains "portscan"
| where DeviceName == DeviceInQuestion
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```
 ![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Network-Degradation/blob/main/img4.png?raw=true)

📜 Query to check file creation:
```kusto
DeviceFileEvents
| where DeviceName contains "king"
| where FileName contains "portscan"
```
 ![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Network-Degradation/blob/main/img5.png?raw=true)

## 🚀 Immediate Action Taken
Discussed with the user (KING) – they denied running the script.
Isolated the machine from the network.
Ran a malware scan – no threats detected.
Submitted a request to reimage the machine as a precaution.

 ![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Network-Degradation/blob/main/img6.png?raw=true)

## 🔥 MITRE ATT&CK Framework - Identified TTPs
TTP ID	Description

**T1046**      -  Network Service Scanning

**T1059.001**	 -  Command and Scripting Interpreter: PowerShell

**T1547.001**	 -  Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (Possible)

**T1202**	   -    Indirect Command Execution

**T1078**	    -   Valid Accounts

**T1021.001**	-   Remote Services: Remote Desktop Protocol (Possible)

## 🛠 Response Plan: Mitigating the Confirmed Threat
# 🛑 Containment

-  Isolate the compromised machine (**king-vm-final**) from the network.

-  Suspend the compromised account (KING).

-  Revoke all active sessions related to the compromised account.

# 🧹 Removal
-  Delete the malicious script (portscan.ps1).

-  Clean startup locations and scheduled tasks.

-  Perform a full system scan using Microsoft Defender Antivirus.

# 🔄 Recovery
-  Reimage the machine to eliminate persistent threats.

-  Reset the compromised account password.

-  Implement AppLocker to block unauthorized PowerShell execution.

# 🚨 Monitoring & Prevention
-  Configure Microsoft Sentinel to detect port scanning behavior.

-  Deploy Defender for Endpoint attack surface reduction (ASR) rules.

-  Automate Sentinel playbooks to isolate compromised machines.

-  Monitor suspicious PowerShell execution (e.g., execution policy bypass).

📜 Query to Detect Execution Policy Bypass:
```kusto
DeviceProcessEvents
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "-ExecutionPolicy Bypass"
```

## 📌 Summary
A port scan was detected from an internal machine (**king-vm-final**).

The scan originated from a PowerShell script (portscan.ps1).

The account (KING) showed no awareness of the script execution.

The machine was isolated and scanned (no malware found).

A precautionary reimage was performed.

Mitigation strategies (AppLocker, ASR rules, Sentinel monitoring) were implemented.

## 🏆 Lessons Learned
- Restrict unnecessary PowerShell execution using AppLocker.

- Monitor for execution policy bypasses in PowerShell logs.

- Implement stricter access control to limit privilege escalation.

- Automate threat response via Sentinel playbooks.

