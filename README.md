# Azure Threat Detection: Brute Force Simulation & Sentinel Automation

## 🛡️ Project Overview
This project documents the end-to-end process of transitioning from manual log searching to **automated threat detection** within a cloud environment. By simulating a Brute Force attack on a Windows Virtual Machine, I validated a custom detection pipeline using **Azure Log Analytics** and **Microsoft Sentinel**.

The goal was to transform raw security telemetry into an actionable "digital alarm system" that pings defenders the moment a suspicious pattern is detected.

## 🛠️ Technical Stack
* **Environment:** Microsoft Azure
* **SIEM/SOAR:** Microsoft Sentinel
* **Endpoint:** Windows Virtual Machine (Azure)
* **Log Management:** Azure Log Analytics Workspace
* **Query Language:** Kusto Query Language (KQL)
* **Simulation Tool:** Windows Admin Center (Remote Desktop)

## 🔍 The Workflow

### 1. The Attack Simulation
To test the defenses, I played the role of the "attacker" by attempting to "hack" my own Windows VM. Using Remote Desktop via Windows Admin Center, I generated a series of failed login attempts, which are recorded in the system as **Event ID 4625**.

### 2. The Log Hunt
Once the telemetry was generated, I jumped into **Azure Log Analytics** to verify the data ingestion. I used KQL to aggregate these failures by Source IP to confirm the "footprints" were visible in the logs.

### 3. The Automation (Sentinel Rule)
I built a custom **Analytics Rule** in Microsoft Sentinel. The logic was designed to monitor for brute force patterns:
* **Threshold:** > 3 failed attempts within a 1-hour window.
* **Frequency:** The rule runs every 5 minutes to ensure near real-time detection.

### 4. The Result
The system successfully identified the pattern. Microsoft Defender automatically generated three **Medium Severity Incidents**, providing a clear investigative path for a SOC Analyst to follow.

---

## 💻 KQL Detection Logic
The following query was used to power the automated alert:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(60min)
| summarize FailureCount = count() by SourceIP = IpAddress, EventID, Activity
| where FailureCount >= 3# Project-SkyWatch
Simulated Threat Detection Rules In Sentinel
```
-----
<img width="1227" height="624" alt="Bruteforce Rule" src="https://github.com/user-attachments/assets/3bde2f1f-4381-49d5-bcf7-8dd26a5fdb2d" />

### 💡 Key Takeaways:
#Visibility is Victory: This lab reinforced that security isn't just about having a firewall; it's about centralizing logs so you can see the "story" the data is telling.

Proactive vs. Reactive: Transitioning from manual searching to automated rules is like moving from searching for footprints in the dark to having a motion-sensing security camera.

Defense in Depth: Even if a perimeter is probed, having an internal "tripwire" ensures that malicious activity is flagged before it can escalate.

