# 🛡️ CyberMonitor

A beginner-friendly **cybersecurity dashboard** built with Python and Streamlit — a lightweight, local alternative to Splunk for analysing Windows Security Event logs.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [Exporting Real Windows Logs](#exporting-real-windows-logs)
- [Uploading Logs to CyberMonitor](#uploading-logs-to-cybermonitor)
- [Event ID Reference](#event-id-reference)
- [Screenshots](#screenshots)
- [License](#license)

---

## Overview

CyberMonitor parses Windows Security Event logs (exported as `.csv` or `.log`) and presents them in an interactive dark-themed dashboard. If no file is uploaded, it automatically generates realistic mock data so it works out of the box — no configuration needed.

---

## Features

| Feature | Description |
|---|---|
| 🔄 **Auto Mock Data** | Generates 500 realistic Windows Security Events on startup |
| 📂 **File Upload** | Accepts `.csv` / `.log` exports from Windows Event Viewer |
| 📊 **KPI Cards** | Total Events, Failed Logins (4625), Successful Logins (4624), Privilege Escalations (4672) |
| 🔍 **Sidebar Filters** | Filter by Event ID, Severity/Level, and Source Account |
| 📈 **Event Volume Chart** | Stacked area chart bucketed by hour, colour-coded by severity |
| 🗂️ **Data Table** | Paginated, labelled table of all parsed log events |
| 🏆 **Top Accounts** | Horizontal bar chart of the most active accounts |
| 🍩 **Event ID Donut** | Breakdown of event types by proportion |
| 🎨 **Dark Theme** | Full GitHub-dark CSS theme (`#0d1117` background) |

---

## Project Structure

```
Ibm project/
├── app.py              # Main Streamlit application (single file)
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── report.html         # Project report (open in any browser)
```

---

## Requirements

- **Python** 3.9 or higher (3.14 confirmed working)
- **pip** (bundled with Python)

Python packages (pinned in `requirements.txt`):

```
streamlit>=1.32.0
altair>=5.3.0
pandas>=2.2.0
```

---

## Installation

**1. Clone or download this project folder.**

**2. Install dependencies:**

```powershell
pip install -r requirements.txt
```

> If `pip` installs to user site-packages and isn't on your PATH, use:
> ```powershell
> python -m pip install -r requirements.txt
> ```

---

## Running the App

```powershell
python -m streamlit run app.py
```

- Press **Enter** to skip the one-time email prompt on first launch.
- Your browser opens automatically at **http://localhost:8501**.
- The dashboard loads with **mock data immediately** — no file needed.

> **Tip:** If you added Python Scripts to your PATH (see below), you can use `streamlit run app.py` directly.

### Fix `streamlit` command not found (one-time)

```powershell
$userScripts = "$env:APPDATA\Python\Python314\Scripts"
[System.Environment]::SetEnvironmentVariable(
    "PATH",
    "$([System.Environment]::GetEnvironmentVariable('PATH','User'));$userScripts",
    "User"
)
```

Restart your terminal after running this.

---

## Exporting Real Windows Logs

Run this in **PowerShell as Administrator** on any Windows machine:

```powershell
Get-WinEvent -LogName Security -MaxEvents 2000 |
  Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security_events.csv" -NoTypeInformation
```

| Parameter | Purpose |
|---|---|
| `-LogName Security` | Targets the Windows Security audit log |
| `-MaxEvents 2000` | Caps the export (adjust as needed) |
| `Select-Object ...` | Picks only the columns CyberMonitor needs |
| `-NoTypeInformation` | Removes the `#TYPE` header line from the CSV |

The exported file will be saved to your **Desktop** as `security_events.csv`.

---

## Uploading Logs to CyberMonitor

1. Launch the app with `python -m streamlit run app.py`
2. In the **left sidebar**, click **Browse files** under "Log Source"
3. Select your `security_events.csv` file
4. The dashboard reloads automatically with your real data

The app automatically remaps these column names from Event Viewer exports:

| Event Viewer Column | CyberMonitor Column |
|---|---|
| `TimeCreated` | `TimeGenerated` |
| `Id` | `EventID` |
| `LevelDisplayName` | `Level` |
| `ProviderName` | `Source` |

---

## Event ID Reference

| Event ID | Description | Severity |
|---|---|---|
| **4624** | Successful Logon | Information |
| **4625** | Failed Logon | Critical |
| **4648** | Logon with Explicit Credentials | Warning |
| **4672** | Special Privileges Assigned (Privilege Escalation) | Warning |
| **4688** | New Process Created | Information |
| **4698** | Scheduled Task Created | Warning |
| **4720** | User Account Created | Information |
| **4732** | Member Added to Security Group | Warning |
| **4771** | Kerberos Pre-Authentication Failed | Error |

---

## License

This project is for **educational and internal monitoring purposes only**. Do not use on systems you do not own or have explicit permission to monitor.

---

<p align="center">🛡️ Built with Python &amp; Streamlit</p>