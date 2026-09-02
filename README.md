# PhishBlocker 🛡️

PhishBlocker is a robust security suite designed to protect users from phishing threats through pre-navigation URL risk analysis and real-time endpoint telemetry monitoring.

## 🚀 Features
- **Pre-Navigation Risk Engine:** FastAPI backend that evaluates URLs for malicious indicators before a user navigates to them.
- **Browser Extension:** Seamlessly intercepts navigation attempts and warns or blocks users from visiting suspicious pages.
- **Endpoint Security Agent:** Written in Go, it monitors system telemetry (process starts, PowerShell commands, credential access) and reports security events to the backend.
- **Cloud Deployment:** Backend hosted live on Render for 24/7 accessibility.

## 🛠️ Tech Stack
- **Backend:** Python, FastAPI, Uvicorn
- **Extension:** JavaScript, HTML, Chrome Extensions API
- **Endpoint Agent:** Go (Golang)
- **Deployment:** Render Cloud

## ⚙️ Setup & Installation

### 1. Backend Setup
Navigate to the backend directory and run:
```bash
pip install -r requirements.txt
uvicorn main:app --reload
