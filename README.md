# PhishTriage NG Lite (demo)

Streamlit demo of SOC/SIEM-style phishing and scam triage for SMS/WhatsApp
messages: ML spam probability, Nigeria-focused scam categories, Sigma-like
detection rules with MITRE T1566 mapping, IOC extraction, email SPF/DKIM/DMARC
checks, case notes and batch triage.

> **Status:** demo / portfolio project. The maintained detection engine,
> used by the PhishTriage app and WhatsApp bot, lives in
> `PhishTriagePlatform/engine/`. On the shared labelled test set it catches
> far more scams with no false alarms; this demo catches about half.

## Changes in this version
- Keywords now match whole words only. Before, normal messages were marked
  High risk because "nin" matched "mor**nin**g", "pin" matched "ship**pin**g"
  and "now" matched "k**now**".
- Genuine OTP notices ("do not share this code") are no longer marked High
  risk just for mentioning an OTP.

## Run locally
```bash
pip install -r requirements.txt
streamlit run app.py
```
