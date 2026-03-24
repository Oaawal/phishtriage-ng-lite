# PhishTriage NG Lite

Digital Inclusion + SOC/SIEM-style phishing/scam triage tool for SMS/WhatsApp messages.

## Features
- AI spam probability (TF-IDF + Logistic Regression)
- Nigeria-focused scam categories (OTP, NIN/CBN/EFCC, job scams, etc.)
- SIEM-style detection rules (Sigma-like) + MITRE T1566 mapping
- IOC extraction (URLs/phones/account patterns)
- Downloadable case note report (.txt)
- Batch triage + case logging + dashboard

## Run locally
pip install -r requirements.txt
streamlit run app.py