import re
import os
import csv
from datetime import datetime
from email.utils import parseaddr
import difflib

import dns.resolver
import joblib
import pandas as pd
import streamlit as st

st.set_page_config(page_title="PhishTriage NG Lite", layout="centered")

# ---------------- Model loading ----------------
@st.cache_resource
def load_model():
    return joblib.load("model.joblib")

model = load_model()

# ---------------- Nigeria-focused categories ----------------
CATEGORIES = {
    "Bank/Fintech OTP Scam": [
        "otp", "one time password", "token", "pin", "verify your account",
        "account will be blocked", "debit alert", "reversal"
    ],
    "Fake NIN/CBN/EFCC Message": [
        "nin", "cbn", "efcc", "arrest", "fine", "court", "bvn", "verification exercise"
    ],
    "Fake Job/NYSC Recruitment": [
        "job", "recruitment", "interview", "nysc", "shortlisted", "training fee", "application fee"
    ],
    "Investment/Crypto Scam": [
        "investment", "crypto", "forex", "double your money", "returns", "profit", "signal"
    ],
    "Delivery/Dispatch Scam": [
        "delivery", "dispatch", "package", "parcel", "waybill", "tracking", "rider"
    ],
    "Airtime/Data/Promo Scam": [
        "airtime", "data", "promo", "bonus", "free data", "reward"
    ],
    "Loan/Fee Scam": [
        "loan", "processing fee", "approval", "funds", "disburse"
    ],
}

# Removed normal words like "today" to reduce false positives
URGENCY_WORDS = ["urgent", "immediately", "now", "last warning", "final", "act fast", "limited time", "within 24 hours"]
CREDENTIAL_WORDS = ["otp", "pin", "password", "token", "verification code"]
MONEY_WORDS = ["pay", "payment", "transfer", "send", "fee", "charge", "deposit", "refund", "cash", "subscription"]

# ---------------- SIEM-style detection rules (Sigma-like) ----------------
SIEM_RULES = [
    {
        "id": "NG-SIEM-001",
        "name": "Credential Harvesting / OTP Request",
        "severity": "High",
        "mitre": "T1566 (Phishing)",
        "match": lambda t, urls, phones: any(x in t for x in ["otp", "pin", "password", "token", "verification code"]),
        "why": "Message requests sensitive credentials (OTP/PIN/password)."
    },
    {
        "id": "NG-SIEM-002",
        "name": "Government/Regulator Impersonation + Threat",
        "severity": "High",
        "mitre": "T1566 (Phishing)",
        "match": lambda t, urls, phones: any(x in t for x in ["cbn", "nin", "efcc"]) and any(x in t for x in ["arrest", "fine", "court", "jail"]),
        "why": "Impersonates CBN/NIN/EFCC and uses threats (arrest/fine) to force action."
    },
    {
        "id": "NG-SIEM-003",
        "name": "Shortened Link + Urgency",
        "severity": "High",
        "mitre": "T1566 (Phishing)",
        "match": lambda t, urls, phones: (("bit.ly" in t) or ("tinyurl" in t) or ("t.co" in t)) and any(w in t for w in URGENCY_WORDS),
        "why": "Uses a shortened link plus urgency—common phishing pattern."
    },
    {
        "id": "NG-SIEM-004",
        "name": "Brand/Account Shutdown Pressure",
        "severity": "Medium",
        "mitre": "T1566 (Phishing)",
        "match": lambda t, urls, phones: any(x in t for x in ["account will be blocked", "deactivated", "suspended", "restricted"]) and (len(urls) > 0 or "click" in t),
        "why": "Claims account shutdown and pushes link clicking/verification."
    },
    {
        "id": "NG-SIEM-005",
        "name": "Fee/Payment Request Pattern",
        "severity": "Medium",
        "mitre": "T1566 (Phishing)",
        "match": lambda t, urls, phones: any(x in t for x in ["pay", "fee", "charge", "subscription", "deposit"]) and any(w in t for w in URGENCY_WORDS),
        "why": "Requests payment/fee with urgency—often scam pressure tactics."
    },
    {
        "id": "NG-SIEM-006",
        "name": "Delivery/Dispatch Fee Scam Pattern",
        "severity": "Medium",
        "mitre": "T1566 (Phishing)",
        "match": lambda t, urls, phones: any(x in t for x in ["dispatch", "delivery", "parcel", "package", "rider"]) and any(x in t for x in ["fee", "pay", "release"]),
        "why": "Delivery/dispatch theme combined with fee/release language."
    },
]

SIEM_SEV_RANK = {"Low": 0, "Medium": 1, "High": 2}

def siem_run_rules(text: str, urls, phones):
    t = text.lower()
    matches = []
    for r in SIEM_RULES:
        try:
            if r["match"](t, urls, phones):
                matches.append({
                    "id": r["id"],
                    "name": r["name"],
                    "severity": r["severity"],
                    "mitre": r.get("mitre", ""),
                    "why": r["why"]
                })
        except Exception:
            continue

    siem_risk = "Low"
    for m in matches:
        if SIEM_SEV_RANK[m["severity"]] > SIEM_SEV_RANK[siem_risk]:
            siem_risk = m["severity"]

    return siem_risk, matches

# ---------------- IOC regex ----------------
URL_REGEX = r"(?i)\b((?:https?://|www\.)[^\s]+)"
PHONE_REGEX = r"(?i)(\+234\d{10}|\b0\d{10}\b)"
ACCT_REGEX = r"(?i)\b\d{10}\b"

# ---------------- Risk helpers ----------------
RISK_RANK = {"Low": 0, "Medium": 1, "High": 2}

def max_risk(a: str, b: str) -> str:
    return a if RISK_RANK[a] >= RISK_RANK[b] else b

def score_to_risk(prob_spam: float):
    if prob_spam >= 0.80:
        return "High"
    if prob_spam >= 0.50:
        return "Medium"
    return "Low"

def defang(url: str) -> str:
    u = url.strip()
    u = re.sub(r"(?i)^https?://", "hxxp://", u)
    if u.lower().startswith("www."):
        u = "hxxp://" + u
    return u

def extract_iocs(text: str):
    urls = re.findall(URL_REGEX, text)
    phones = re.findall(PHONE_REGEX, text)
    accts = re.findall(ACCT_REGEX, text)
    urls = [defang(u) for u in urls]
    return sorted(set(urls)), sorted(set(phones)), sorted(set(accts))

def categorize(text: str):
    t = text.lower()
    for cat, kws in CATEGORIES.items():
        if any(kw in t for kw in kws):
            return cat
    return "General Suspicious Message"

def red_flags(text: str, urls, phones):
    t = text.lower()
    flags = []

    if any(w in t for w in URGENCY_WORDS):
        flags.append("Uses urgency/pressure tactics (e.g., 'urgent', 'immediately').")

    if any(w in t for w in CREDENTIAL_WORDS):
        flags.append("Asks for sensitive credentials (OTP/PIN/password). Legit services never request OTP via chat.")

    if any(w in t for w in MONEY_WORDS):
        flags.append("Mentions payments/fees/transfers—common in scams.")

    if urls:
        flags.append("Contains a link. Scams often use links to steal login details or install malware.")

    if phones:
        flags.append("Provides a phone number to move conversation off-platform (common social-engineering tactic).")

    if "click" in t or "tap" in t:
        flags.append("Prompts you to click/tap quickly (possible phishing).")

    return flags[:8] if flags else ["No obvious red flags found, but always verify via official channels."]

def advice(risk_level: str, category: str):
    base = [
        "Do not share OTP/PIN/password with anyone.",
        "Verify claims using the official website/app or official customer-care number.",
        "Avoid clicking unknown links; type the official website yourself.",
    ]
    if risk_level in ("High", "Medium"):
        base += [
            "If you already clicked a link, change passwords and enable 2FA on your important accounts.",
            "Block/report the sender on the platform.",
        ]
    if "OTP" in category:
        base += ["Contact your bank/fintech via official channels if you suspect compromise."]
    return base[:7]

def rule_based_risk(text: str, urls, phones) -> str:
    t = text.lower()

    if any(x in t for x in ["otp", "pin", "password", "token", "verification code"]):
        return "High"

    score = 0
    if urls:
        score += 1
    if phones:
        score += 1
    if any(w in t for w in URGENCY_WORDS):
        score += 1
    if any(x in t for x in ["cbn", "nin", "efcc", "arrest", "fine", "court", "bvn"]):
        score += 1
    if any(x in t for x in ["bit.ly", "tinyurl", "t.co"]):
        score += 1

    if score >= 3:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"

# ---------------- Email verification helpers ----------------
def extract_domain_from_email(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return ""

def parse_authentication_results(headers_text: str) -> dict:
    h = (headers_text or "").lower()
    out = {}
    for key in ["spf", "dkim", "dmarc"]:
        m = re.search(rf"{key}=(pass|fail|softfail|neutral|none|temperror|permerror)", h)
        if m:
            out[key] = m.group(1)
    return out

@st.cache_data(show_spinner=False)
def dns_txt_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        records = []
        for r in answers:
            s = "".join([x.decode() if isinstance(x, bytes) else str(x) for x in r.strings])
            records.append(s)
        return records
    except Exception:
        return []

def check_spf_dmarc_presence(from_domain: str) -> dict:
    result = {"spf_present": False, "dmarc_present": False}

    txt = dns_txt_records(from_domain)
    result["spf_present"] = any("v=spf1" in t.lower() for t in txt)

    dmarc_txt = dns_txt_records(f"_dmarc.{from_domain}")
    result["dmarc_present"] = any("v=dmarc1" in t.lower() for t in dmarc_txt)

    return result

def email_auth_checks(from_addr: str, reply_to: str, expected_domain: str, headers_text: str):
    checks = []

    from_domain = extract_domain_from_email(from_addr)
    reply_domain = extract_domain_from_email(reply_to)

    auth = parse_authentication_results(headers_text)

    if auth:
        for k in ["spf", "dkim", "dmarc"]:
            if k in auth:
                status = "PASS" if auth[k] == "pass" else ("WARN" if auth[k] in ["none", "neutral"] else "FAIL")
                checks.append({"check": f"{k.upper()} result (from headers)", "status": status, "detail": f"{k}={auth[k]}"})
    else:
        checks.append({
            "check": "SPF/DKIM/DMARC results",
            "status": "WARN",
            "detail": "No Authentication-Results found. Paste email headers for stronger verification."
        })

    if reply_to and from_domain and reply_domain:
        if reply_domain != from_domain:
            checks.append({
                "check": "Reply-To domain mismatch",
                "status": "FAIL",
                "detail": f"From domain is {from_domain} but Reply-To domain is {reply_domain}."
            })
        else:
            checks.append({
                "check": "Reply-To alignment",
                "status": "PASS",
                "detail": "Reply-To domain matches From domain."
            })

    if expected_domain:
        exp = expected_domain.lower().strip()
        if from_domain == exp:
            checks.append({
                "check": "Expected sender domain match",
                "status": "PASS",
                "detail": f"From domain matches expected domain: {exp}"
            })
        else:
            similarity = difflib.SequenceMatcher(None, from_domain, exp).ratio() if from_domain and exp else 0
            status = "FAIL" if similarity > 0.75 else "WARN"
            checks.append({
                "check": "Expected sender domain mismatch",
                "status": status,
                "detail": f"From domain ({from_domain}) != expected ({exp}). Similarity={similarity:.2f}"
            })

    if from_domain:
        dns_presence = check_spf_dmarc_presence(from_domain)
        checks.append({
            "check": "SPF record present (DNS)",
            "status": "PASS" if dns_presence["spf_present"] else "WARN",
            "detail": "SPF TXT record found." if dns_presence["spf_present"] else "No SPF TXT record found."
        })
        checks.append({
            "check": "DMARC record present (DNS)",
            "status": "PASS" if dns_presence["dmarc_present"] else "WARN",
            "detail": "DMARC TXT record found." if dns_presence["dmarc_present"] else "No DMARC TXT record found."
        })

    return checks

# ---------------- Core analysis ----------------
def analyze_message(msg: str) -> dict:
    prob_spam = float(model.predict_proba([msg])[0][1])
    ai_risk = score_to_risk(prob_spam)

    urls, phones, accts = extract_iocs(msg)
    category = categorize(msg)

    rule_risk = rule_based_risk(msg, urls, phones)
    siem_risk, siem_matches = siem_run_rules(msg, urls, phones)

    final_risk = max_risk(ai_risk, rule_risk)
    final_risk = max_risk(final_risk, siem_risk)

    if final_risk == "Low" and not urls and not phones and not siem_matches:
        category = "Likely Legit / Normal Message"

    flags = red_flags(msg, urls, phones)
    actions = advice(final_risk, category)

    return {
        "message": msg,
        "ai_prob": prob_spam,
        "ai_risk": ai_risk,
        "rule_risk": rule_risk,
        "risk": final_risk,
        "category": category,
        "urls": urls,
        "phones": phones,
        "accts": accts,
        "flags": flags,
        "actions": actions,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "siem_risk": siem_risk,
        "siem_matches": siem_matches,
    }

def build_report(res: dict, email_checks=None) -> str:
    siem_lines = "\n".join(
        [f"- {m['severity']} | {m['id']} — {m['name']} ({m['mitre']}) | {m['why']}" for m in res["siem_matches"]]
    ) if res["siem_matches"] else "None"

    email_lines = "None"
    if email_checks:
        email_lines = "\n".join([f"- {c['status']} — {c['check']}: {c['detail']}" for c in email_checks])

    return f"""PhishTriage NG Lite — Case Note
Time: {res["time"]}

Input Message:
{res["message"]}

Triage:
- Risk Level: {res["risk"]}
- AI Spam Probability: {res["ai_prob"]:.2f}
- AI Risk: {res["ai_risk"]}
- Rule-Based Risk: {res["rule_risk"]}
- Category: {res["category"]}
- SIEM Rule Risk: {res["siem_risk"]}

Extracted IOCs:
- URLs: {", ".join(res["urls"]) if res["urls"] else "None"}
- Phone Numbers: {", ".join(res["phones"]) if res["phones"] else "None"}
- Possible Account Numbers: {", ".join(res["accts"]) if res["accts"] else "None"}

Email authenticity checks (if email):
{email_lines}

Red Flags:
{chr(10).join(["- " + x for x in res["flags"]])}

Recommended Actions:
{chr(10).join(["- " + x for x in res["actions"]])}

Matched SIEM Rules:
{siem_lines}

Tool Disclosure:
- AI: TF-IDF + Logistic Regression (offline, scikit-learn)
- SIEM rules: Sigma-like keyword rules + MITRE mapping
- App: Streamlit (Python)
"""

# ---------------- Case logging (CSV) ----------------
CASES_FILE = "cases.csv"

def save_case(res: dict):
    new_file = not os.path.exists(CASES_FILE)
    fields = ["time", "risk", "ai_prob", "ai_risk", "rule_risk", "category", "urls", "phones", "accounts", "message"]

    row = {
        "time": res["time"],
        "risk": res["risk"],
        "ai_prob": round(res["ai_prob"], 2),
        "ai_risk": res["ai_risk"],
        "rule_risk": res["rule_risk"],
        "category": res["category"],
        "urls": " | ".join(res["urls"]) if res["urls"] else "",
        "phones": " | ".join(res["phones"]) if res["phones"] else "",
        "accounts": " | ".join(res["accts"]) if res["accts"] else "",
        "message": res["message"].replace("\n", " ").strip()
    }

    with open(CASES_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if new_file:
            writer.writeheader()
        writer.writerow(row)

# ---------------- UI ----------------
page = st.sidebar.radio("Menu", ["Single Check", "Batch Check", "Dashboard", "About"])

if page == "Single Check":
    st.title("PhishTriage NG Lite")
    st.caption("Digital Inclusion project: scam/phishing checker for SMS/WhatsApp + Email triage (AI + SIEM rules + IOC extraction).")

    input_type = st.selectbox("Input type", ["SMS/WhatsApp", "Email"], key="input_type")

    headers_text = ""
    email_from = ""
    email_reply_to = ""
    expected_domain = ""
    email_checks = None

    if input_type == "SMS/WhatsApp":
        msg = st.text_area(
            "Paste the message text here:",
            height=180,
            key="single_msg",
            placeholder="Paste SMS/WhatsApp message..."
        )
        combined_msg = msg
    else:
        email_from = st.text_input("From (optional):", key="email_from")
        email_reply_to = st.text_input("Reply-To (optional):", key="email_reply_to")
        email_subject = st.text_input("Subject (optional):", key="email_subject")
        email_body = st.text_area("Email body:", height=180, key="email_body")

        headers_text = st.text_area(
            "Email headers (recommended for verification):",
            height=120,
            key="email_headers",
            placeholder="Paste Authentication-Results / Received headers here..."
        )

        expected_domain = st.text_input(
            "Expected sender domain (optional, enterprise check e.g. yourcompany.com):",
            key="expected_domain"
        )

        combined_msg = (
            f"From: {email_from}\n"
            f"Reply-To: {email_reply_to}\n"
            f"Subject: {email_subject}\n\n"
            f"{email_body}\n\n"
            f"Headers:\n{headers_text}"
        )

    def clear_single_msg():
        st.session_state["single_msg"] = ""
        st.session_state["email_from"] = ""
        st.session_state["email_reply_to"] = ""
        st.session_state["email_subject"] = ""
        st.session_state["email_body"] = ""
        st.session_state["email_headers"] = ""
        st.session_state["expected_domain"] = ""

    col1, col2 = st.columns([1, 1])
    analyze = col1.button("Analyze", type="primary")
    col2.button("Clear", on_click=clear_single_msg)

    if analyze:
        if not combined_msg.strip():
            st.warning("Please paste a message to analyze.")
            st.stop()

        res = analyze_message(combined_msg)

        if input_type == "Email":
            st.subheader("Email authenticity checks (verification signals)")
            email_checks = email_auth_checks(email_from, email_reply_to, expected_domain, headers_text)
            for c in email_checks:
                st.write(f"- **{c['status']}** — {c['check']}: {c['detail']}")

        st.subheader("Result")
        st.write(f"**Risk level:** {res['risk']}")
        st.write(f"**Spam probability (AI):** {res['ai_prob']:.2f}")
        st.write(f"**AI risk:** {res['ai_risk']}")
        st.write(f"**Rule-based risk:** {res['rule_risk']}")
        st.write(f"**SIEM rule risk:** {res['siem_risk']}")
        st.write(f"**Category (Nigeria-focused):** {res['category']}")

        st.subheader("Indicators of Compromise (IOCs)")
        st.write("**URLs:**", res["urls"] if res["urls"] else "None detected")
        st.write("**Phone numbers:**", res["phones"] if res["phones"] else "None detected")
        st.write("**Possible account numbers (10 digits):**", res["accts"] if res["accts"] else "None detected")

        st.subheader("Red flags (explanations)")
        for f in res["flags"]:
            st.write(f"- {f}")

        st.subheader("Recommended safe actions")
        for a in res["actions"]:
            st.write(f"- {a}")

        report = build_report(res, email_checks=email_checks)

        c1, c2 = st.columns([1, 1])
        with c1:
            st.download_button(
                label="Download Report (.txt)",
                data=report.encode("utf-8"),
                file_name="phishtriage_case_note.txt",
                mime="text/plain"
            )
        with c2:
            if st.button("Save Case"):
                save_case(res)
                st.success("Saved to cases.csv")

        st.subheader("Matched SIEM Detection Rules")
        if res["siem_matches"]:
            for m in res["siem_matches"]:
                st.write(f"- **{m['severity']}** | {m['id']} — {m['name']} ({m['mitre']})")
                st.write(f"  - Why: {m['why']}")
        else:
            st.write("No SIEM rules matched.")

elif page == "Batch Check":
    st.title("Batch Check (SOC-style triage)")
    st.caption("Paste multiple messages (one per block). The app will analyze each and output a table.")

    batch = st.text_area(
        "Paste messages (separate messages with a blank line):",
        height=220,
        key="batch_msg",
        placeholder="Message 1...\n\nMessage 2...\n\nMessage 3..."
    )

    if st.button("Run Batch Analysis", type="primary"):
        blocks = [b.strip() for b in re.split(r"\n\s*\n", batch) if b.strip()]

        if not blocks:
            st.warning("Paste at least one message first.")
            st.stop()

        results = []
        for b in blocks:
            r = analyze_message(b)
            results.append({
                "time": r["time"],
                "risk": r["risk"],
                "ai_prob": round(r["ai_prob"], 2),
                "ai_risk": r["ai_risk"],
                "rule_risk": r["rule_risk"],
                "siem_risk": r["siem_risk"],
                "category": r["category"],
                "urls": " | ".join(r["urls"]) if r["urls"] else "",
                "phones": " | ".join(r["phones"]) if r["phones"] else "",
                "message": (r["message"][:80] + "...") if len(r["message"]) > 80 else r["message"]
            })

        df = pd.DataFrame(results)
        st.subheader("Batch Results")
        st.dataframe(df, use_container_width=True)

        st.download_button(
            "Download Batch Results (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="batch_results.csv",
            mime="text/csv"
        )

        if st.button("Save ALL as Cases"):
            for b in blocks:
                save_case(analyze_message(b))
            st.success("All batch items saved to cases.csv")

elif page == "Dashboard":
    st.title("Dashboard")
    st.caption("Shows saved triage cases (stored locally in cases.csv). Note: cloud storage can reset on free hosting.")

    if not os.path.exists(CASES_FILE):
        st.info("No saved cases yet. Go to 'Single Check' or 'Batch Check' and save cases.")
        st.stop()

    df = pd.read_csv(CASES_FILE)

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Cases", len(df))
    c2.metric("High Risk", int((df["risk"] == "High").sum()))
    c3.metric("Medium Risk", int((df["risk"] == "Medium").sum()))

    st.subheader("Recent Cases")
    st.dataframe(df.tail(20), use_container_width=True)

    st.subheader("Cases by Risk")
    st.bar_chart(df["risk"].value_counts())

    st.subheader("Cases by Category")
    st.bar_chart(df["category"].value_counts())

elif page == "About":
    st.title("About")
    st.write("""
**PhishTriage NG Lite** is a Digital Inclusion-focused tool that helps users and SOC beginners triage suspicious SMS/WhatsApp messages and phishing emails.

**Key Features**
- Offline AI spam probability (TF-IDF + Logistic Regression)
- Nigeria-focused scam categories (CBN/NIN, OTP scams, job scams, etc.)
- SIEM-style detection rules (Sigma-like) + MITRE T1566 mapping
- IOC extraction (URLs, phone numbers, account patterns)
- Email verification signals: SPF/DKIM/DMARC (from headers), domain alignment checks, DNS presence of SPF/DMARC
- Downloadable case note report (.txt)
- Batch triage + case logging + dashboard

**Privacy**
Avoid pasting real OTPs, bank details, or highly sensitive personal data.
""")
