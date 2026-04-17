import requests
from bs4 import BeautifulSoup
import re
import whois
from datetime import datetime
import streamlit as st

def analyze_website(url):
    results = []
    score = 0

    if not url.startswith("http"):
        url = "https://" + url

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, timeout=10, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text().lower()
        links = soup.find_all("a", href=True)

        # -----------------------------------------------
        # A. EXTRACT — emails, phones, links
        # -----------------------------------------------
        emails = re.findall(r"[\w\.-]+@[\w\.-]+\.[a-z]{2,}", text)
        phones = re.findall(r"\+?\d[\d\s\-]{8,}", text)

        # BUG FIX 3: Also check /contact page if no contact found on homepage
        if not emails and not phones:
            try:
                contact_url = url.rstrip("/") + "/contact"
                cr = requests.get(contact_url, timeout=5, headers=headers)
                ct = BeautifulSoup(cr.text, "html.parser").get_text().lower()
                emails = re.findall(r"[\w\.-]+@[\w\.-]+\.[a-z]{2,}", ct)
                phones = re.findall(r"\+?\d[\d\s\-]{8,}", ct)
            except:
                pass

        # BUG FIX 2: Check privacy policy in links too, not just page text
        privacy_links = [a["href"] for a in links if "privacy" in a.get("href", "").lower()]
        has_privacy = bool(privacy_links) or "privacy policy" in text or "privacy" in text

        terms_links = [a["href"] for a in links if "term" in a.get("href", "").lower()]
        has_terms = bool(terms_links) or "terms" in text

        suspicious_keywords = [
            "guaranteed profit", "100% return", "risk free", "double your money",
            "guaranteed returns", "unlimited profit", "no risk", "instant profit"
        ]

        # -----------------------------------------------
        # B. RULE-BASED DETECTION
        # -----------------------------------------------

        # 1. Suspicious Claims
        found_keywords = [w for w in suspicious_keywords if w in text]
        if found_keywords:
            for word in found_keywords:
                results.append({
                    "Detected Element": "Suspicious Claim",
                    "Matched External Evidence": f"Keyword found: '{word}'",
                    "Rule Triggered": "Unrealistic promise",
                    "Risk Category": "Fraud Risk",
                    "Severity": "High",
                    "Rationale": f"Website uses high-risk language: '{word}'"
                })
                score += 30
        else:
            results.append({
                "Detected Element": "Suspicious Claims",
                "Matched External Evidence": "No suspicious keywords found",
                "Rule Triggered": "None",
                "Risk Category": "None",
                "Severity": "Safe",
                "Rationale": "No unrealistic promises or fraud keywords detected"
            })

        # 2. Contact Information
        if not emails and not phones:
            results.append({
                "Detected Element": "Contact Information",
                "Matched External Evidence": "No email or phone found (homepage + /contact checked)",
                "Rule Triggered": "Missing contact details",
                "Risk Category": "Transparency Risk",
                "Severity": "Medium",
                "Rationale": "No contact information found — low transparency"
            })
            score += 15
        else:
            contact_found = []
            if emails:
                contact_found.append(f"Email: {emails[0]}")
            if phones:
                contact_found.append(f"Phone found")
            results.append({
                "Detected Element": "Contact Information",
                "Matched External Evidence": ", ".join(contact_found),
                "Rule Triggered": "None",
                "Risk Category": "None",
                "Severity": "Safe",
                "Rationale": "Contact information is present"
            })

        # 3. HTTPS Check
        if not url.startswith("https"):
            results.append({
                "Detected Element": "Website Security (SSL)",
                "Matched External Evidence": "No HTTPS detected",
                "Rule Triggered": "Insecure connection",
                "Risk Category": "Security Risk",
                "Severity": "High",
                "Rationale": "Website is not using HTTPS — data is not encrypted"
            })
            score += 30
        else:
            results.append({
                "Detected Element": "Website Security (SSL)",
                "Matched External Evidence": "HTTPS present",
                "Rule Triggered": "None",
                "Risk Category": "None",
                "Severity": "Safe",
                "Rationale": "Website uses HTTPS — secure connection"
            })

        # 4. Privacy Policy — BUG FIX 2
        if not has_privacy:
            results.append({
                "Detected Element": "Privacy Policy",
                "Matched External Evidence": "Not found in page text or links",
                "Rule Triggered": "Missing policy",
                "Risk Category": "Compliance Risk",
                "Severity": "Medium",
                "Rationale": "No privacy policy detected — compliance risk"
            })
            score += 15
        else:
            results.append({
                "Detected Element": "Privacy Policy",
                "Matched External Evidence": "Privacy policy link or text found",
                "Rule Triggered": "None",
                "Risk Category": "None",
                "Severity": "Safe",
                "Rationale": "Privacy policy is present"
            })

        # 5. Terms of Service
        if not has_terms:
            results.append({
                "Detected Element": "Terms of Service",
                "Matched External Evidence": "Not found",
                "Rule Triggered": "Missing terms",
                "Risk Category": "Compliance Risk",
                "Severity": "Low",
                "Rationale": "No terms of service page detected"
            })
            score += 10
        else:
            results.append({
                "Detected Element": "Terms of Service",
                "Matched External Evidence": "Terms link or text found",
                "Rule Triggered": "None",
                "Risk Category": "None",
                "Severity": "Safe",
                "Rationale": "Terms of service is present"
            })

        # -----------------------------------------------
        # C. EXTERNAL CORRELATION — WHOIS domain age
        # -----------------------------------------------
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                if age_days < 180:
                    results.append({
                        "Detected Element": "Domain Age",
                        "Matched External Evidence": f"Domain is only {age_days} days old",
                        "Rule Triggered": "New domain (< 6 months)",
                        "Risk Category": "Reputation Risk",
                        "Severity": "High",
                        "Rationale": "Newly registered domains are a common fraud signal"
                    })
                    score += 25
                else:
                    results.append({
                        "Detected Element": "Domain Age",
                        "Matched External Evidence": f"Domain is {age_days} days old ({age_days // 365} years)",
                        "Rule Triggered": "None",
                        "Risk Category": "None",
                        "Severity": "Safe",
                        "Rationale": "Domain has been active for a significant time"
                    })
            else:
                results.append({
                    "Detected Element": "Domain Age",
                    "Matched External Evidence": "Creation date not available in WHOIS",
                    "Rule Triggered": "Unable to verify",
                    "Risk Category": "Unknown Risk",
                    "Severity": "Low",
                    "Rationale": "Could not determine domain age"
                })

        except Exception as e:
            results.append({
                "Detected Element": "Domain Info (WHOIS)",
                "Matched External Evidence": "WHOIS lookup failed",
                "Rule Triggered": "Unable to verify",
                "Risk Category": "Unknown Risk",
                "Severity": "Low",
                "Rationale": f"Domain WHOIS data not available: {str(e)[:60]}"
            })

        # NOTE: Google scraping removed — it's blocked by CAPTCHA and always fails silently.
        # Use Google Custom Search API or SerpAPI for real search presence checks.

        # -----------------------------------------------
        # D. FINAL RISK RATING
        # -----------------------------------------------
        if score >= 60:
            overall = "High"
        elif score >= 30:
            overall = "Medium"
        else:
            overall = "Low"

        # BUG FIX 1 & 5: Always show a meaningful summary
        safe_count = sum(1 for r in results if r["Severity"] == "Safe")
        risk_count = sum(1 for r in results if r["Severity"] in ["High", "Medium"])

        return {
            "URL Analyzed": url,
            "Domain": domain,
            "Detailed Findings": results,
            "Overall Risk Score": score,
            "Overall Merchant Risk Rating": overall,
            "Safe Checks Passed": safe_count,
            "Risk Signals Found": risk_count
        }

    except Exception as e:
        return {"Error": str(e)}


# -----------------------------------------------
# STREAMLIT UI
# -----------------------------------------------
st.set_page_config(page_title="Website Risk Analyzer", page_icon="🛡️", layout="wide")
st.title("🛡️ Website Risk Analyzer")
st.caption("Analyzes any website for fraud signals, transparency issues, and security risks.")

url = st.text_input("Enter website URL", placeholder="https://example.com")

if st.button("Analyze", type="primary") and url:
    with st.spinner("Analyzing website..."):
        output = analyze_website(url)

    if "Error" in output:
        st.error(f"Could not analyze site: {output['Error']}")
    else:
        # Summary metrics
        rating = output["Overall Merchant Risk Rating"]
        score = output["Overall Risk Score"]
        color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(rating, "⚪")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Overall Rating", f"{color} {rating}")
        col2.metric("Risk Score", f"{score} / 100")
        col3.metric("Safe Checks", f"✅ {output['Safe Checks Passed']}")
        col4.metric("Risk Signals", f"⚠️ {output['Risk Signals Found']}")

        st.divider()
        st.subheader("Detailed Findings")

        findings = output.get("Detailed Findings", [])
        if not findings:
            st.success("No findings — site appears clean.")
        else:
            for item in findings:
                sev = item["Severity"]
                icon = {"High": "🔴", "Medium": "🟡", "Low": "🔵", "Safe": "🟢"}.get(sev, "⚪")
                with st.expander(f"{icon} {item['Detected Element']} — {sev}"):
                    st.write(f"**Rule triggered:** {item['Rule Triggered']}")
                    st.write(f"**Evidence:** {item['Matched External Evidence']}")
                    st.write(f"**Risk category:** {item['Risk Category']}")
                    st.write(f"**Rationale:** {item['Rationale']}")
