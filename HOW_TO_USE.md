# 🛡️ ThreatIQ — User Guide (How to Use)

Welcome to **ThreatIQ**! This guide walks you through everything you need to know to get started, run security investigations, interpret risk scores, and interact with the AI Copilot.

---

## 🚀 1. Quick Start: Launching ThreatIQ

### Option A: Using Docker (Recommended)
Open your terminal and run:

```bash
cd Threat-IQ
docker compose up -d --build
```

- 🌐 **Web Dashboard**: Open [http://localhost:8501](http://localhost:8501) in your browser.
- 📚 **API Documentation**: Open [http://localhost:8000/docs](http://localhost:8000/docs).

### Option B: Stopping the Services
When you are done, run:
```bash
docker compose down
```

---

## 🔍 2. How to Run an Investigation

ThreatIQ acts as your automated SOC analyst. You give it a target, and it runs multi-agent scans, builds a threat graph, computes a deterministic risk score, and gives you a remediation plan.

### Step 1: Open the Dashboard
Navigate to [http://localhost:8501](http://localhost:8501) and click **Investigate** in the left sidebar.

### Step 2: Enter an Indicator
You can paste any of the following into the input box:

| Indicator Type | Example Input | What ThreatIQ Does |
|---|---|---|
| **URL** | `https://paypa1-secure-login.tk/verify` | Scans reputation, checks redirects, inspects headers, runs DNS lookup |
| **Domain** | `paypa1-secure-login.tk` | Checks typo-squatting/brand impersonation, WHOIS/RDAP, DNS records |
| **IP Address** | `185.220.101.5` | Checks abuse reports, geo-location, passive DNS |
| **File Hash** | `44d88612fea8a8f36de82e1278abb02f` (MD5/SHA256) | Queries VirusTotal multi-engine antivirus detection |
| **CVE ID** | `CVE-2024-3400` | Pulls CVSS score, EPSS exploit probability, and CISA KEV exploitation data |
| **Phishing Email** | *(Raw email with headers)* | Parses headers, SPF/DKIM/DMARC authentication, body links, sender spoofing |

### Step 3: Click "Investigate"
ThreatIQ will automatically:
1. Classify the input.
2. Extract all embedded indicators (IPs, domains, links).
3. Dispatch specialist agents in parallel.
4. Calculate risk scores and map findings to security standards.

---

## 📊 3. Understanding the Investigation Report

Once the scan completes, your report is divided into easy-to-read sections:

### 1. The Risk Score (0 to 100)
- 🔴 **Critical (80–100)**: Active threat, confirmed malware, or exploited vulnerability.
- 🟠 **High (60–79)**: High-probability threat, suspicious infrastructure, or unpatched high-severity CVE.
- 🟡 **Medium (40–59)**: Suspicious signals or poor security hygiene.
- 🟢 **Low / Benign (0–39)**: Clean reputation, normal services, or low risk.

> 💡 **Why Trust the Score?**  
> The score is computed using **deterministic math** based on factual evidence from security APIs. The AI is only used to summarize findings—it **never invents or guesses numbers**.

### 2. Coverage & Confidence
- **Coverage**: Tells you how many threat intelligence feeds were available.
- If you haven't entered an API key (like VirusTotal), ThreatIQ excludes that factor rather than counting it as "safe". Missing data lowers **confidence**, never the security score.

### 3. Interactive Threat Graph
- Switch to the **Threat Graph** tab to see an interactive visual map showing how the submitted indicator connects to domains, IPs, servers, and malware campaigns.

### 4. Framework & Compliance Mapping
- Findings are automatically tagged and mapped to:
  - **MITRE ATT&CK** (Tactics & Techniques)
  - **OWASP Top 10**
  - **CWE** (Common Weakness Enumeration)
  - **NIST CSF** (Cybersecurity Framework)

### 5. Remediation Plan
- A step-by-step checklist prioritized by urgency (e.g., block IP on firewall, revoke credentials, apply CVE patch).

---

## 🤖 4. Using the AI Copilot

Need deeper insights or advice on next steps?

1. Click the **Ask Copilot** button at the top of any investigation report (or select **Copilot** in the sidebar).
2. Click any of the **Quick Starter Questions** (e.g., *"How do I fix this?"*, *"Is this IP safe?"*) or type your own question.
3. The Copilot will answer strictly based on the collected evidence and security playbooks.

---

## 🔑 5. Adding Free API Keys (Optional)

ThreatIQ works right away **without any API keys** (9 out of 15 tools run completely free with no key required).

To unlock deeper lookups (like VirusTotal or AbuseIPDB):

### Method 1: In the Web UI (Recommended for Privacy)
1. Go to the **API keys** page in the left sidebar.
2. Paste your free-tier keys (e.g., VirusTotal, AbuseIPDB, Groq).
3. Click **Test keys**.
4. *Your keys are saved only in your current browser session and never stored to disk or shared with other users.*

### Method 2: In `.env` (For Server/Single-User Deployments)
1. Copy `.env.example` to `.env`.
2. Fill in your keys (e.g., `VIRUSTOTAL_API_KEY=your_key_here`).
3. Restart the container: `docker compose up -d --build`.

*(See [`KEYS.md`](./Threat-IQ/KEYS.md) for direct links to get free keys).*

---

## 🧪 6. Sample Inputs to Test Right Now

Try copying and pasting any of these into the **Investigate** box:

### A. Active Exploit CVE
```text
CVE-2024-3400
```
*(Demonstrates CVSS score, CISA KEV active exploitation flags, and patch guidance).*

### B. Suspicious Phishing Email Sample
```text
From: "PayPal Security" <alerts@paypa1-secure-login.tk>
Reply-To: harvest@mail.ru
Subject: Your account has been limited

Please verify your credentials immediately: https://paypa1-secure-login.tk/verify
```
*(Demonstrates header analysis, lookalike domain detection, and IOC extraction).*

### C. Public DNS / IP Indicator
```text
1.1.1.1
```
*(Demonstrates clean reputation, Cloudflare ASN resolution, and low-risk classification).*

---

## ❓ Frequently Asked Questions (FAQ)

- **Q: What does "Skipped" or "No API Key" in the evidence table mean?**  
  **A:** It means that specific third-party provider (e.g., VirusTotal) was not configured. The pipeline safely skips it without failing your scan.

- **Q: How do I share a report with a team member?**  
  **A:** Copy the URL with the investigation parameter: `http://localhost:8501/?investigation=<id>`.

- **Q: Can I run active scans?**  
  **A:** Active probes and vulnerability scans are strictly locked behind an authorization allowlist in `config.py` so you only scan systems you own.
