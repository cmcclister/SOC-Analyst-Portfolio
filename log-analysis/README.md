# Investigation #1 — Suspicious Authentication Activity"
**TryHackMe NetworkMiner Case Study**

---

## Summary

This document presents a systematic incident investigation based on analysis of network traffic captured in a controlled laboratory environment. The investigation demonstrates core Security Operations Center (SOC) analyst competencies including artifact collection, hypothesis development, timeline reconstruction, and incident classification using industry-standard frameworks.

**Investigation Scope:** Network traffic analysis using packet capture (PCAP) and file extraction via NetworkMiner  
**Lab Platform:** TryHackMe - Network Traffic Analysis NetworkMiner Lab  
**Analysis Date:** 2026-10-28  
**Analyst:** Christopher McClister

---

## Investigation Framework

This investigation follows the **NIST Incident Response Lifecycle (SP 800-61 Revision 3)**, specifically addressing the **Detection and Analysis** phase.

---

## 1. Alert Definition

### The Alert
**Network-based detection of plaintext credential exposure in HTTP traffic combined with suspicious redirect to external tracking domain.**

### Alert Characteristics
| Attribute | Value |
|-----------|-------|
| **Detection Type** | Network-based (Packet Analysis) |
| **Alert Classification** | Credential Exposure and Suspicious Domain Redirect |
| **Alert Severity** | **HIGH** |
| **Detection Method** | PCAP analysis via NetworkMiner file extraction |
| **Triggering Indicators** | Plaintext email credentials, external redirect domain, tracking pixel mechanism |

### Why This Matters
Credentials exposed in HTTP traffic represent a **CRITICAL** risk vector. The presence of external redirect infrastructure suggests potential credential harvesting or unauthorized credential usage tracking by an external threat actor.

---

## 2. Initial Hypothesis

### Hypothesis Statement
**A system or user on the monitored network has transmitted email account credentials in plaintext via HTTP, likely as part of web form submission or authentication attempt. This same traffic session contains a redirect to an external tracking/synchronization domain, suggesting either:**

- **Scenario A (Primary):** Compromised web application capturing credentials for exfiltration.
- **Scenario B:** Phishing landing page harvesting credentials.
- **Scenario C:** Legitimate service with insecure credential handling (misconfiguration).

### Supporting Logic
1. **Plaintext credentials in HTTP** = Absence of HTTPS/TLS encryption.
2. **External redirect domain** = Potential C2 or tracking infrastructure.
3. **Tracking pixel pattern** = `367408.gif` with encoded parameters; this is a common credential exfiltration method.
4. **Email account involved** = High-value target for lateral movement and persistence.

### Hypothesis Risk Rating
**CRITICAL** - Assumes active credential compromise until proven otherwise.

---

## 3. User Identification

### Affected Account (Sanitized)
| Field | Value |
|-------|-------|
| **Email Address (Sanitized)** | `[REDACTED]@gmx.com` |
| **Original Format** | `[firstname].[lastname-indicator]@gmx.com` |
| **Email Provider** | GMX (Web.de Group) |
| **Account Status** | Unknown from PCAP analysis alone |

### User Attribution Analysis
From PCAP alone, we can infer:
- **Account naming pattern:** Suggests either test account (`[REDACTED]` subdomain indicator) or compromised account
- **Email service:** Public email provider (GMX) = consumer-grade security, not enterprise-managed
- **Risk implication:** Account compromise likely not detected by enterprise monitoring if this were real

### Investigation Follow-up Questions
*In production IR, these would be escalation points:*
- Is this account an employee or external user?
- When was this account last accessed from legitimate location?
- Has account recovery/password reset been initiated?

---

## 4. Source IP Address

### Primary Source IP
| Attribute | Value |
|-----------|-------|
| **Source IP Address (Sanitized)** | `[REDACTED]` |
| **Original IP** | `46.228.164.[REDACTED]` |

### IP Risk Assessment
| Factor | Analysis |
|--------|----------|
| **Is it internal?** | No - public routable space |
| **Threat context** | External IP + credential exfiltration = **INCIDENT** |

### Geographic/Network Intelligence
*In production, you would:*
1. Query WHOIS database for ASN and ISP.
2. Use GeoIP to identify country/region.
3. Cross-reference against known malicious IP databases.
4. Check if IP appears in threat feeds.

---

## 5. Destination Asset / Target

### Primary Destination
| Attribute | Value |
|-----------|-------|
| **Destination Domain (Sanitized)** | `[REDACTED-sync].rlcdn.com` |
| **Domain Purpose** | Credential synchronization / ID tracking |
| **Protocol** | HTTP (no encryption) |
| **Full URL Path (Sanitized)** | `http://[REDACTED]/[ENCODED-PARAMETER]?partner_uid=[REDACTED]` |

### Threat Assessment
| Aspect | Finding |
|--------|---------|
| **Domain Legitimacy** | Suspicious - synchronization domain pattern |
| **Trust Level** | Untrusted - external, unrelated to credential context |
| **Likely Purpose** | Credential exfiltration or account enumeration |
| **Severity** | **CRITICAL** |

### Asset Impact Determination
- **Asset Type:** External third-party tracking infrastructure
- **Asset Owner:** Unknown (likely malicious actor or compromised service)
- **Data Exposure:** Email credentials, user identifiers, behavioral tracking
- **Indicator Status:** Should be added to **Blocked Domain** list

---

## 6. Timestamp Analysis

### Event Timestamp (Frame 19184)
| Field | Value |
|-------|-------|
| **Frame Number** | 19184 |
| **Event Timestamp (UTC)** | `2015-03-06 14:05:34` |
| **Date** | March 6, 2015 |
| **Time** | 2:05:34 PM UTC |

### Timeline Context
```
2015-03-06 14:05:34 UTC
├─ Year: 2015 (historical lab data)
├─ Day of Week: Friday
├─ Business Hours?: Yes (if UTC-5 EST) or Evening (if UTC+0 GMT)
└─ Shift Implications: Timing suggests possible business hours attack
```

---

## 7. Relevant Logs & Evidence

### Evidence Collection (NetworkMiner Output)

| Evidence Category | Details | Location |
|------------------|---------|----------|
| **PCAP File** | case2.pcap | `/home/ubuntu/Desktop/NetworkMiner_[version]/` |
| **Extracted File** | 367408.gif | `/home/ubuntu/Desktop/NetworkMiner_[version]/AssembledFiles/46.228.164.[REDACTED]/TCP-80/r/dd/id/` |
| **Frame Reference** | Frame 19184 | Packet capture frame number |
| **Protocol** | HTTP | Layer 4 protocol |
| **Port** | TCP/80 | Standard web traffic |

### Log Evidence Hierarchy

In a production environment, you would examine logs in this priority order:

#### 1. **Network Logs (Highest Priority)**
```
Source IP:      46.228.164.[REDACTED]
Destination IP: [Target web server]
Port:           TCP 80
Protocol:       HTTP
Timestamp:      2015-03-06 14:05:34 UTC
Method:         GET or POST
URI:            [Endpoint containing credential submission]
User-Agent:     [Browser identification]
Referrer:       [Source page]
Status Code:    200 (if successful) or 30x (if redirect)
```

#### 2. **Web Application Logs** (2nd Priority)
- HTTP request logs with full URI/query parameters
- POST body (if available)
- Authentication attempt records
- Session initiation logs

#### 3. **Endpoint Logs** (3rd Priority - From source IP)
- Browser history
- DNS query logs (to track domain resolution)
- Network adapter logs
- File download logs

#### 4. **Email Logs** (4th Priority - If account is monitored)
- Login history for affected email account
- Geographic anomalies
- Device/IP changes for account access
- Recovery email/phone changes

---

## 8. Indicators of Compromise (IOCs)

### IOC Inventory

| IOC Type | Indicator (Sanitized) | Confidence | TTL |
|--------------------|-----------------------------------------|------------|-------------|
| **IP Address**     | `[REDACTED]`                            | High       | 30 day
| **Domain**         | `[REDACTED-sync].rlcdn.com`             | Critical   | Long-ter
| **Email**          | `[REDACTED]@gmx.com`                    | Critical   | Immediate
| **URL Path**       | `[REDACTED]/[ENCODED]?partner_uid=[ID]` | Critical   | Immediate
| **File Hash**      | [MD5/SHA256 of 367408.gif]              | Medium     | Medium-term
| **Tracking Pixel** | `367408.gif`                            | Medium     | Medium-term

### IOC Actionability

#### **Immediate Action Items**
1. **Email Account:** Reset password, review recovery options, enable 2FA.
2. **Domain Blocks:** Add `[REDACTED-sync].rlcdn.com` to firewall blocklist and DNS sinkhole.
3. **IP Block:** Consider blocking `46.228.164.[REDACTED]` at perimeter (evaluate impact).

#### **Short-term IOC Actions (24-48 hours)**
1. **Hash Analysis:** Submit file hash to VirusTotal.
2. **Domain Reputation:** Check against PhishTank, URLhaus, Shodan.
3. **IP Reputation:** Query AbuseIPDB, Shodan, Censys.
4. **Threat Feed Distribution:** Share IOCs with industry ISACs.

#### **Long-term IOC Management**
1. Add to enterprise YARA rules.
2. Update EDR/XDR detection signatures.
3. Distribute to SIEM correlation engines.
4. Archive for historical threat intelligence.

---

## 9. Timeline Reconstruction

Incident Progression Matrix:

| Phase | Timeline | Key Events | Investigation Status |
|--------------|-----------------------------|------------------------|----------------------|
| Detection      | T+0 (2015-03-06 14:05:34)   | Credential exposure    | IDENTIFIED |
| Confirmation   | T+1-30 minutes              | File extraction        | CONFIRMED |
| Investigation  | T+1-24 hours                | Log analysis           | IN PROGRESS |
| Containment    | T+24-48 hours               | Password reset, block  | RECOMMENDED |
| Recovery       | T+48-72 hours               | Account monitoring     | ONGOING |
| Post-Incident  | T+7-30 days                 | Lessons learned        | PLANNED |

---

## 10. MITRE ATT&CK Mapping

### Tactical Mapping

| ATT&CK Tactic | Techniques | Real-world Mapping | Evidence from Lab |
|---------------|-----------|-------------------|------------------|
| **TA0006: Credential Access** | T1187, T1111, T1056 | Harvesting valid credentials | Plaintext credentials in HTTP |
| **TA0007: Discovery** | T1087 | Account enumeration post-compromise | Email address and tracking ID |
| **TA0008: Lateral Movement** | T1078 | Use of stolen credentials for access | Credential exposure likely enables this |
| **TA0009: Collection** | T1123, T1185 | Gathering account information | Tracking pixel collects user identifiers |

## 11. What is the true-positive/false-positive determination?

- **Credential exposure:** True positive as a data-handling/security finding if the PCAP confirms the credential is present. Whether it was transmitted in cleartext, and whether it is valid, still requires verification.
- **Malicious activity or compromise:** Undetermined. A tracking URL and exposed credential alone do not establish malicious intent, credential theft, or account takeover.

## 12. Recommended Response

- Keep the credential redacted; if it could be real, notify the owner through an appropriate channel and advise changing it anywhere it was reused. Revoke sessions and enable MFA where applicable.
- Preserve the original PCAP and work from a copy. Record hashes, tool versions, timezone assumptions, and relevant frame/stream references.
- Verify the protocol, direction, and payload around the credential and frame 19184; correlate with DNS, proxy, endpoint, and authentication telemetry.
- Escalate or block the hostname only if organizational policy and corroborating evidence support that action. Do not block solely because a tracking URL appears in a lab capture.

## 13. Lessons Learned

- NetworkMiner is a PCAP parser that can extract files and credentials.
- Use NetworkMiner for a quick artifact overview, then validate important findings in packet-level detail.
- Preserve evidence and document reproducible steps, timestamps, timezone, and confidence.
- Separate a confirmed exposure from an unproven compromise or malicious indicator.
