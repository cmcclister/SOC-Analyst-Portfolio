# Web Attack Investigation: Directory Fuzzing, Brute Force, and SQL Injection

**Investigation #3** | **Source:** TryHackMe, *Detecting Web Attacks*, Task 4: Log-Based Detection
**Focus:** Application security and SOC analysis

---

## Summary

This investigation follows a single external IP through a complete web attack chain. The attacker used **directory fuzzing with FFUF** to map the application, **brute-forced the login form with Hydra** to obtain valid access, and then **exploited a SQL injection flaw** in the account area. The entire sequence occurred in **42 seconds** on August 20, 2025, between 07:37:38 and 07:38:20 UTC.

| Stage | Evidence (log lines) | Technique | MITRE ATT&CK |
|---|---|---|---|
| Reconnaissance | Lines 1-13: FFUF user agent, 200 and 404 responses to common paths | Directory and endpoint fuzzing | T1595.003 (Wordlist Scanning) |
| Credential access | Lines 14-35: Hydra user agent, rapid repeated requests to `/login.php` | Password brute force | T1110.001 (Password Guessing) |
| Initial access | Line 33: `302` response to a POST at `/login.php` | Valid credentials obtained | T1078 (Valid Accounts) |
| Exploitation | Line 38: SQLi payload in `/account/changeusername.php`, sent by sqlmap | SQL injection | T1190 (Exploit Public-Facing Application) |

---

## Environment and Scope

The web application is a PHP-based site with endpoints including `/login.php`, `/account/`, and `/account/changeusername.php`. The Apache-style access log records the client IP, timestamp, request line, status code, response size, and user agent for each request. The source IP is redacted as `192.168.1.[REDACTED]` in this report.

The analysis covers only the 38 log entries in the access log for this IP. I did not have access to the application's source code, server error logs, or authentication logs, so some conclusions are inferences, which I note where they apply.

---

## 1. HTTP Request Analysis

The attacker began with **automated directory and endpoint discovery**. The requests are simple `GET` requests against common paths such as `/images`, `/manage`, `/corporate`, `/company`, `/files`, `/adminpanel`, and `/jobs`. Most returned **404 Not Found**, but several returned **200 OK**: `/login.php` (line 1), `/home` (line 8), `/catalog` (line 9), and `/products` (line 10).

From a developer's perspective, this pattern is a wordlist being fed through a fuzzer. Each path is a guess at a route that might exist, and the response code tells the attacker whether it does. A 200 on `/login.php` is the most valuable result for an attacker because it exposes an authentication surface.

---

## 2. Application Behavior

The application responded normally to every request, so there was no crash or error. Its behavior is what made the attack succeed:

- **The login form accepted unlimited attempts.** Over 20 login requests arrived within seconds with no visible throttling, lockout, or CAPTCHA. The server returned 200 responses to each one, and no request was blocked.
- **A successful login returned a redirect.** At line 33, the server answered the POST with `302`, which typically means "redirect to another page." Since the attacker's next request went to `/account`, the redirect was most likely to the account page. This is an inference. Confirming it would require the response's `Location` header or the response body.
- **The account area accepted unsanitized input.** The request at line 38 passed a value containing SQL syntax into a query parameter, and the server returned 200 with a 289-byte response. The response size is consistent with a successful query returning data, though I'd confirm this against the application's real response behavior.

---

## 3. Log Evidence

The timeline below is taken from the access log.

| Time (UTC) | Line(s) | Method and path | Status | User agent | Significance |
|---|---|---|---|---|---|
| 07:37:38 | 1 | GET `/login.php` | 200 | FFUF v2.1.0 | Login page discovered |
| 07:37:38 | 2-7 | GET various paths | 404 | FFUF v2.1.0 | Enumeration misses |
| 07:37:38 | 8-10 | GET `/home`, `/catalog`, `/products` | 200 | FFUF v2.1.0 | Valid content found |
| 07:37:38-40 | 11-13 | GET `/features`, `/adminpanel`, `/jobs` | 404 | FFUF v2.1.0 | Enumeration misses |
| 07:38:09 | 14-24 | GET `/login.php` (HTTP/1.0) | 200 | Mozilla/5.0 (Hydra) | Hydra probing the login form |
| 07:38:09 | 25-35 | POST `/login.php` | 200, except line 33 | Mozilla/5.0 (Hydra) | Brute-force attempts; line 33 returns 302 |
| 07:38:09 | 36 | GET `/account` | 301 | Mozilla/5.0 (Hydra) | Redirect after successful login |
| 07:38:09 | 37 | GET `/account/` | 200 | Mozilla/5.0 (Hydra) | Authenticated account page |
| 07:38:20 | 38 | GET `/account/changeusername.php?q=%25%27+OR+%271%27%3D%271` | 200 | sqlmap/stable | SQL injection payload |

Two details in this table matter for detection. First, the user agent changes from FFUF to Hydra at line 14, which suggests the attacker switched tools between reconnaissance and credential attacks. Second, line 38 comes from **sqlmap**, not from a manual browser session, which indicates automated SQL injection testing.

### Decoding the Final Request

The raw query string is `q=%25%27+OR+%271%27%3D%271`. URL decoding gives:

| Encoded | Decoded | Meaning |
|---|---|---|
| `%25` | `%` | Wildcard character, which suggests the input closes a `LIKE` pattern |
| `%27` | `'` | Single quote, which closes the string literal |
| `+` | (space) | Space |
| `OR` | `OR` | Boolean operator |
| `%27%31%27` | `'1'` | String literal |
| `%3D` | `=` | Equality operator |

The decoded payload is **`%' OR '1'='1`**. The `'1'='1'` condition is always true, so when the application inserts this value into a SQL query, the WHERE clause matches every row. The leading `%'` suggests the vulnerable query was something like `LIKE '%{input}%'`, where the input breaks out of the pattern and quote.

---

## 4. Attack Technique

The attack followed a standard **reconnaissance → credential access → exploitation** chain.

**Reconnaissance (FFUF):** FFUF is an open-source web fuzzer. The attacker used a wordlist to test paths quickly, and the 200 responses told them which endpoints existed.

**Credential access (Hydra):** Hydra is a network login brute-forcer. The repeated POSTs to `/login.php` in quick succession show automated password guessing. The attacker needed only one successful guess, which arrived at line 33.

**Exploitation (sqlmap):** sqlmap is an automated SQL injection tool. The payload at line 38 is a classic boolean-based test. Its user agent indicates that the attacker used sqlmap to confirm and probably extract data from the injectable parameter.

---

## 5. Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| Source IP | `192.168.1.[REDACTED]` | Originated all 38 requests |
| User agent | `FFUF v2.1.0` | Reconnaissance, lines 1-13 |
| User agent | `Mozilla/5.0 (Hydra)` | Brute force and post-login activity, lines 14-37 |
| User agent | `sqlmap/stable` | SQL injection, line 38 |
| URI pattern | `/account/changeusername.php?q=%' OR '1'='1` | SQLi payload (encoded form: `%25%27+OR+%271%27%3D%271`) |
| Timing | 20+ POSTs to `/login.php` within seconds | Brute-force signature |

---

## 6. Detection Logic

Each detection below maps to one stage of the attack. None of them depends on a single indicator, which makes the detections harder to evade.

### Detection 1: Known Attack-Tool User Agents

Requests whose user agent identifies a fuzzing, brute-force, or SQLi tool should alert. Attackers can change user agents, but many leave defaults in place, as this attacker did.

```
user_agent contains any of ["FFUF", "Hydra", "sqlmap", "Nikto", "gobuster"]
```

### Detection 2: Brute-Force Pattern on Authentication Endpoints

Multiple POSTs to the same login endpoint from one source IP within a short window should trigger an alert. In this case, more than 20 attempts occurred in under 15 seconds.

```
count(POST /login.php) by src_ip > 10 within 60 seconds
```

### Detection 3: Authentication Success After a Failure Burst

A successful login (302 redirect) that follows a burst of failed attempts from the same IP is the strongest signal that credentials were guessed rather than typed.

```
POST /login.php with status 302 AND prior failed logins from same src_ip within 5 minutes
```

### Detection 4: SQL Injection Patterns in Query Parameters

Decoding the query string before matching is necessary, because attackers encode payloads to evade simple filters. Matching on decoded values catches `' OR '1'='1`, `UNION SELECT`, and similar patterns.

```
url_decode(query_string) matches regex (?i)('|%27)\s*(or|and)\s*('|%27)?\d+('|%27)?\s*=
```

### Detection 5: Scanning Behavior

Many 404s followed by 200s from one IP within a short window indicates enumeration. This is a lower-confidence signal on its own, but useful in correlation.

```
count(status=404) by src_ip > 10 within 60 seconds
```

---

## 7. Response and Remediation

### Immediate Containment

- **Block the source IP** at the firewall or WAF. This stops the current attacker, but it is a weak long-term control because attackers can change IPs easily.
- **Invalidate the session** for any account that was accessed through the brute-forced login. The credentials used at line 33 should be treated as compromised.
- **Force a password reset** for the affected account and review what the account could access.
- **Review the database** for unauthorized reads or writes made through the injectable parameter, and check whether sqlmap extracted data.

### Short-Term Fixes

- **Rate-limit and lock out login attempts** by both IP and account. For example, delay after 5 failures and lock the account after 10 within 15 minutes.
- **Add CAPTCHA or MFA** to the login flow. MFA would have stopped the attacker even after the correct password was guessed.
- **Enable WAF rules** for SQLi signatures and known attack-tool user agents.

### Long-Term Fix (Root Cause)

The root cause of the SQL injection is that user input was concatenated directly into a SQL query. The fix belongs in the code:

- **Use parameterized queries (prepared statements)** so the database treats user input as data, never as SQL. This is the primary control.
- **Validate input against an allowlist** where possible. A username field should accept only the characters a username can contain.
- **Apply least privilege** to the database account the web application uses, so a successful injection can access less.

Input sanitization alone is not enough. Blocklists are easy to bypass with encoding, which is why this payload was URL-encoded in the first place. Parameterized queries eliminate the class of vulnerability rather than trying to filter each payload.

---

## 8. Analyst Notes

The most useful takeaway from this investigation is that **no single log line proves the attack by itself**. The FFUF user agent suggests scanning, but scanners are common on the internet. The 302 is the first real evidence of compromise, and the sqlmap user agent confirms that the SQLi was deliberate. Correlating the tool, timing, response code, and payload together turns individual suspicious events into a confirmed incident.

The investigation also shows that the attacker's path was predictable from the logs. A SIEM alert on the Hydra user agent or the brute-force pattern would have fired around 07:38:09, roughly 11 seconds before the account was accessed, which leaves time to respond before the SQLi at 07:38:20.

---

## Development Background Perspective

This investigation draws on a web developer's understanding of HTTP. Recognizing that `%27` is a single quote, that `+` is a space in query strings, and that a 302 is a redirect rather than an error is knowledge gained from building web applications. The same knowledge explains why the vulnerability existed: the payload works because the application built its SQL by string concatenation, which is a mistake developers commonly make. Understanding both sides of the request makes it easier to write detections that match real attacker behavior and fixes that address root causes.
