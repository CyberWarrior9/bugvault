---
tags: [moc, report-study]
---

# Report Studies — MOC

85 top-voted, bounty-paid HackerOne reports (stratified across vulnerability classes).
Source: HackerOne official disclosed-reports dataset (train split).
Each dossier: `rs-<h1_id>.md` — attack narrative, why it paid, technique links, full text.

## Index (by votes)

| id | class | weakness | team | votes | chars | primitives |
|---|---|---|---|---|---|---|
| [[rs-745324]] | [[auth-bypass]] | Improper Authentication - Generic | security | 1540 | 250 | auth-bypass, info-leak |
| [[rs-827052]] | [[file-read]] | Path Traversal | gitlab | 1453 | 2693 | file-read |
| [[rs-470520]] | [[memory-safety]] | Classic Buffer Overflow | valve | 1270 | 14754 | memory-safety, ato, info-leak |
| [[rs-591295]] | [[rce]] | OS Command Injection | x | 1189 | 4873 | rce, file-read, rce-confirmed |
| [[rs-489146]] | [[info-disclosure]] | Information Disclosure | security | 995 | 1358 | info-disclosure, info-leak |
| [[rs-921780]] | [[auth-bypass]] | Improper Authentication - Generic | snapchat | 916 | 3905 | auth-bypass, ato |
| [[rs-737140]] | [[http-smuggling]] | HTTP Request Smuggling | slack | 835 | 4810 | http-smuggling, session-theft, ato |
| [[rs-422944]] | [[rce]] | Command Injection - Generic | shopify | 817 | 3166 | rce, rce-confirmed, ssrf-chain |
| [[rs-403417]] | [[rce]] | Command Injection - Generic | semrush | 800 | 1915 | rce, file-read, rce-confirmed |
| [[rs-658013]] | [[rce]] | Command Injection - Generic | gitlab | 762 | 3698 | rce, rce-confirmed |
| [[rs-826026]] | [[memory-safety]] | Use After Free | playstation | 715 | 766 | memory-safety, priv-esc, rce-confirmed |
| [[rs-297478]] | [[sqli]] | SQL Injection | gsa_bbp | 679 | 2637 | sqli, sqli-proof |
| [[rs-846338]] | [[xss]] | Cross-site Scripting (XSS) - Reflected | glassdoor | 642 | 1686 | xss, session-theft |
| [[rs-792927]] | [[idor-bola]] | Improper Authorization | security | 633 | 1135 | idor-bola, pii-exposure, info-leak |
| [[rs-129873]] | [[auth-bypass]] | Improper Authentication - Generic | x | 591 | 2879 | auth-bypass, ato |
| [[rs-484434]] | [[xss]] | Cross-site Scripting (XSS) - Stored | imgur | 591 | 1234 | xss, xss-exec |
| [[rs-807448]] | [[info-disclosure]] | Information Disclosure | security | 568 | 1253 | info-disclosure, info-leak |
| [[rs-771666]] | [[http-smuggling]] | HTTP Request Smuggling | zomato | 545 | 7400 | http-smuggling, session-theft, ato |
| [[rs-910300]] | [[privilege-escalation]] | Privilege Escalation | shopify | 536 | 1820 | privilege-escalation, ato |
| [[rs-764434]] | [[dos]] | Uncontrolled Resource Consumption | security | 464 | 3896 | dos |
| [[rs-409850]] | [[xss]] | Cross-site Scripting (XSS) - Stored | valve | 462 | 810 | xss, rce-confirmed, info-leak |
| [[rs-684092]] | [[input-validation]] | Improper Input Validation | makerdao_bbp | 461 | 3079 | input-validation |
| [[rs-1567186]] | [[idor-bola]] | Improper Access Control - Generic | reddit | 455 | 9836 | idor-bola, xss-exec |
| [[rs-146336]] | [[xss]] | Cross-site Scripting (XSS) - Generic | slack | 443 | 906 | xss, xss-exec |
| [[rs-2262382]] | [[ssrf]] | Server-Side Request Forgery (SSRF) | security | 417 | 195 | ssrf, ssrf-chain |
| [[rs-1888915]] | [[idor-bola]] | Improper Access Control - Generic | mattermost | 400 | 740 | idor-bola |
| [[rs-850447]] | [[info-disclosure]] | Information Disclosure | gitlab | 400 | 6526 | info-disclosure, file-read |
| [[rs-1032468]] | [[privilege-escalation]] | Privilege Escalation | x | 395 | 931 | privilege-escalation |
| [[rs-314808]] | [[idor-bola]] | Improper Access Control - Generic | reverb | 386 | 1168 | idor-bola |
| [[rs-423467]] | [[business-logic]] | Business Logic Errors | shopify | 365 | 8822 | business-logic |
| [[rs-481472]] | [[unclassified]] | Phishing | slack | 356 | 1310 | unclassified |
| [[rs-409395]] | [[input-validation]] | Improper Input Validation | gitlab | 355 | 1113 | input-validation, file-read, info-leak |
| [[rs-509924]] | [[info-disclosure]] | Information Disclosure | gitlab | 354 | 4074 | info-disclosure |
| [[rs-1133118]] | [[business-logic]] | Business Logic Errors | security | 344 | 761 | business-logic |
| [[rs-826361]] | [[ssrf]] | Server-Side Request Forgery (SSRF) | gitlab | 342 | 4576 | ssrf, ssrf-chain, info-leak |
| [[rs-905607]] | [[auth-bypass]] | Improper Authentication - Generic | cs_money | 338 | 1515 | auth-bypass, ato |
| [[rs-632101]] | [[ssrf]] | Server-Side Request Forgery (SSRF) | gitlab | 333 | 2161 | ssrf, rce-confirmed, ssrf-chain |
| [[rs-786044]] | [[sqli]] | SQL Injection | mailru | 330 | 1383 | sqli, sqli-proof |
| [[rs-210779]] | [[dos]] | Uncontrolled Resource Consumption | x | 319 | 2122 | dos, csrf-action |
| [[rs-397545]] | [[memory-safety]] | Classic Buffer Overflow | valve | 318 | 1724 | memory-safety, rce-confirmed |
| [[rs-999789]] | [[business-logic]] | Business Logic Errors | security | 314 | 1371 | business-logic |
| [[rs-333419]] | [[ssrf]] | Server-Side Request Forgery (SSRF) | slack | 312 | 1799 | ssrf, ssrf-chain |
| [[rs-500515]] | [[xxe]] | XML External Entities (XXE) | starbucks | 311 | 2172 | xxe, pii-exposure, info-leak |
| [[rs-630462]] | [[memory-safety]] | Heap Overflow | putty_h1c | 307 | 4025 | memory-safety, rce-confirmed |
| [[rs-665398]] | [[privilege-escalation]] | Privilege Escalation | starbucks | 303 | 1385 | privilege-escalation, ato |
| [[rs-894569]] | [[business-logic]] | Business Logic Errors | gitlab | 300 | 4344 | business-logic |
| [[rs-498964]] | [[unclassified]] | Incorrect Authorization | gitlab | 300 | 2186 | unclassified, info-leak |
| [[rs-703972]] | [[ato]] | Weak Password Recovery Mechanism for Forgotten Password | pixiv | 298 | 1385 | ato |
| [[rs-1439593]] | [[file-read]] | Path Traversal | gitlab | 295 | 5385 | file-read |
| [[rs-807924]] | [[csrf]] | Cross-Site Request Forgery (CSRF) | shopify | 292 | 2344 | csrf, info-leak, csrf-action |
| [[rs-867952]] | [[http-smuggling]] | HTTP Request Smuggling | helium | 289 | 2614 | http-smuggling, priv-esc |
| [[rs-662287]] | [[unclassified]] | UI Redressing (Clickjacking) | gitlab | 277 | 3804 | unclassified |
| [[rs-2281075]] | [[privilege-escalation]] | Privilege Escalation | teleport | 258 | 1525 | privilege-escalation, priv-esc |
| [[rs-396954]] | [[unclassified]] | Deserialization of Untrusted Data | rootstocklabs | 256 | 13788 | unclassified |
| [[rs-248668]] | [[xxe]] | XML External Entities (XXE) | x | 251 | 3758 | xxe, priv-esc, file-read |
| [[rs-683298]] | [[open-redirect]] | Open Redirect | x | 233 | 907 | open-redirect, xss-exec |
| [[rs-1181946]] | [[dos]] | Uncontrolled Resource Consumption | security | 212 | 1412 | dos |
| [[rs-583987]] | [[csrf]] | Cross-Site Request Forgery (CSRF) | x | 208 | 2152 | csrf, csrf-action |
| [[rs-273946]] | [[sqli]] | SQL Injection | grab | 181 | 6180 | sqli, sqli-proof |
| [[rs-1132378]] | [[file-read]] | Path Traversal | gitlab | 181 | 2849 | file-read, ssrf-chain, info-leak |
| [[rs-469803]] | [[open-redirect]] | Open Redirect | upserve | 162 | 193 | open-redirect |
| [[rs-436928]] | [[file-read]] | Path Traversal | wordpress | 161 | 4729 | priv-esc, file-read, rce-confirmed |
| [[rs-1039315]] | [[sqli]] | SQL Injection | automattic | 160 | 1501 | sqli, sqli-proof |
| [[rs-867699]] | [[dos]] | Uncontrolled Resource Consumption | kubernetes | 159 | 3692 | dos, file-read |
| [[rs-726773]] | [[http-smuggling]] | HTTP Request Smuggling | gsa_bbp | 150 | 7325 | http-smuggling, xss-exec, sqli-proof |
| [[rs-1788006]] | [[open-redirect]] | Open Redirect | expediagroup_bbp | 149 | 1545 | open-redirect, info-leak |
| [[rs-1727221]] | [[csrf]] | Cross-Site Request Forgery (CSRF) | security | 148 | 6406 | csrf, csrf-action |
| [[rs-170552]] | [[csrf]] | Cross-Site Request Forgery (CSRF) | security | 137 | 1840 | csrf, ato, csrf-action |
| [[rs-1946534]] | [[open-redirect]] | Open Redirect | brave | 133 | 4259 | open-redirect, pii-exposure, info-leak |
| [[rs-312543]] | [[xxe]] | XML External Entities (XXE) | semrush | 101 | 4686 | xxe, file-read |
| [[rs-712979]] | [[header-injection]] | CRLF Injection | x | 92 | 2696 | header-injection |
| [[rs-423073]] | [[input-validation]] | Improper Input Validation | security | 78 | 1005 | input-validation |
| [[rs-876192]] | [[ato]] | Weak Password Recovery Mechanism for Forgotten Password | brave | 76 | 3239 | ato |
| [[rs-953219]] | [[crypto]] | Cryptographic Issues - Generic | portswigger | 74 | 121 | crypto |
| [[rs-786745]] | [[input-validation]] | Improper Input Validation | mailru | 70 | 935 | input-validation |
| [[rs-1200647]] | [[header-injection]] | CRLF Injection | aiven_ltd | 69 | 1604 | header-injection, rce-confirmed |
| [[rs-977851]] | [[header-injection]] | Improper Neutralization of HTTP Headers for Scripting Syntax | shopify | 62 | 1040 | header-injection, xss-exec |
| [[rs-2147132]] | [[header-injection]] | CRLF Injection | mozilla | 54 | 1798 | header-injection |
| [[rs-1547877]] | [[file-upload]] | Unrestricted Upload of File with Dangerous Type | aiven_ltd | 50 | 914 | file-upload, rce-confirmed |
| [[rs-1048457]] | [[crypto]] | Improper Certificate Validation | curl | 49 | 1774 | crypto |
| [[rs-2435482]] | [[crypto]] | Improper Certificate Validation | ibb | 46 | 209 | crypto |
| [[rs-903424]] | [[crypto]] | Cryptographic Issues - Generic | nextcloud | 42 | 3625 | crypto |
| [[rs-1095645]] | [[xxe]] | XML External Entities (XXE) | wordpress | 40 | 3062 | xxe, file-read, rce-confirmed |
| [[rs-854424]] | [[ato]] | Unverified Password Change | x | 30 | 129 | ato |
| [[rs-332632]] | [[ato]] | Weak Password Recovery Mechanism for Forgotten Password | bohemia | 25 | 2834 | ato, csrf-action |

## Exemplar lessons (deep-read)

1. **[[rs-745324]]** — demonstrated impact beats prose: leaked session proved staff access.
2. **[[rs-921780]]** — gold standard for auth bugs: full request/response pairs per attack step, redacted.
3. **[[rs-403417]]** — root cause + external reference + /etc/hosts verification of the target.
4. **[[rs-484434]]** — live PoC URL + exact payload + honest duplicate handling.

## Data-grounded report standard

- 94% of top bounty reports have an explicit Impact section (median 26 words)
- ~70% structured repro (numbered steps), median 2-4 steps
- 56% include code blocks; 69% cite the specific target URL
- Length sweet spot: 3k-10k chars (66% bounty rate)
