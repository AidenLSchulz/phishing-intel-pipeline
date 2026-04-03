A combination of some / all indicators will be used for best resluts.

Phishing Website Indicators
1. Newly Registered Domain

Why it matters: Phishing sites are often created shortly before attacks and abandoned quickly.

How to find it: Perform a WHOIS lookup and check the domain creation date.

Description: Domains registered within the last 30 days should be treated as suspicious, especially if they imitate known brands.

2. Brand Impersonation (Typosquatting)

Why it matters: Attackers create domains that look like legitimate companies to trick users.

How to find it: Compare the domain to known brand domains using string similarity checks (e.g., Levenshtein distance).

Description: Examples include domains like paypa1.com, micr0soft-login.com, or amazon-support-secure.net.

3. Credential Harvesting Forms

Why it matters: Phishing websites often attempt to steal usernames and passwords.

How to find it: Scan the page HTML for form fields such as <input type="password">.

Description: If a site asks for login credentials but is not the official domain of the service, it may be phishing.

4. Suspicious SSL Certificate

Why it matters: Many phishing sites quickly obtain free SSL certificates to appear legitimate.

How to find it: Inspect the TLS certificate for issuer, organization name, and issue date.

Description: Certificates issued very recently or with missing organization information may indicate a phishing site.

5. Unusual or Complex URL Structure

Why it matters: Phishing URLs often contain long strings, multiple subdomains, or excessive hyphens to hide the real domain.

How to find it: Analyze the URL length, number of subdomains, and special characters.

Description: Example: secure-login.paypal.verify-account.security-update.com.

6. Domain Reputation / Threat Intelligence Matches

Why it matters: Many phishing domains are already reported to security databases.

How to find it: Check the domain against threat intelligence sources such as Google Safe Browsing, VirusTotal, or PhishTank.

Description: If the domain appears on phishing or malware blocklists, it should be treated as high risk.

7. Suspicious Hosting Infrastructure

Why it matters: Phishing sites are often hosted on infrastructure associated with other malicious domains.

How to find it: Analyze DNS records and the hosting IP address using reputation databases.

Description: If the IP address hosts many known malicious sites, the domain may also be part of a phishing campaign.

8. Page Content Mimicking Legitimate Services

Why it matters: Phishing pages often copy the design of real login pages.

How to find it: Compare page structure, branding elements, or images against legitimate websites.

Description: A site visually identical to a Microsoft or PayPal login page but hosted on a different domain is a strong phishing indicator.
