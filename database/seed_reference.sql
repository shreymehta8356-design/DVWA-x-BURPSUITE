-- ============================================================================
--  DVWA x BURPSUITE  --  Reference data seed
--  Risk model, platform settings, predefined security check catalogue,
--  and the initial training corpus for the offline classifier.
-- ============================================================================

SET NAMES utf8mb4;
USE `dvwa_burp_platform`;

-- ---------------------------------------------------------------------------
-- Risk matrix  (5x5, qualitative, fully transparent and admin editable)
--   score = likelihood x impact  (used for ordering)
--   band  = published cell value (used for severity)
-- ---------------------------------------------------------------------------
DELETE FROM `risk_matrix`;
INSERT INTO `risk_matrix` (`likelihood`,`impact`,`score`,`band`,`colour`) VALUES
(1,1,1,'info','#6b7280'),   (1,2,2,'info','#6b7280'),   (1,3,3,'low','#3b82f6'),
(1,4,4,'low','#3b82f6'),    (1,5,5,'medium','#f59e0b'),
(2,1,2,'info','#6b7280'),   (2,2,4,'low','#3b82f6'),    (2,3,6,'low','#3b82f6'),
(2,4,8,'medium','#f59e0b'), (2,5,10,'medium','#f59e0b'),
(3,1,3,'low','#3b82f6'),    (3,2,6,'low','#3b82f6'),    (3,3,9,'medium','#f59e0b'),
(3,4,12,'high','#f97316'),  (3,5,15,'high','#f97316'),
(4,1,4,'low','#3b82f6'),    (4,2,8,'medium','#f59e0b'), (4,3,12,'high','#f97316'),
(4,4,16,'high','#f97316'),  (4,5,20,'critical','#dc2626'),
(5,1,5,'medium','#f59e0b'), (5,2,10,'medium','#f59e0b'),(5,3,15,'high','#f97316'),
(5,4,20,'critical','#dc2626'),(5,5,25,'critical','#dc2626');

-- ---------------------------------------------------------------------------
-- Severity ranking and remediation SLA
-- ---------------------------------------------------------------------------
DELETE FROM `severity_sla`;
INSERT INTO `severity_sla` (`severity`,`sla_days`,`rank`,`description`) VALUES
('critical', 7,5,'Immediate action. Exploitable with severe business impact.'),
('high',    30,4,'Prioritised remediation within the current cycle.'),
('medium',  60,3,'Scheduled remediation in the normal release cadence.'),
('low',     90,2,'Remediate opportunistically or accept with justification.'),
('info',   180,1,'Observation only. Hardening or hygiene improvement.');

-- ---------------------------------------------------------------------------
-- Platform settings
-- ---------------------------------------------------------------------------
DELETE FROM `settings`;
INSERT INTO `settings` (`skey`,`svalue`,`value_type`,`description`) VALUES
('org_name','Security Assessment Lab','string','Organisation name printed on reports'),
('report_footer','CONFIDENTIAL - For authorised recipients only','string','Report footer line'),
('severity_strategy','higher_of','string','matrix | cvss | higher_of  - how final severity is derived'),
('ai_enabled','1','bool','Master switch for all AI assistance'),
('ai_llm_enabled','0','bool','Enable the optional local LLM narrative assistant'),
('ai_llm_provider','ollama','string','ollama | openai_compatible | disabled'),
('ai_llm_endpoint','http://127.0.0.1:11434','string','Local LLM endpoint (stays on this machine)'),
('ai_llm_model','llama3.2','string','Local model name pulled in Ollama'),
('ai_llm_timeout','60','int','LLM request timeout in seconds'),
('ai_llm_api_key','','string','Only used by the openai_compatible provider'),
('ai_dedup_threshold','0.55','float','Cosine similarity above which a finding is flagged as a possible duplicate'),
('ai_triage_min_confidence','0.40','float','Minimum calibrated classifier confidence before a suggestion is shown'),
('evidence_max_mb','16','int','Maximum evidence upload size in megabytes'),
('auto_redact_evidence','1','bool','Automatically redact secrets and PII in text evidence'),
('login_max_attempts','5','int','Failed logins before the account is locked'),
('login_lockout_minutes','15','int','Lockout duration in minutes'),
('session_idle_minutes','30','int','Idle session timeout in minutes'),
('require_review','1','bool','Test results must be peer reviewed before report finalisation');

-- ---------------------------------------------------------------------------
-- Predefined security check catalogue
--   Codes follow the OWASP Web Security Testing Guide v4.2.
--   dvwa_module maps each check to the DVWA screen used to exercise it.
-- ---------------------------------------------------------------------------
DELETE FROM `test_catalog`;
INSERT INTO `test_catalog`
(`code`,`title`,`category`,`owasp_top10`,`cwe_id`,`description`,`test_objective`,`test_steps`,`tools_hint`,`expected_secure_behaviour`,`default_likelihood`,`default_impact`,`default_cvss_vector`,`dvwa_module`) VALUES

-- ---- Information gathering -------------------------------------------------
('WSTG-INFO-02','Fingerprint Web Server','Information Gathering','A05:2021 Security Misconfiguration','CWE-200',
 'Identify the web server product and version exposed by the application.',
 'Determine whether the server discloses software and version information that assists an attacker in selecting exploits.',
 '1. Send a request to the base URL through the Burp proxy.\n2. Inspect the Server, X-Powered-By and Via response headers.\n3. Request a non-existent path and inspect the default error page banner.',
 'Burp Repeater; browser developer tools','Version banners are suppressed or generic.',2,2,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Home'),

('WSTG-INFO-05','Review Webpage Content for Information Leakage','Information Gathering','A05:2021 Security Misconfiguration','CWE-200',
 'Inspect HTML source, comments, JavaScript and metadata for sensitive information.',
 'Confirm that no credentials, internal hostnames, debug notes or developer comments are exposed to the client.',
 '1. View source of each in-scope page.\n2. Search the response body for comment markers, TODO notes, internal IPs and API keys.\n3. Review linked JavaScript files for hardcoded secrets.',
 'Burp Target sitemap; browser view-source','No sensitive data is present in client-side content.',3,2,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Home'),

('WSTG-INFO-08','Fingerprint Web Application Framework','Information Gathering','A06:2021 Vulnerable and Outdated Components','CWE-1104',
 'Identify the application framework and its version.',
 'Establish whether framework fingerprints are exposed and whether the identified version is supported.',
 '1. Inspect cookies, headers and file extensions.\n2. Check for framework-specific paths and default files.\n3. Record the identified framework and version.',
 'Burp Target; manual inspection','Framework identity is not trivially disclosed and the version is supported.',2,2,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Home'),

-- ---- Configuration and deployment -----------------------------------------
('WSTG-CONF-02','Test Application Platform Configuration','Configuration and Deployment','A05:2021 Security Misconfiguration','CWE-16',
 'Review the platform configuration for insecure defaults, sample files and verbose settings.',
 'Confirm the platform is hardened and no sample or documentation content remains reachable.',
 '1. Browse for default directories such as /docs, /examples, /test.\n2. Confirm whether directory listing is enabled.\n3. Review PHP settings that affect security such as display_errors and allow_url_include.',
 'Burp Target; directory browsing','Sample content is removed, directory listing disabled, errors not displayed.',3,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Home'),

('WSTG-CONF-03','Test File Extensions Handling for Sensitive Information','Configuration and Deployment','A05:2021 Security Misconfiguration','CWE-552',
 'Determine whether files with sensitive extensions are served rather than executed or blocked.',
 'Confirm that .bak, .inc, .old, .sql and .config files are not retrievable.',
 '1. Enumerate known file names with alternative extensions.\n2. Request each and observe the response code and body.\n3. Record any file served as plain text.',
 'Burp Intruder with an extension wordlist','Sensitive extensions are not served to clients.',3,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N','Home'),

('WSTG-CONF-04','Review Old Backup and Unreferenced Files','Configuration and Deployment','A05:2021 Security Misconfiguration','CWE-530',
 'Identify backup copies and unreferenced files left on the server.',
 'Confirm that no source backups or editor artefacts are reachable.',
 '1. Request common backup names such as index.php.bak and config.php~.\n2. Review the Burp sitemap for orphaned paths.\n3. Attempt retrieval and record the response.',
 'Burp Engagement tools: Discover content','No backup or unreferenced source files are reachable.',3,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N','Home'),

('WSTG-CONF-05','Enumerate Admin Interfaces','Configuration and Deployment','A01:2021 Broken Access Control','CWE-419',
 'Discover administrative interfaces reachable from the tested network position.',
 'Confirm that administrative functionality is not exposed without authentication or network restriction.',
 '1. Request common admin paths such as /admin, /phpmyadmin, /setup.php.\n2. Record which respond without authentication.\n3. Confirm access controls on each discovered interface.',
 'Burp Discover content','Administrative interfaces require authentication and are network restricted.',3,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N','Setup / Reset DB'),

('WSTG-CONF-06','Test HTTP Methods','Configuration and Deployment','A05:2021 Security Misconfiguration','CWE-650',
 'Determine which HTTP methods the server accepts.',
 'Confirm that unsafe methods such as PUT, DELETE and TRACE are disabled.',
 '1. Send an OPTIONS request and read the Allow header.\n2. Attempt TRACE, PUT and DELETE on a test path.\n3. Record the server response for each method.',
 'Burp Repeater','Only required methods are enabled; TRACE and PUT are rejected.',2,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N','Home'),

('WSTG-CONF-07','Test HTTP Strict Transport Security','Configuration and Deployment','A02:2021 Cryptographic Failures','CWE-319',
 'Verify that HSTS is present and correctly configured on HTTPS services.',
 'Confirm the application instructs browsers to use HTTPS only.',
 '1. Request the site over HTTPS.\n2. Inspect the Strict-Transport-Security header.\n3. Validate max-age and includeSubDomains.',
 'Burp Repeater','HSTS present with an adequate max-age.',3,3,'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N','Home'),

('WSTG-CONF-12','Test for Security Response Headers','Configuration and Deployment','A05:2021 Security Misconfiguration','CWE-693',
 'Review the presence and value of browser security headers.',
 'Confirm Content-Security-Policy, X-Content-Type-Options, X-Frame-Options and Referrer-Policy are correctly set.',
 '1. Capture a response for each in-scope page.\n2. Record each security header present and its value.\n3. Identify missing or permissive directives.',
 'Burp Proxy history','A restrictive CSP and the supporting headers are present on every response.',4,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N','CSP Bypass'),

-- ---- Identity management ---------------------------------------------------
('WSTG-IDNT-01','Test Role Definitions','Identity Management','A01:2021 Broken Access Control','CWE-266',
 'Enumerate the roles the application defines and the permissions attached to each.',
 'Confirm roles follow least privilege and that role boundaries are documented and enforced.',
 '1. Record all available roles.\n2. Map the functions each role reaches.\n3. Compare the observed permissions against the documented model.',
 'Manual walkthrough with each role','Roles are least privilege and enforced server side.',3,3,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N','Home'),

('WSTG-IDNT-04','Testing for Account Enumeration','Identity Management','A07:2021 Identification and Authentication Failures','CWE-204',
 'Determine whether the application reveals which usernames exist.',
 'Confirm authentication responses are identical for valid and invalid usernames.',
 '1. Submit a login with a known valid username and a wrong password.\n2. Submit a login with an invalid username.\n3. Compare status code, body, and response time.',
 'Burp Repeater; Comparer','Responses are indistinguishable between valid and invalid accounts.',4,2,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Brute Force'),

-- ---- Authentication --------------------------------------------------------
('WSTG-ATHN-01','Credentials Transported over an Encrypted Channel','Authentication','A02:2021 Cryptographic Failures','CWE-319',
 'Verify credentials are only submitted over an encrypted channel.',
 'Confirm no credential is transmitted in cleartext.',
 '1. Submit the login form and capture the request.\n2. Confirm the scheme is HTTPS.\n3. Confirm no credential appears in the query string.',
 'Burp Proxy history','Credentials are sent over TLS in the request body only.',3,5,'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N','Login'),

('WSTG-ATHN-02','Testing for Default Credentials','Authentication','A07:2021 Identification and Authentication Failures','CWE-1392',
 'Determine whether default or well known accounts remain enabled.',
 'Confirm all default credentials have been changed or disabled.',
 '1. Attempt documented default accounts such as admin/password.\n2. Record any successful authentication.\n3. Confirm the privilege level obtained.',
 'Burp Repeater','No default credential authenticates successfully.',4,5,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','Login'),

('WSTG-ATHN-03','Testing for Weak Lock Out Mechanism','Authentication','A07:2021 Identification and Authentication Failures','CWE-307',
 'Assess protection against automated password guessing.',
 'Confirm the application throttles or locks accounts after repeated failures.',
 '1. Send repeated failed logins for one account using Burp Intruder.\n2. Record whether any throttling, CAPTCHA or lockout occurs.\n3. Note the number of attempts permitted.',
 'Burp Intruder (Sniper) with a small password list','Account lockout or progressive throttling is enforced after a small number of failures.',4,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N','Brute Force'),

('WSTG-ATHN-04','Testing for Bypassing Authentication Schema','Authentication','A07:2021 Identification and Authentication Failures','CWE-287',
 'Attempt to reach authenticated functionality without valid credentials.',
 'Confirm every protected resource enforces authentication server side.',
 '1. Request a protected page with the session cookie removed.\n2. Attempt direct page access by URL.\n3. Attempt parameter tampering on the authentication decision.',
 'Burp Repeater','All protected resources return a redirect to login or 401/403.',3,5,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N','Login'),

('WSTG-ATHN-07','Testing for Weak Password Policy','Authentication','A07:2021 Identification and Authentication Failures','CWE-521',
 'Assess the strength requirements applied to user passwords.',
 'Confirm password complexity and length requirements resist guessing.',
 '1. Attempt to set a single character password.\n2. Attempt a common password such as password123.\n3. Record which values are accepted.',
 'Manual; Burp Repeater','Weak and common passwords are rejected.',4,3,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N','Login'),

('WSTG-ATHN-09','Testing for Weak Password Change Functionality','Authentication','A07:2021 Identification and Authentication Failures','CWE-620',
 'Assess whether the password change function verifies the current identity.',
 'Confirm password change requires the existing password and is CSRF protected.',
 '1. Submit a password change without supplying the current password.\n2. Replay the request without the anti-CSRF token.\n3. Record whether the change succeeds.',
 'Burp Repeater','Password change requires the current password and a valid anti-CSRF token.',4,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N','CSRF'),

-- ---- Authorization ---------------------------------------------------------
('WSTG-ATHZ-01','Testing Directory Traversal and File Include','Authorization','A01:2021 Broken Access Control','CWE-22',
 'Determine whether user input reaches file system paths or include statements.',
 'Confirm the application cannot be induced to read or execute arbitrary files.',
 '1. Substitute traversal sequences into the page parameter.\n2. Attempt absolute paths such as /etc/passwd and C:\\Windows\\win.ini.\n3. Attempt PHP wrappers such as php://filter and remote URLs.',
 'Burp Repeater and Intruder','Input is validated against an allow list and never concatenated into a path.',4,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N','File Inclusion'),

('WSTG-ATHZ-02','Testing for Bypassing Authorization Schema','Authorization','A01:2021 Broken Access Control','CWE-285',
 'Attempt to access functionality reserved for a higher privileged role.',
 'Confirm authorisation is enforced server side for every request.',
 '1. Authenticate as a low privileged user.\n2. Request a high privilege URL captured from an admin session.\n3. Replay privileged actions and record the outcome.',
 'Burp Repeater; two browser profiles','Low privileged users are denied with 403 on every privileged action.',4,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N','Authorisation Bypass'),

('WSTG-ATHZ-03','Testing for Privilege Escalation','Authorization','A01:2021 Broken Access Control','CWE-269',
 'Attempt to raise the privilege level of the authenticated session.',
 'Confirm role values cannot be influenced by client supplied data.',
 '1. Identify role or level parameters in requests and cookies.\n2. Modify the value to an administrative one and replay.\n3. Record any privilege gained.',
 'Burp Repeater; cookie editor','Role is derived server side and never trusted from the client.',3,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','Authorisation Bypass'),

('WSTG-ATHZ-04','Testing for Insecure Direct Object References','Authorization','A01:2021 Broken Access Control','CWE-639',
 'Determine whether object identifiers can be manipulated to reach other users data.',
 'Confirm every object access is validated against the session owner.',
 '1. Capture a request containing an object identifier.\n2. Increment or substitute the identifier.\n3. Record whether another user record is returned.',
 'Burp Repeater; Intruder','Object access is authorised against the session, not the supplied identifier.',4,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N','Authorisation Bypass'),

-- ---- Session management ----------------------------------------------------
('WSTG-SESS-01','Testing for Session Management Schema','Session Management','A07:2021 Identification and Authentication Failures','CWE-384',
 'Assess how session identifiers are generated, transported and invalidated.',
 'Confirm session tokens are unpredictable and correctly bound to the user.',
 '1. Collect a sample of session identifiers.\n2. Assess randomness and length.\n3. Confirm a new identifier is issued on authentication.',
 'Burp Sequencer','Session identifiers are long, random and rotated on privilege change.',4,4,'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N','Weak Session IDs'),

('WSTG-SESS-02','Testing for Cookie Attributes','Session Management','A05:2021 Security Misconfiguration','CWE-1004',
 'Review the security attributes applied to session cookies.',
 'Confirm HttpOnly, Secure and SameSite are set on session cookies.',
 '1. Capture the Set-Cookie response header at login.\n2. Record each attribute present.\n3. Confirm the cookie is not readable from JavaScript.',
 'Burp Proxy; browser console','Session cookies carry HttpOnly, Secure and SameSite.',4,3,'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N','Weak Session IDs'),

('WSTG-SESS-03','Testing for Session Fixation','Session Management','A07:2021 Identification and Authentication Failures','CWE-384',
 'Determine whether a pre-authentication session identifier survives login.',
 'Confirm the session identifier is regenerated when the user authenticates.',
 '1. Record the session identifier before authentication.\n2. Authenticate and capture the identifier again.\n3. Compare the two values.',
 'Burp Proxy history','A new session identifier is issued on authentication.',3,4,'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N','Weak Session IDs'),

('WSTG-SESS-05','Testing for Cross Site Request Forgery','Session Management','A01:2021 Broken Access Control','CWE-352',
 'Determine whether state changing requests can be forged from another origin.',
 'Confirm every state changing request requires an unpredictable token.',
 '1. Capture a state changing request such as password change.\n2. Remove or alter the anti-CSRF token and replay.\n3. Build a proof of concept HTML form and confirm the action executes.',
 'Burp Repeater; Generate CSRF PoC','State changing requests are rejected without a valid per-session token.',4,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N','CSRF'),

('WSTG-SESS-06','Testing for Logout Functionality','Session Management','A07:2021 Identification and Authentication Failures','CWE-613',
 'Confirm that logout invalidates the session on the server.',
 'Confirm a captured session identifier cannot be reused after logout.',
 '1. Authenticate and capture the session cookie.\n2. Log out through the interface.\n3. Replay an authenticated request with the captured cookie.',
 'Burp Repeater','The replayed request is rejected after logout.',3,4,'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N','Logout'),

('WSTG-SESS-07','Testing Session Timeout','Session Management','A07:2021 Identification and Authentication Failures','CWE-613',
 'Assess whether idle sessions expire within an acceptable period.',
 'Confirm an idle session is invalidated server side.',
 '1. Authenticate and leave the session idle.\n2. Replay an authenticated request after the documented timeout.\n3. Record whether the session remains valid.',
 'Burp Repeater','Idle sessions expire server side within the documented period.',3,3,'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N','Logout'),

-- ---- Input validation ------------------------------------------------------
('WSTG-INPV-01','Testing for Reflected Cross Site Scripting','Input Validation','A03:2021 Injection','CWE-79',
 'Determine whether user input is reflected into responses without encoding.',
 'Confirm all reflected input is contextually output encoded.',
 '1. Submit a benign marker into each parameter.\n2. Locate the marker in the response and identify the output context.\n3. Escalate to a context appropriate payload and confirm execution.',
 'Burp Repeater; browser','Input is reflected only as encoded text and never executes.',4,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N','XSS (Reflected)'),

('WSTG-INPV-02','Testing for Stored Cross Site Scripting','Input Validation','A03:2021 Injection','CWE-79',
 'Determine whether persisted input executes when later rendered.',
 'Confirm stored content is encoded on output for every consumer of the data.',
 '1. Submit a marker payload into a persisted field such as guestbook.\n2. Reload the page as the same and a different user.\n3. Confirm whether the payload executes and who is affected.',
 'Burp Repeater; browser','Stored content is encoded on output in every rendering context.',4,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N','XSS (Stored)'),

('WSTG-INPV-03','Testing for HTTP Verb Tampering','Input Validation','A01:2021 Broken Access Control','CWE-650',
 'Determine whether access control decisions depend on the HTTP method.',
 'Confirm authorisation is enforced independently of the request method.',
 '1. Capture a request to a protected resource.\n2. Replay with alternative methods such as HEAD, POST and arbitrary verbs.\n3. Record any bypass.',
 'Burp Repeater','Authorisation is enforced for every method.',2,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N','Home'),

('WSTG-INPV-04','Testing for HTTP Parameter Pollution','Input Validation','A03:2021 Injection','CWE-235',
 'Assess how the application handles duplicated parameters.',
 'Confirm duplicate parameters cannot be used to bypass validation.',
 '1. Submit a request with a parameter supplied twice with different values.\n2. Observe which value the application uses.\n3. Attempt to bypass a filter using the duplicate.',
 'Burp Repeater','Duplicate parameters are rejected or handled consistently.',2,3,'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N','Home'),

('WSTG-INPV-05','Testing for SQL Injection','Input Validation','A03:2021 Injection','CWE-89',
 'Determine whether user input is concatenated into SQL statements.',
 'Confirm all database access uses parameterised statements.',
 '1. Submit a single quote into each parameter and observe error behaviour.\n2. Test boolean conditions such as 1 OR 1=1 and 1 AND 1=2.\n3. Confirm with a UNION or ORDER BY probe and record the extracted column count.',
 'Burp Repeater; Intruder','Input is parameterised and no error or boolean difference is observable.',4,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','SQL Injection'),

('WSTG-INPV-06','Testing for Blind SQL Injection','Input Validation','A03:2021 Injection','CWE-89',
 'Determine whether SQL injection is exploitable without visible output.',
 'Confirm no boolean or time based inference channel exists.',
 '1. Submit a true and a false condition and compare responses.\n2. Submit a time delay payload such as SLEEP(5) and measure the response time.\n3. Record the inference channel used.',
 'Burp Repeater; Intruder with response time column','No measurable difference between true and false conditions.',3,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','SQL Injection (Blind)'),

('WSTG-INPV-11','Testing for Code Injection','Input Validation','A03:2021 Injection','CWE-94',
 'Determine whether user input reaches a code evaluation function.',
 'Confirm no user input is evaluated as code.',
 '1. Identify parameters influencing rendered or evaluated content.\n2. Submit language specific probes and observe the result.\n3. Record any evaluation of supplied input.',
 'Burp Repeater','No user input reaches eval, include or equivalent constructs.',3,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','File Inclusion'),

('WSTG-INPV-12','Testing for Command Injection','Input Validation','A03:2021 Injection','CWE-78',
 'Determine whether user input is passed to an operating system shell.',
 'Confirm no user input reaches a shell command.',
 '1. Append shell separators such as ; && and | to the parameter.\n2. Append a benign command such as whoami and observe the response.\n3. Confirm with a blind technique such as a timing delay where output is not returned.',
 'Burp Repeater','Input is validated and system calls use escaped arguments or are removed.',4,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','Command Injection'),

('WSTG-INPV-19','Testing for Server Side Request Forgery','Input Validation','A10:2021 Server-Side Request Forgery','CWE-918',
 'Determine whether the server can be induced to make attacker controlled requests.',
 'Confirm outbound requests are restricted to an allow list.',
 '1. Identify parameters that accept a URL.\n2. Substitute an internal address and observe the response or timing.\n3. Record any internal resource reached.',
 'Burp Collaborator alternative: local listener','Outbound requests are restricted by an allow list.',2,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N','File Inclusion'),

-- ---- Client side -----------------------------------------------------------
('WSTG-CLNT-01','Testing for DOM Based Cross Site Scripting','Client Side','A03:2021 Injection','CWE-79',
 'Determine whether client side script writes untrusted data to a dangerous sink.',
 'Confirm no source such as location.hash reaches a sink such as innerHTML.',
 '1. Review inline and linked JavaScript for sources and sinks.\n2. Submit a marker through the identified source.\n3. Confirm execution in the browser.',
 'Browser developer tools; Burp DOM Invader','Client side code uses safe sinks and encodes untrusted data.',4,4,'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N','XSS (DOM)'),

('WSTG-CLNT-04','Testing for Client Side URL Redirect','Client Side','A01:2021 Broken Access Control','CWE-601',
 'Determine whether a redirect target can be controlled by the user.',
 'Confirm redirect destinations are restricted to an allow list.',
 '1. Identify parameters that control navigation.\n2. Substitute an external host and follow the response.\n3. Record whether the browser is redirected off site.',
 'Burp Repeater; browser','Redirect targets are validated against an allow list.',3,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N','Open HTTP Redirect'),

('WSTG-CLNT-09','Testing for Clickjacking','Client Side','A05:2021 Security Misconfiguration','CWE-1021',
 'Determine whether the application can be framed by another origin.',
 'Confirm framing is prevented by CSP frame-ancestors or X-Frame-Options.',
 '1. Inspect responses for X-Frame-Options and CSP frame-ancestors.\n2. Build a local page that frames the target.\n3. Confirm whether the application renders inside the frame.',
 'Local HTML proof of concept','Framing by foreign origins is denied.',3,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N','CSP Bypass'),

('WSTG-CLNT-12','Testing Browser Storage','Client Side','A02:2021 Cryptographic Failures','CWE-922',
 'Review data placed in localStorage, sessionStorage and IndexedDB.',
 'Confirm no sensitive data or session token is stored in browser storage.',
 '1. Open developer tools and inspect each storage area.\n2. Record any credential, token or personal data present.\n3. Confirm the data is cleared on logout.',
 'Browser developer tools','No sensitive data is held in browser storage.',3,3,'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N','JavaScript'),

('WSTG-CLNT-99','Testing Client Side Security Control Bypass','Client Side','A04:2021 Insecure Design','CWE-602',
 'Determine whether security decisions are enforced only in client side code.',
 'Confirm every client side check is duplicated on the server.',
 '1. Identify validation or token generation performed in JavaScript.\n2. Reimplement or bypass the logic and submit the request directly.\n3. Record whether the server accepts the request.',
 'Burp Repeater; browser console','Server side enforcement rejects the tampered request.',4,4,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N','JavaScript'),

-- ---- Error handling and cryptography --------------------------------------
('WSTG-ERRH-01','Testing for Improper Error Handling','Error Handling','A05:2021 Security Misconfiguration','CWE-209',
 'Assess whether error responses disclose internal detail.',
 'Confirm errors are generic and detail is logged server side only.',
 '1. Submit malformed input to trigger errors.\n2. Record any database, path or framework detail returned.\n3. Confirm a generic error page is displayed instead.',
 'Burp Repeater','Users receive a generic error; detail is logged server side.',4,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Home'),

('WSTG-ERRH-02','Testing for Stack Traces','Error Handling','A05:2021 Security Misconfiguration','CWE-209',
 'Determine whether stack traces or debug output reach the client.',
 'Confirm no stack trace is rendered in a response.',
 '1. Force an exception through malformed parameters.\n2. Inspect the response body for file paths and line numbers.\n3. Record the disclosed information.',
 'Burp Repeater','No stack trace is returned to the client.',3,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Home'),

('WSTG-CRYP-03','Sensitive Information Sent via Unencrypted Channels','Cryptography','A02:2021 Cryptographic Failures','CWE-319',
 'Identify sensitive data transmitted without encryption.',
 'Confirm all sensitive data is transmitted over TLS.',
 '1. Review the proxy history for cleartext requests.\n2. Record any credential, token or personal data sent in the clear.\n3. Confirm the transport used for each.',
 'Burp Proxy history','All sensitive data is transmitted over TLS.',3,5,'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N','Login'),

('WSTG-CRYP-04','Testing for Weak Encryption and Hashing','Cryptography','A02:2021 Cryptographic Failures','CWE-327',
 'Assess the algorithms used to protect stored and transmitted data.',
 'Confirm modern algorithms are used and passwords use a slow salted hash.',
 '1. Identify hash and cipher formats in storage or responses.\n2. Determine the algorithm from length and character set.\n3. Record any use of MD5, SHA1 or unsalted hashing.',
 'Manual analysis; hash identification','Passwords use bcrypt, scrypt or Argon2 and data uses AES-GCM or equivalent.',3,5,'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N','Cryptography'),

-- ---- Business logic --------------------------------------------------------
('WSTG-BUSL-01','Test Business Logic Data Validation','Business Logic','A04:2021 Insecure Design','CWE-840',
 'Determine whether the application accepts logically invalid data.',
 'Confirm business rules are enforced on the server.',
 '1. Submit out of range, negative and inconsistent values.\n2. Replay a workflow step out of order.\n3. Record any accepted invalid state.',
 'Burp Repeater','Server side validation rejects logically invalid data.',3,4,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N','Home'),

('WSTG-BUSL-05','Test Number of Times a Function Can Be Used','Business Logic','A04:2021 Insecure Design','CWE-837',
 'Determine whether limited use functionality can be replayed.',
 'Confirm single use operations cannot be repeated.',
 '1. Identify a function intended to be used once.\n2. Replay the request multiple times.\n3. Record whether the operation repeats.',
 'Burp Repeater; Turbo replay','Single use operations are invalidated after first use.',3,3,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L','Insecure CAPTCHA'),

('WSTG-BUSL-09','Test Upload of Malicious Files','Business Logic','A04:2021 Insecure Design','CWE-434',
 'Determine whether the upload function accepts and serves executable content.',
 'Confirm uploads are validated by content, renamed, and stored outside the web root.',
 '1. Upload a benign file and record the stored path.\n2. Upload a file with an executable extension and a spoofed content type.\n3. Request the uploaded file and confirm whether it executes.',
 'Burp Repeater; file upload with modified Content-Type','Executable content is rejected and uploads are not served from an executable path.',4,5,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','File Upload'),

('WSTG-BUSL-99','Test Anti Automation Controls','Business Logic','A04:2021 Insecure Design','CWE-799',
 'Assess whether repetitive automated requests are detected and limited.',
 'Confirm rate limiting or a challenge protects sensitive functions.',
 '1. Automate repeated submissions of a sensitive function.\n2. Record any rate limiting, CAPTCHA or blocking.\n3. Attempt to bypass any challenge by replaying its parameters.',
 'Burp Intruder','Sensitive functions are rate limited and challenges cannot be replayed.',4,3,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L','Insecure CAPTCHA');

-- ---------------------------------------------------------------------------
-- Initial training corpus for the offline Naive Bayes triage classifier.
-- Each row is a short analyst-style observation mapped to a vulnerability class.
-- The model is retrained from this table plus analyst-confirmed findings.
-- ---------------------------------------------------------------------------
DELETE FROM `ai_training_data`;
INSERT INTO `ai_training_data` (`text`,`label`,`source`) VALUES
('single quote in the id parameter returned a mysql syntax error near the sql statement','SQL Injection','seed'),
('the id parameter accepts 1 or 1=1 and returns every row from the users table','SQL Injection','seed'),
('union select null null returned an extra column in the rendered table','SQL Injection','seed'),
('order by 6 produced an unknown column error revealing the column count','SQL Injection','seed'),
('sleep 5 payload in the id parameter delayed the response by five seconds confirming blind injection','SQL Injection','seed'),
('true and false boolean conditions produce different page content indicating blind sql injection','SQL Injection','seed'),
('database error message with mysql fetch array warning displayed to the user','SQL Injection','seed'),
('script alert payload submitted in the name parameter executed in the browser','Cross-Site Scripting','seed'),
('the name parameter is reflected into the html body without encoding and the payload fires','Cross-Site Scripting','seed'),
('img onerror payload stored in the guestbook message executes for every visitor','Cross-Site Scripting','seed'),
('stored payload in the signature field runs whenever the page is loaded by another user','Cross-Site Scripting','seed'),
('the default parameter is written to document write via location hash producing dom xss','Cross-Site Scripting','seed'),
('svg onload payload bypassed the blacklist filter and executed script','Cross-Site Scripting','seed'),
('semicolon whoami appended to the ip parameter returned the web server user account','Command Injection','seed'),
('the ping field passes input to the shell and cat etc passwd returned the file contents','Command Injection','seed'),
('ampersand ampersand dir returned a windows directory listing from the command field','Command Injection','seed'),
('pipe character allowed a second operating system command to run','Command Injection','seed'),
('the page parameter accepts traversal sequences and returned etc passwd','Path Traversal / File Inclusion','seed'),
('php filter wrapper returned the base64 encoded source of the include file','Path Traversal / File Inclusion','seed'),
('absolute path to windows win ini was read through the include parameter','Path Traversal / File Inclusion','seed'),
('remote url in the page parameter was fetched and executed as php','Path Traversal / File Inclusion','seed'),
('the form has no anti csrf token and the password change request replays successfully from another origin','Cross-Site Request Forgery','seed'),
('removing the user token parameter did not prevent the state changing request','Cross-Site Request Forgery','seed'),
('a crafted html form hosted locally changed the account password without user interaction','Cross-Site Request Forgery','seed'),
('a php file with a spoofed image content type was uploaded and executed from the uploads directory','Insecure File Upload','seed'),
('the upload accepts any extension and stores the file inside the web root','Insecure File Upload','seed'),
('only client side javascript validates the uploaded file type','Insecure File Upload','seed'),
('two hundred password attempts were sent with no lockout throttling or captcha','Broken Authentication','seed'),
('default credentials admin password authenticated successfully','Broken Authentication','seed'),
('the login response differs for a valid and an invalid username enabling account enumeration','Broken Authentication','seed'),
('a single character password was accepted by the change password form','Broken Authentication','seed'),
('the session cookie is a sequential integer that increments on every login','Session Management','seed'),
('the phpsessid cookie is missing the httponly and secure attributes','Session Management','seed'),
('the session identifier did not change after authentication indicating session fixation','Session Management','seed'),
('the captured session cookie still worked after logging out','Session Management','seed'),
('changing the id parameter returned another user profile record','Broken Access Control','seed'),
('a low privileged account reached the administrative page by requesting the url directly','Broken Access Control','seed'),
('the role parameter in the request was changed to admin and the privilege was granted','Broken Access Control','seed'),
('the protected page rendered when the session cookie was removed','Broken Access Control','seed'),
('the redirect parameter accepts an external host and the browser follows it off site','Open Redirect','seed'),
('the url in the redirect parameter is not validated against an allow list','Open Redirect','seed'),
('the response is missing content security policy x frame options and x content type options','Security Misconfiguration','seed'),
('directory listing is enabled and shows the contents of the include folder','Security Misconfiguration','seed'),
('the server header discloses the exact apache and php version','Security Misconfiguration','seed'),
('trace method is enabled on the web server','Security Misconfiguration','seed'),
('a backup file index php bak was served as plain text source code','Security Misconfiguration','seed'),
('the page can be framed by a foreign origin allowing clickjacking','Security Misconfiguration','seed'),
('the unhandled exception returned a full stack trace with absolute file paths','Information Disclosure','seed'),
('an html comment contains the database connection string','Information Disclosure','seed'),
('the error page reveals the internal server path and the sql query','Information Disclosure','seed'),
('the phpinfo page is reachable without authentication','Information Disclosure','seed'),
('passwords are stored as unsalted md5 hashes','Cryptographic Failure','seed'),
('credentials are submitted over plain http without tls','Cryptographic Failure','seed'),
('the session token is stored in local storage in clear text','Cryptographic Failure','seed'),
('the application uses a weak cipher with a hardcoded key','Cryptographic Failure','seed'),
('the captcha token can be replayed and the step can be repeated indefinitely','Business Logic Flaw','seed'),
('the workflow step can be skipped by requesting the final url directly','Business Logic Flaw','seed'),
('a negative quantity was accepted by the server side handler','Business Logic Flaw','seed'),
('the single use operation executed three times when the request was replayed','Business Logic Flaw','seed'),
('the url parameter caused the server to fetch an internal address','Server-Side Request Forgery','seed'),
('an internal service on localhost was reachable through the url fetch feature','Server-Side Request Forgery','seed');

-- ---------------------------------------------------------------------------
-- Additional training examples.
-- The first block above covers the obvious phrasing for each class; this one
-- broadens the vocabulary so classes that are easily confused with each other
-- (access control against business logic, CSRF against authentication,
-- traversal against command injection) separate cleanly. Class balance is
-- checked by tools/selftest.php through k-fold cross validation.
-- ---------------------------------------------------------------------------
INSERT INTO `ai_training_data` (`text`,`label`,`source`) VALUES

-- SQL Injection -------------------------------------------------------------
('the search field concatenates input into the where clause and a quote breaks the statement','SQL Injection','seed'),
('extracting the database version through a union select with a matching column count','SQL Injection','seed'),
('stacked query with a semicolon executed a second statement against the database','SQL Injection','seed'),
('the login form is bypassed with admin quote or quote 1 equals 1 dash dash in the username','SQL Injection','seed'),
('information_schema tables were enumerated through the vulnerable id parameter','SQL Injection','seed'),

-- Cross-Site Scripting ------------------------------------------------------
('the message field renders unencoded html and an iframe payload loads from the stored record','Cross-Site Scripting','seed'),
('the value is written into an attribute so breaking out with a quote and onmouseover executes','Cross-Site Scripting','seed'),
('the search term is echoed into a javascript variable allowing script context injection','Cross-Site Scripting','seed'),
('innerhtml is assigned from location hash producing client side script execution','Cross-Site Scripting','seed'),

-- Command Injection ---------------------------------------------------------
('backtick characters in the hostname field caused the enclosed command to run on the server','Command Injection','seed'),
('the dns lookup feature passes the domain to the shell and newline injected a second command','Command Injection','seed'),
('a blind os command was confirmed by a five second sleep in the response time','Command Injection','seed'),
('the export function shells out to a binary and unescaped input reached the argument list','Command Injection','seed'),
('ipconfig output was returned after appending an ampersand to the address field','Command Injection','seed'),
('uname minus a executed through the diagnostic form and the kernel version was displayed','Command Injection','seed'),
('the web server account was disclosed by injecting id into the ping utility parameter','Command Injection','seed'),
('shell metacharacters are not filtered before the value is passed to system','Command Injection','seed'),

-- Path Traversal / File Inclusion -------------------------------------------
('dot dot slash sequences in the template name escaped the views directory','Path Traversal / File Inclusion','seed'),
('the download endpoint accepts a file name and returned the application configuration file','Path Traversal / File Inclusion','seed'),
('null byte and double encoded traversal bypassed the filter on the document parameter','Path Traversal / File Inclusion','seed'),
('the include target is built by string concatenation with no realpath containment check','Path Traversal / File Inclusion','seed'),
('reading the database connection file through the report template parameter','Path Traversal / File Inclusion','seed'),
('data wrapper in the page parameter caused supplied php to be evaluated by the include','Path Traversal / File Inclusion','seed'),
('the log file path is user controlled so an arbitrary file outside the web root was read','Path Traversal / File Inclusion','seed'),
('basename is not applied so a full path in the attachment parameter was honoured','Path Traversal / File Inclusion','seed'),

-- Cross-Site Request Forgery ------------------------------------------------
('the state changing request carries no unpredictable token and succeeds from a foreign origin','Cross-Site Request Forgery','seed'),
('the email address update accepts a request with no referer and no token check','Cross-Site Request Forgery','seed'),
('an auto submitting form hosted locally performed the transfer as the logged in victim','Cross-Site Request Forgery','seed'),
('the delete action is exposed on a get request so an image tag triggers it','Cross-Site Request Forgery','seed'),
('the token is present but never validated server side and any value is accepted','Cross-Site Request Forgery','seed'),
('the same token is reused for every user so it is predictable and forgeable','Cross-Site Request Forgery','seed'),
('samesite is not set and the sensitive action executes on a cross origin submission','Cross-Site Request Forgery','seed'),
('the admin user creation endpoint can be forged from an attacker controlled page','Cross-Site Request Forgery','seed'),

-- Insecure File Upload ------------------------------------------------------
('the avatar upload accepts a phtml extension and the file is reachable under the web root','Insecure File Upload','seed'),
('content type is trusted from the request so a script was stored as an image','Insecure File Upload','seed'),
('appending a magic header let an executable file pass the image validation','Insecure File Upload','seed'),
('the uploaded file keeps its original name allowing an existing file to be overwritten','Insecure File Upload','seed'),
('double extension in the file name defeated the deny list on the upload handler','Insecure File Upload','seed'),
('a web shell uploaded through the document form executed when requested directly','Insecure File Upload','seed'),
('there is no size or type restriction on the attachment endpoint','Insecure File Upload','seed'),

-- Broken Authentication -----------------------------------------------------
('the remember me cookie encodes the username so it can be forged for any account','Broken Authentication','seed'),
('password reset tokens are sequential and can be predicted for another account','Broken Authentication','seed'),
('the account lockout resets on a successful login so guessing can continue indefinitely','Broken Authentication','seed'),
('multi factor authentication is offered but the step can be skipped by going straight to the landing url','Broken Authentication','seed'),
('the timing difference between a valid and an invalid username reveals which accounts exist','Broken Authentication','seed'),
('credential stuffing succeeded because no rate limit applies per source address','Broken Authentication','seed'),

-- Session Management --------------------------------------------------------
('the session token is a base64 encoded username and can be crafted for another user','Session Management','seed'),
('concurrent sessions are unlimited and an old token stays valid after a password change','Session Management','seed'),
('the identifier is placed in the url so it leaks through the referer header','Session Management','seed'),
('burp sequencer reported low entropy across five hundred collected session tokens','Session Management','seed'),

-- Broken Access Control -----------------------------------------------------
('a standard user reached the administrative console by requesting the url directly','Broken Access Control','seed'),
('incrementing the invoice identifier returned a document belonging to another customer','Broken Access Control','seed'),
('the delete endpoint does not verify ownership so any record identifier can be removed','Broken Access Control','seed'),
('the menu hides the admin link but the underlying endpoint has no server side check','Broken Access Control','seed'),
('a hidden form field carries the account number and changing it operated on another account','Broken Access Control','seed'),
('horizontal privilege escalation confirmed by reading another user profile with the same role','Broken Access Control','seed'),
('vertical privilege escalation achieved by posting to the user management endpoint as a viewer','Broken Access Control','seed'),
('the api returns full records regardless of the entitlements attached to the token','Broken Access Control','seed'),
('forced browsing to the export url succeeded without the reporting permission','Broken Access Control','seed'),

-- Open Redirect -------------------------------------------------------------
('the next parameter after login sends the browser to any host supplied in the query string','Open Redirect','seed'),
('the returnurl value is placed straight into the location header without validation','Open Redirect','seed'),
('a protocol relative url beginning with two slashes bypassed the relative path check','Open Redirect','seed'),
('the logout page forwards to an attacker chosen destination usable for phishing','Open Redirect','seed'),
('meta refresh built from a query parameter sends the visitor off site','Open Redirect','seed'),
('the allow list is matched with a prefix check so an attacker owned domain passes','Open Redirect','seed'),
('the redirect leaks the authorisation code to the external host through the referer','Open Redirect','seed'),

-- Security Misconfiguration -------------------------------------------------
('the git directory is exposed and the repository can be reconstructed','Security Misconfiguration','seed'),
('default sample applications shipped with the server are still reachable','Security Misconfiguration','seed'),
('the cors policy reflects any origin and allows credentials','Security Misconfiguration','seed'),
('debug mode is left enabled in the deployed configuration','Security Misconfiguration','seed'),

-- Information Disclosure ----------------------------------------------------
('an api key is hardcoded in the bundled javascript file served to every visitor','Information Disclosure','seed'),
('the response header discloses the exact framework build number','Information Disclosure','seed'),
('a directory index revealed the internal file naming scheme used by the application','Information Disclosure','seed'),
('the verbose 500 page includes the full sql statement that failed','Information Disclosure','seed'),
('internal hostnames and private addresses appear in the html comments','Information Disclosure','seed'),
('the swagger documentation endpoint is reachable without authentication','Information Disclosure','seed'),

-- Cryptographic Failure -----------------------------------------------------
('the reset token is an md5 of the timestamp so it can be recomputed','Cryptographic Failure','seed'),
('the application uses ecb mode so identical blocks produce identical ciphertext','Cryptographic Failure','seed'),
('the initialisation vector is a fixed constant across every encrypted value','Cryptographic Failure','seed'),
('personal data is stored in the database in clear text','Cryptographic Failure','seed'),
('the tls configuration still offers deprecated protocol versions and weak ciphers','Cryptographic Failure','seed'),

-- Business Logic Flaw -------------------------------------------------------
('a negative quantity in the order produced a credit rather than a charge','Business Logic Flaw','seed'),
('the discount code applied repeatedly because usage is not decremented','Business Logic Flaw','seed'),
('the payment step is skipped by requesting the confirmation url directly','Business Logic Flaw','seed'),
('the price is submitted by the client and the server accepts the supplied value','Business Logic Flaw','seed'),
('the approval workflow can be completed by the same person who raised the request','Business Logic Flaw','seed'),
('rounding in the currency conversion can be abused by repeating small transactions','Business Logic Flaw','seed'),
('the booking can be confirmed for a date in the past','Business Logic Flaw','seed'),
('replaying the confirmation request created several identical records','Business Logic Flaw','seed'),
('the multi step form accepts the final step without the preceding ones being completed','Business Logic Flaw','seed'),

-- Server-Side Request Forgery -----------------------------------------------
('the webhook url field caused the server to connect back to an address under our control','Server-Side Request Forgery','seed'),
('supplying a loopback address to the import feature reached a service bound to localhost','Server-Side Request Forgery','seed'),
('the pdf renderer fetches remote images so an internal endpoint was requested by the server','Server-Side Request Forgery','seed'),
('response timing differences allowed internal ports to be enumerated through the fetch feature','Server-Side Request Forgery','seed'),
('the cloud metadata address was reachable through the url preview function','Server-Side Request Forgery','seed'),
('a redirect from an allowed host was followed to an internal destination','Server-Side Request Forgery','seed'),
('the file import accepts a remote scheme and the server retrieves the supplied location','Server-Side Request Forgery','seed');
