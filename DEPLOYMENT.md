# Deployment guide

**DVWA × BURPSUITE — Offline Web Application Security Assessment, Evidence & Reporting Platform**

Everything below runs on one machine. Nothing in this platform makes an outbound
Internet connection, and the optional AI assistant talks only to `127.0.0.1`.

Total time from a clean machine: **about 20 minutes**, most of it waiting for
XAMPP to download.

---

## 0. What you need

| Component | Version | Why |
|---|---|---|
| XAMPP | 8.1+ (ships Apache 2.4, PHP 8, MariaDB 10) | Web server, PHP runtime, database |
| DVWA | any recent release | The assessment target |
| Burp Suite | Community is enough | Capturing requests and responses |
| Ollama | optional | Only if you want AI-written narrative |

PHP extensions required: `pdo_mysql`, `mbstring`, `json`, `fileinfo`, `openssl`,
`simplexml`. All six ship enabled in XAMPP. `curl` is optional and only used by
the local LLM assistant.

---

## 1. Install XAMPP

1. Download XAMPP from `https://www.apachefriends.org` and install it. On
   Windows the default path is `C:\xampp`.
2. Open the **XAMPP Control Panel** and press **Start** next to **Apache** and
   **MySQL**. Both should show a green "Running" state.
3. Confirm Apache is serving: open `http://localhost/` — you should see the
   XAMPP welcome page.

> **If Apache refuses to start**, port 80 is usually taken by IIS, Skype or
> another service. In the Control Panel choose *Config → httpd.conf*, change
> `Listen 80` to `Listen 8080` and `ServerName localhost:80` to
> `localhost:8080`, then restart. Every URL below becomes
> `http://localhost:8080/...`.

---

## 2. Install the platform

1. Copy the whole `dvwa-burp-platform` folder into the XAMPP web root:

   ```
   Windows   C:\xampp\htdocs\dvwa-burp-platform
   Linux     /opt/lampp/htdocs/dvwa-burp-platform
   macOS     /Applications/XAMPP/htdocs/dvwa-burp-platform
   ```

2. Create the configuration file from the sample:

   ```bash
   cd C:\xampp\htdocs\dvwa-burp-platform
   copy config\config.sample.php config\config.php      REM Windows
   cp   config/config.sample.php config/config.php      # Linux / macOS
   ```

3. Open `config/config.php` and check three values:

   ```php
   'db' => [
       'user' => 'root',
       'pass' => '',          // set this if you gave MySQL a password
       'name' => 'dvwa_burp_platform',
   ],
   'app' => [
       'base_path' => '/dvwa-burp-platform',   // must match the folder name
   ],
   ```

   `base_path` is the only value people usually get wrong. If you served the
   platform from `htdocs/security-lab`, set it to `/security-lab`. If you put it
   at the web root, set it to `''`.

---

## 3. Create the database

**Option A — the installer (recommended).** It creates the database, imports
everything, checks permissions, trains the classifier and builds a worked demo
assessment:

```bash
cd C:\xampp\htdocs\dvwa-burp-platform
C:\xampp\php\php.exe tools\install.php          REM Windows
php tools/install.php                            # Linux / macOS
```

Add `--no-demo` if you want an empty platform.

**Option B — phpMyAdmin.** Open `http://localhost/phpmyadmin`, go to **Import**
and run these three files **in order**:

1. `database/schema.sql`
2. `database/seed_reference.sql`
3. `database/seed_users.sql`

**Option C — the mysql client:**

```bash
cd C:\xampp\htdocs\dvwa-burp-platform
C:\xampp\mysql\bin\mysql.exe -u root -p < database/schema.sql
C:\xampp\mysql\bin\mysql.exe -u root -p < database/seed_reference.sql
C:\xampp\mysql\bin\mysql.exe -u root -p < database/seed_users.sql
```

---

## 4. Sign in

Open **`http://localhost/dvwa-burp-platform/`**.

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin@DVWA2026` | Everything, plus users, settings and AI configuration |
| `lead` | `Lead@DVWA2026` | Owns assessments, sets severity, finalises reports |
| `analyst` | `Analyst@DVWA2026` | Runs checks, records evidence, drafts findings |
| `reviewer` | `Review@DVWA2026` | Read-only plus peer-review sign-off |

> **Change all four immediately.** Each account is flagged *must change
> password* and the platform will nag you until you do. Use **My account →
> Change password**.

---

## 5. Install the target (DVWA)

1. Download DVWA and extract it to `C:\xampp\htdocs\DVWA`.
2. Copy `config/config.inc.php.dist` to `config/config.inc.php` inside DVWA.
3. Open `http://localhost/DVWA/setup.php` and press **Create / Reset Database**.
4. Sign in with `admin` / `password`.
5. Set **DVWA Security** to **Low** for a baseline assessment. Raise it to
   Medium and High later — the platform records the level against every result,
   so you can show the same check passing and failing at different levels.

Then, in the platform: **Assessments → New assessment**, target
`http://localhost/DVWA`. Leave "add every active check" ticked and you get a
50-check plan mapped to the DVWA modules.

> The platform refuses any target that is not a loopback, private or `.local`
> address. That is deliberate — it is a laboratory record-keeping tool, not a
> scanner.

---

## 6. Point Burp Suite at the target

1. In Burp: **Proxy → Proxy settings**, confirm the listener on `127.0.0.1:8080`.
2. Set your browser's proxy to `127.0.0.1:8080`, or use Burp's embedded browser.
3. Browse the DVWA modules you are testing so they appear in **Target → Site map**.
4. To bring issues into the platform: right-click the host → **Issues → Report
   selected issues** → choose **XML** → tick **Base64-encode requests and
   responses** → save the file.
5. In the platform: assessment → **Burp import** → upload that XML.

Imported issues are **staged, not accepted**. Each is classified by the offline
model and mapped to a catalogue check; you choose which become findings.

Using Burp Community without the scanner is fine — paste requests and responses
straight into a check result instead, and the platform hashes and redacts them
as evidence exactly the same way.

---

## 7. Verify the deployment

```bash
php tools/verify_deployment.php
```

This checks the PHP extensions, storage permissions, database schema, seeded
reference data, the trained classifier, the CVSS engine against its published
reference score, the audit hash chain, and — over real HTTP — that the API
refuses unauthenticated requests and that `config/`, `database/`, `app/` and
`storage/` are not served.

To test the whole application logic without touching your database:

```bash
php tools/selftest.php
```

That stands the platform up against a throwaway SQLite database and runs 169
assertions across the CVSS engine, the risk model, the classifier (including
5-fold cross validation), duplicate detection, evidence hashing and redaction,
the tamper-evident audit chain, the Burp importer, the full workflow with its
guard rails, and the platform's own resistance to SQL injection and XSS.

---

## 8. Optional — the local AI narrative assistant

The platform is fully functional without this. Everything the AI does has a
deterministic offline path; the assistant only improves the prose.

1. Install Ollama from `https://ollama.com`.
2. Pull a small model:

   ```bash
   ollama pull llama3.2
   ```

   A 3B model is plenty. On a machine with 8 GB RAM use `llama3.2:1b` or
   `qwen2.5:1.5b`.

3. Confirm it is serving: `curl http://127.0.0.1:11434/api/tags`
4. In the platform: **Administration → Settings → AI**, set `ai_llm_enabled` to
   **Enabled**, then **AI models → Test connection**.

If the endpoint is unreachable the platform silently falls back to templates and
labels the output accordingly. It never fails a user action because a model is
missing.

> The `openai_compatible` provider exists for a **local** OpenAI-shaped server
> (llama.cpp, LM Studio, vLLM). Pointing it at an Internet endpoint would send
> assessment text off the machine and break the offline guarantee.

---

## 9. Production hardening

Do these before the platform holds anything you care about.

1. **Change every default password** (step 4).
2. **Give MySQL a password** and put it in `config/config.php`. XAMPP ships
   `root` with no password.
3. **Create a least-privilege database user** instead of using `root`:

   ```sql
   CREATE USER 'dxb_app'@'localhost' IDENTIFIED BY 'a-long-random-password';
   GRANT SELECT, INSERT, UPDATE, DELETE ON dvwa_burp_platform.* TO 'dxb_app'@'localhost';
   FLUSH PRIVILEGES;
   ```

   Note it is not granted `DROP`, `ALTER` or access to any other schema.
4. **Turn off error display** in `php.ini`:

   ```ini
   display_errors = Off
   log_errors = On
   expose_php = Off
   ```

   and leave `'debug' => false` in `config/config.php`.
5. **Confirm `AllowOverride All`** is set for `htdocs` in `httpd.conf`,
   otherwise the bundled `.htaccess` files are ignored and `config/`,
   `database/` and `storage/` become readable. `verify_deployment.php` checks
   this for you.
6. **Restrict access to the host.** In `httpd.conf`, bind to loopback only:
   `Listen 127.0.0.1:80`.
7. **Serve over HTTPS** if the platform is reachable from any other machine,
   then set `'cookie_secure' => true` in `config/config.php` and uncomment the
   HSTS header in `.htaccess`.
8. **Back up** `database/` dumps and the `storage/evidence/` folder together —
   evidence hashes are meaningless without the artefacts they cover.

---

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| "The database is not reachable yet" | MySQL is not running, or the credentials in `config/config.php` are wrong. Start MySQL in the XAMPP panel. |
| Blank white page | PHP fatal error. Look in `storage/logs/php-error.log`. Temporarily set `'debug' => true` in `config/config.php`. |
| CSS and JavaScript do not load, page looks like plain text | `base_path` does not match the folder name. See step 2.3. |
| "Endpoint not found" on every action | Same cause — `base_path` is wrong. |
| "CSRF token missing or invalid" | The session expired. Reload the page and sign in again. |
| Login says "Account locked" | Five failed attempts locks an account for 15 minutes. An admin can unlock it in **Administration → Users**, or wait. |
| Evidence upload fails on large files | Raise `upload_max_filesize` and `post_max_size` in `php.ini`, then restart Apache. |
| Burp import rejected: "declares entities" | Correct behaviour — the XML contained an `ENTITY` declaration, which is how XXE attacks are delivered. Re-export from Burp without editing the file. |
| Burp import rejected: "already been imported" | That exact file (by SHA-256) is already in this assessment. |
| Report shows "no evidence attached" warnings | Attach the captured request, response or screenshot to the finding before finalising. |
| AI suggestions never appear | `ai_enabled` is off, or confidence is below `ai_triage_min_confidence`. Both are in **Administration → Settings**. |
| Classifier suggests the wrong class often | Add labelled examples in **Administration → AI training data**, then **AI models → Retrain**, then **Cross-validate** to see the effect per class. |

---

## 11. Getting a PDF report

No PDF library is needed and nothing extra has to be installed.

1. Assessment → **Reports** → **Generate report**.
2. The report opens in a new tab. Press **Ctrl+P** (**Cmd+P** on macOS).
3. Destination **Save as PDF**, margins **Default**, and tick **Background
   graphics** so the severity colours print.

The print stylesheet handles page breaks, keeps findings and evidence blocks
from splitting across pages, and prints the classification footer on every page.

---

## 12. File layout

```
dvwa-burp-platform/
├── index.php                 sign-in screen and single-page console shell
├── .htaccess                 hardening, optional pretty API URLs
├── api/
│   ├── index.php             JSON API front controller (auth, CSRF, routing)
│   └── routes.php            the route table
├── app/
│   ├── bootstrap.php         autoloader, config, session hardening, error handling
│   ├── Core/                 Database, Auth, Csrf, Audit, Http, Router, Config
│   ├── Services/             AssessmentService, TestService, FindingService,
│   │                         RemediationService, EvidenceService, RiskEngine,
│   │                         BurpImporter, ReportService, DashboardService
│   ├── AI/                   NaiveBayesClassifier, TfIdfIndex, Tokenizer,
│   │                         Redactor, LlmClient, AiService
│   └── Controllers/          one per resource
├── assets/css, assets/js     the interface - no CDN, no build step
├── config/                   config.sample.php and your config.php
├── database/                 schema.sql and the two seed files
├── storage/                  evidence, models, reports, logs (never served)
├── templates/report.php      the printable report
└── tools/                    install, selftest, verify_deployment, seed_demo,
                              sample_burp_issues.xml
```

---

## 13. Uninstalling

```sql
DROP DATABASE dvwa_burp_platform;
```

Then delete the `dvwa-burp-platform` folder. Evidence artefacts live in
`storage/evidence/` and are removed with it — export anything you need first.
