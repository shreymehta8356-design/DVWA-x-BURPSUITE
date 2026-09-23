# DVWA × BURPSUITE

**Offline Web Application Security Assessment, Evidence & Reporting Platform**

A security assessment is not one activity. It is a dozen: agreeing scope,
selecting checks, running them, writing down what happened, keeping the proof,
deciding how bad it is, telling someone how to fix it, chasing the fix,
verifying the fix, and writing the report. Those normally live in a notebook, a
spreadsheet, a folder of screenshots and someone's memory — which is why two
analysts rate the same issue differently, why evidence goes missing, and why the
report is written from recollection a week later.

This platform puts the whole lifecycle in one traceable, evidence-based
workflow:

```
Assessment → Security Check → Result → Evidence → Finding → Risk
          → Remediation → Retest → Report
```

It runs entirely on one machine — HTML, CSS, vanilla JavaScript, PHP, MySQL,
XAMPP — against a locally hosted DVWA instance. It performs **no scanning and no
exploitation of its own**, and it sends nothing anywhere.

**→ [DEPLOYMENT.md](DEPLOYMENT.md) has the installation steps.** About 20 minutes.

---

## What it does

**Assessment and scope.** Reference-coded assessments (`ASMT-2026-001`) with
scope items, rules of engagement and a status machine that refuses invalid
transitions — you cannot mark testing complete while checks have no result, and
you cannot close an assessment with open critical findings.

**A catalogue of 50 predefined checks**, coded to the OWASP Web Security Testing
Guide v4.2 and each mapped to the DVWA module that exercises it, with the
objective, the steps, the expected secure behaviour and a default rating.

**Results with evidence.** PASS / FAIL / MANUAL REVIEW / NOT APPLICABLE, each
with an observation. A FAIL needs a real one — twenty characters of "broken" is
rejected. Paste the request and response and they become hashed evidence
automatically.

**Evidence you can defend.** Every artefact is SHA-256 hashed at the moment of
capture, *before* redaction, so integrity stays provable even after secrets are
removed. Every access, attachment and export writes a chain-of-custody row.
Uploads are validated by real content type, renamed, and stored outside the web
root.

**Transparent risk.** Two independent inputs — a published 5×5 likelihood/impact
matrix and a full CVSS v3.1 implementation — and a documented strategy for
combining them. Every finding stores the sentence that produced its severity,
and the report prints it, so any rating can be re-derived by hand.

**Remediation and retest.** Every finding gets a remediation record with an
owner and a due date derived from the severity SLA. A finding cannot be marked
resolved by assertion: it needs a retest that records a *fixed* result.

**Burp Suite import.** Reads Burp's XML issue export, decodes the base64 traffic,
classifies each issue offline and maps it to a catalogue check. Issues are
staged for review, never auto-accepted. The parser refuses XML declaring
entities, so a doctored export cannot XXE the platform.

**Audit-ready reports.** Generating a report freezes the entire assessment into
a hashed JSON snapshot, so reopening it later reproduces exactly what was signed
off. HTML with a proper print stylesheet (Ctrl+P → Save as PDF, no library
needed), plus JSON and CSV export.

**A tamper-evident audit trail.** Every action is recorded in a SHA-256 hash
chain. Editing, deleting or reordering any historical row breaks verification
from that point forward, and the report re-verifies the chain at generation
time and prints the result.

---

## The AI layer

Four models run **offline, in pure PHP, with no dependencies**. They work on a
machine that has never had an Internet connection.

| Engine | What it does |
|---|---|
| **Multinomial Naive Bayes** | Reads a free-text observation and predicts the vulnerability class, so the finding, CWE, OWASP category and a starting CVSS vector are pre-filled |
| **TF-IDF + cosine similarity** | Flags a new finding that restates one already recorded, and matches free text to the nearest catalogue check |
| **CVSS v3.1 engine** | Computes base scores from the published specification, including the integer-arithmetic round-up most hand-rolled implementations get wrong |
| **Pattern redactor** | Strips cookies, tokens, credentials, keys and personal data out of captured evidence while preserving the payload the finding depends on |

Three things make this defensible rather than decorative:

**It explains itself.** The classifier returns the terms that drove the
decision, the runner-up classes with their probabilities, and the size of the
corpus it learned from. An analyst can judge the suggestion instead of trusting
it.

**Its confidence means something.** Naive Bayes is notoriously overconfident —
measured on this corpus it reported 0.86 confidence on *correct* answers and
0.61 on *wrong* ones, which tells an analyst nothing. Reported confidence is now
temperature-calibrated by cross validation, so its average tracks measured
accuracy (0.69 when right, 0.45 when wrong). The transform is monotone, so the
ranking is provably unchanged — only the number shown is honest.

**It is measured, not asserted.** `tools/selftest.php` runs 5-fold stratified
cross validation on every run. Current figures on the shipped corpus of 208
documents across 15 classes: **≈66% top-1, ≈88% top-3, against a 6.7% random
baseline.** Top-3 is the number that matters, because the interface shows a
ranked list and the analyst picks from it.

**Every invocation is logged** to `ai_runs` with the task, engine, model,
confidence and whether a human accepted it — and the report prints that register,
so a reader can see exactly which parts of it a model touched. No severity,
status or conclusion is ever set by a model.

**Optional local LLM.** Install Ollama and the platform will use a local model
to draft finding narratives, remediation guidance and the executive summary.
Requests go to `127.0.0.1` and never leave the host. With it switched off — the
default — drafting falls back to a curated knowledge base and deterministic
templates, and every output is labelled with which produced it. No feature ever
fails because a model is missing.

**It learns from use.** Every finding an analyst confirms with a class becomes a
new labelled example. Retraining is explicit rather than automatic, so the model
behind a report never changes underneath an assessment in progress.

---

## Security of the platform itself

A tool that reports missing security headers should not be missing them.

- Every SQL statement is a prepared statement with bound parameters, with
  emulated prepares disabled. Table and column names are never taken from
  request data.
- Output is escaped at every interpolation, in both the interface and the
  report. A stored XSS payload renders as text — the self test asserts it.
- CSRF tokens on every state-changing request, compared in constant time.
- Session hardening: `HttpOnly`, `SameSite=Strict`, strict mode, regeneration
  on login, idle and absolute timeouts, and a user-agent binding.
- bcrypt at cost 12, a real password policy, account lockout and per-IP
  throttling, with responses that do not distinguish an unknown username from a
  wrong password.
- Role-based access control on every endpoint, plus separation of duties: you
  cannot peer review a result you recorded yourself.
- A restrictive `Content-Security-Policy`, and `.htaccess` deny rules over
  `app/`, `config/`, `database/`, `storage/`, `templates/` and `tools/`.
- Evidence is served through the API with `Content-Disposition: attachment` and
  a sandboxed CSP, so a stored HTML or SVG artefact can never execute in the
  platform's origin.

---

## Verifying it

```bash
php tools/selftest.php            # 169 assertions, no database server needed
php tools/verify_deployment.php   # checks a real installation, including live HTTP
```

The self test stands the whole application up against a throwaway SQLite
database and exercises the CVSS engine against ten published vectors, the risk
matrix and severity strategies, the classifier and its cross validation,
duplicate detection, redaction, the full workflow with every guard rail, the
Burp importer including its XXE refusal, the audit chain (including deliberately
tampering with a row to prove detection works), report generation and hashing,
and the platform's own resistance to SQL injection and XSS.

> The self test uses SQLite so it can run anywhere. **MySQL is the supported
> deployment target** — the translation in `tools/sqlite_schema.php` exists only
> for the harness.

---

## Technology

Exactly the stack in the brief, and nothing else:

| Layer | Technology |
|---|---|
| Frontend | HTML |
| Styling | CSS — one hand-written stylesheet, no framework |
| Client-side | Vanilla JavaScript — no framework, no build step, no CDN |
| Backend | PHP 8 — no Composer, no dependencies |
| Database | MySQL / MariaDB |
| Local server | XAMPP |
| Target | Local DVWA |

Charts are hand-drawn inline SVG. Fonts are system fonts. The platform loads
zero external resources, because an offline tool that needs a CDN is not an
offline tool.

---

## Default accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin@DVWA2026` | Everything, plus users, settings, AI configuration |
| `lead` | `Lead@DVWA2026` | Owns assessments, sets severity, finalises reports |
| `analyst` | `Analyst@DVWA2026` | Runs checks, records evidence, drafts findings |
| `reviewer` | `Review@DVWA2026` | Read-only plus peer-review sign-off |

**Change all four on first sign-in.** Every account is flagged *must change
password*.

---

## Scope and limits

This platform records and organises assessments. It does not scan, fuzz, or
exploit, and it refuses any target that is not a loopback, private or `.local`
address. That is the design, not a limitation: the value is in the lifecycle —
structured, evidence-based, risk-aware, remediation-tracked, report-ready — not
in another scanner.

A clean result means the specific condition tested for was not observed with the
techniques applied. It is not a guarantee that no weakness of that class exists,
and the generated report says so.
