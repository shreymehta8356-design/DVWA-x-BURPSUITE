<?php
/**
 * Builds a fully worked demo assessment against a local DVWA instance:
 * a test plan, executed checks with observations and captured traffic,
 * findings with real CVSS vectors, remediation owners and a retest round.
 *
 * Run standalone:   php tools/seed_demo.php
 * Or it is invoked automatically by tools/install.php.
 *
 * Everything it creates is ordinary platform data - delete the assessment
 * from the interface if you do not want it.
 */

declare(strict_types=1);

if (!defined('APP_ROOT')) {
    require_once dirname(__DIR__) . '/app/bootstrap.php';
}

use App\Core\Auth;
use App\Core\Database;
use App\Services\AssessmentService;
use App\Services\EvidenceService;
use App\Services\FindingService;
use App\Services\RemediationService;
use App\Services\TestService;

/**
 * @return string one-line summary of what was created
 */
function seedDemoAssessment(): string
{
    Auth::impersonateCli('analyst');

    $existing = Database::scalar("SELECT id FROM assessments WHERE title LIKE 'DVWA baseline%' LIMIT 1");
    if ($existing !== null) {
        return 'demo assessment already present (id ' . $existing . ') - skipped';
    }

    // ---------------------------------------------------------------- 1. Assessment
    $assessment = AssessmentService::create([
        'title'           => 'DVWA baseline assessment - security level low',
        'target_name'     => 'Damn Vulnerable Web Application',
        'target_base_url' => 'http://localhost/DVWA',
        'environment'     => 'local_lab',
        'methodology'     => 'OWASP WSTG v4.2',
        'classification'  => 'ACADEMIC',
        'start_date'      => date('Y-m-d', strtotime('-9 days')),
        'end_date'        => date('Y-m-d', strtotime('-2 days')),
        'objective'       => 'Establish a baseline of the security posture of the locally hosted DVWA instance at '
            . 'security level "low", evidence every result, rate the findings consistently and track remediation to '
            . 'verified closure. The assessment is a controlled laboratory exercise used to exercise the full '
            . 'assessment lifecycle end to end.',
        'constraints'     => 'Testing was limited to the DVWA modules listed in scope at security level low. '
            . 'Automated scanning was not used; every result was produced manually through an intercepting proxy.',
        'scope' => [
            ['item_type' => 'url', 'value' => 'http://localhost/DVWA/vulnerabilities/sqli/', 'in_scope' => 1],
            ['item_type' => 'url', 'value' => 'http://localhost/DVWA/vulnerabilities/xss_r/', 'in_scope' => 1],
            ['item_type' => 'url', 'value' => 'http://localhost/DVWA/vulnerabilities/exec/', 'in_scope' => 1],
            ['item_type' => 'url', 'value' => 'http://localhost/DVWA/vulnerabilities/fi/', 'in_scope' => 1],
            ['item_type' => 'url', 'value' => 'http://localhost/DVWA/vulnerabilities/csrf/', 'in_scope' => 1],
            ['item_type' => 'module', 'value' => 'Brute Force', 'in_scope' => 1],
            ['item_type' => 'url', 'value' => 'http://localhost/phpmyadmin/', 'in_scope' => 0,
             'notes' => 'XAMPP component, outside the application boundary'],
            ['item_type' => 'credential_role', 'value' => 'admin / password (DVWA default account)', 'in_scope' => 1],
        ],
    ]);
    $assessmentId = (int) $assessment['id'];

    // ---------------------------------------------------------------- 2. Test plan
    AssessmentService::buildTestPlan($assessmentId);

    /** @return int|null the assessment_tests row id for a catalogue code */
    $testIdFor = static function (string $code) use ($assessmentId): ?int {
        $id = Database::scalar(
            'SELECT t.id FROM assessment_tests t JOIN test_catalog c ON c.id = t.catalog_id
             WHERE t.assessment_id = ? AND c.code = ?',
            [$assessmentId, $code]
        );
        return $id === null ? null : (int) $id;
    };

    // ---------------------------------------------------------------- 3. Results
    $results = [
        ['WSTG-INPV-05', 'fail', 'low',
         "Submitting a single quote into the id parameter of /vulnerabilities/sqli/ returned a MySQL syntax error rendered directly in the page. The condition 1' OR '1'='1 returned every row from the users table rather than one record, and ORDER BY 3 produced an unknown column error, establishing a two column result set. The parameter is concatenated into the query with no parameterisation.",
         "1' OR '1'='1",
         "GET /DVWA/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1\nHost: localhost\nUser-Agent: Mozilla/5.0\nCookie: PHPSESSID=7f2a9c1de4b8; security=low\nConnection: close",
         "HTTP/1.1 200 OK\nDate: Mon, 31 Aug 2026 09:14:22 GMT\nServer: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12\nX-Powered-By: PHP/8.2.12\nContent-Type: text/html;charset=utf-8\n\n<pre>ID: 1' OR '1'='1<br />First name: admin<br />Surname: admin</pre>\n<pre>ID: 1' OR '1'='1<br />First name: Gordon<br />Surname: Brown</pre>\n<pre>ID: 1' OR '1'='1<br />First name: Hack<br />Surname: Me</pre>\n<pre>ID: 1' OR '1'='1<br />First name: Pablo<br />Surname: Picasso</pre>\n<pre>ID: 1' OR '1'='1<br />First name: Bob<br />Surname: Smith</pre>"],

        ['WSTG-INPV-01', 'fail', 'low',
         "The name parameter of /vulnerabilities/xss_r/ is reflected into the HTML body without encoding. A benign marker was returned verbatim, and the payload <script>alert(1)</script> executed in the browser. The output context is the HTML body, so no attribute or script escaping is applied at all.",
         '<script>alert(1)</script>',
         "GET /DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\nHost: localhost\nCookie: PHPSESSID=7f2a9c1de4b8; security=low",
         "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n<div class=\"vulnerable_code_area\">\n<pre>Hello <script>alert(1)</script></pre>\n</div>"],

        ['WSTG-INPV-12', 'fail', 'low',
         "The ip parameter of /vulnerabilities/exec/ passes user input to a shell. Appending a semicolon and a second command returned the output of that command in the response, confirming operating system command injection as the web server account.",
         '127.0.0.1; whoami',
         "POST /DVWA/vulnerabilities/exec/ HTTP/1.1\nHost: localhost\nContent-Type: application/x-www-form-urlencoded\nCookie: PHPSESSID=7f2a9c1de4b8; security=low\nContent-Length: 44\n\nip=127.0.0.1%3B+whoami&Submit=Submit",
         "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.041 ms\n\nnt authority\\system\n</pre>"],

        ['WSTG-ATHZ-01', 'fail', 'low',
         "The page parameter of /vulnerabilities/fi/ is passed to an include statement with no validation. Traversal sequences resolved outside the application directory and returned the contents of a system file, and the php://filter wrapper returned the base64 encoded source of the include target.",
         '../../../../../../windows/win.ini',
         "GET /DVWA/vulnerabilities/fi/?page=../../../../../../windows/win.ini HTTP/1.1\nHost: localhost\nCookie: PHPSESSID=7f2a9c1de4b8; security=low",
         "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1"],

        ['WSTG-ATHN-03', 'fail', 'low',
         "Two hundred consecutive failed authentication attempts were submitted against the Brute Force module with Burp Intruder. No throttling, CAPTCHA, lockout or rate limiting was applied at any point, and the response for a correct password was distinguishable by content length, making an offline wordlist attack trivially practical.",
         'password wordlist, 200 requests',
         "POST /DVWA/vulnerabilities/brute/ HTTP/1.1\nHost: localhost\nContent-Type: application/x-www-form-urlencoded\nCookie: PHPSESSID=7f2a9c1de4b8; security=low\n\nusername=admin&password=password&Login=Login",
         "HTTP/1.1 200 OK\nContent-Length: 4821\n\n<p>Welcome to the password protected area admin</p>"],

        ['WSTG-SESS-05', 'fail', 'low',
         "The password change form at /vulnerabilities/csrf/ carries no anti-CSRF token and the request is a plain GET. A local HTML page containing an image tag pointing at the change URL altered the password of the authenticated user with no interaction beyond visiting the page.",
         'password_new=hacked&password_conf=hacked&Change=Change',
         "GET /DVWA/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change HTTP/1.1\nHost: localhost\nReferer: http://evil.local/poc.html\nCookie: PHPSESSID=7f2a9c1de4b8; security=low",
         "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n<pre>Password Changed.</pre>"],

        ['WSTG-CONF-12', 'fail', 'low',
         "No Content-Security-Policy, X-Frame-Options, X-Content-Type-Options or Referrer-Policy header is returned on any tested page. A locally hosted page was able to frame the application, and the absence of a CSP removes the last line of defence against the injection findings raised elsewhere in this assessment.",
         null,
         null,
         "HTTP/1.1 200 OK\nDate: Mon, 31 Aug 2026 09:41:07 GMT\nServer: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12\nX-Powered-By: PHP/8.2.12\nSet-Cookie: PHPSESSID=7f2a9c1de4b8; path=/\nContent-Type: text/html;charset=utf-8"],

        ['WSTG-SESS-02', 'fail', 'low',
         "The PHPSESSID cookie is issued without the HttpOnly, Secure or SameSite attributes. document.cookie returned the session identifier from the browser console, which converts any of the cross-site scripting findings in this assessment directly into session theft.",
         'document.cookie',
         null,
         "HTTP/1.1 200 OK\nSet-Cookie: PHPSESSID=7f2a9c1de4b8; path=/\nSet-Cookie: security=low"],

        ['WSTG-ERRH-01', 'fail', 'low',
         "Malformed input produced a raw PHP warning containing the absolute file path of the executing script and the failing function. The error is rendered to the client rather than logged, disclosing the internal directory structure and the database access layer in use.",
         "id=1'",
         null,
         "HTTP/1.1 200 OK\n\n<pre>Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result, bool given in C:\\xampp\\htdocs\\DVWA\\vulnerabilities\\sqli\\source\\low.php on line 12</pre>"],

        // Checks that passed or need judgement.
        ['WSTG-CONF-06', 'pass', null,
         'An OPTIONS request returned Allow: GET, POST, HEAD only. TRACE, PUT and DELETE were each rejected with 405 Method Not Allowed, so unsafe methods are not exposed.',
         null, null, null],

        ['WSTG-CONF-04', 'pass', null,
         'Common backup and editor artefact names were requested across the application root and the vulnerabilities directory. Every request returned 404 and no source file was served as plain text.',
         null, null, null],

        ['WSTG-INPV-04', 'pass', null,
         'Duplicated parameters were submitted to the sqli and xss_r endpoints. PHP consistently used the last occurrence and no validation control could be bypassed by supplying a parameter twice.',
         null, null, null],

        ['WSTG-INFO-02', 'manual_review', null,
         'The Server header discloses Apache 2.4.58 with OpenSSL 3.1.3 and PHP 8.2.12, and X-Powered-By repeats the PHP version. This is a hardening gap rather than a defect in the application, and the versions in use are currently supported. Flagged for the platform owner to decide whether banner suppression is in scope for this deployment.',
         null, null, null],

        ['WSTG-CRYP-03', 'not_applicable', null,
         'The laboratory instance is served over plain HTTP on the loopback interface by design and has no TLS configuration. Transport security cannot be meaningfully assessed in this environment; it is deferred to the deployment review.',
         null, null, null],

        ['WSTG-INPV-19', 'pass', null,
         'No endpoint in scope accepts a URL that the server subsequently fetches. The file inclusion parameter was tested separately under WSTG-ATHZ-01 and is recorded there.',
         null, null, null],
    ];

    foreach ($results as [$code, $status, $level, $observation, $payload, $request, $response]) {
        $testId = $testIdFor($code);
        if ($testId === null) {
            continue;
        }
        TestService::recordResult($testId, [
            'status'              => $status,
            'observation'         => $observation,
            'payload_used'        => $payload,
            'request_snippet'     => $request,
            'response_snippet'    => $response,
            'dvwa_security_level' => $level,
        ]);
    }

    // Peer review a sample of the results, as a reviewer.
    Auth::impersonateCli('reviewer');
    foreach (['WSTG-INPV-05', 'WSTG-INPV-12', 'WSTG-INPV-01', 'WSTG-CONF-06'] as $code) {
        $testId = $testIdFor($code);
        if ($testId !== null) {
            try {
                TestService::review($testId, 'approved', 'Observation and captured traffic support the recorded result.');
            } catch (Throwable) {
                // Non-fatal in a seed.
            }
        }
    }
    Auth::impersonateCli('analyst');

    // ---------------------------------------------------------------- 4. Findings
    $findings = [
        [
            'code' => 'WSTG-INPV-05',
            'data' => [
                'title'              => 'SQL injection in the id parameter of the SQL Injection module',
                'vuln_class'         => 'SQL Injection',
                'affected_component' => 'SQL Injection module, id parameter',
                'affected_url'       => 'http://localhost/DVWA/vulnerabilities/sqli/?id=1',
                'description'        => "The id parameter is concatenated directly into a SQL statement with no parameterisation, so input supplied by the user alters the structure of the query rather than only its data.\n\nA single quote produced a MySQL syntax error rendered in the response. The condition 1' OR '1'='1 returned every row of the users table instead of a single record, and ORDER BY probing established a two column result set, which is sufficient to mount a UNION based extraction of arbitrary tables.",
                'impact_narrative'   => 'An unauthenticated attacker can read, modify and delete arbitrary records in the application database, including the credential table. With the privileges typically granted to the application database account in this configuration, the weakness also permits reading local files, which normally leads to full compromise of the host.',
                'reproduction_steps' => "1. Sign in to DVWA and set the security level to low.\n2. Browse to /DVWA/vulnerabilities/sqli/.\n3. Submit the value 1' in the User ID field and observe the MySQL syntax error.\n4. Submit 1' OR '1'='1 and observe that every user record is returned.\n5. Submit 1' ORDER BY 3 -- and observe the unknown column error confirming two columns.",
                'likelihood' => 5, 'impact' => 5,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'A. Sharma', 'owner_team' => 'Application Engineering', 'status' => 'implemented'],
            'retest' => [
                'result' => 'fixed',
                'method' => 'Replayed the original injection payloads in Burp Repeater against the patched build at security level low.',
                'observation' => 'The single quote payload now returns an empty result set with no error, and the boolean tautology returns only the record matching the literal string. The handler was rewritten to use a prepared statement with a bound parameter, confirmed in the module source.',
            ],
        ],
        [
            'code' => 'WSTG-INPV-12',
            'data' => [
                'title'              => 'Operating system command injection in the Command Injection module',
                'vuln_class'         => 'Command Injection',
                'affected_component' => 'Command Injection module, ip parameter',
                'affected_url'       => 'http://localhost/DVWA/vulnerabilities/exec/',
                'description'        => "The ip parameter is interpolated into a string that is executed by the operating system shell. Shell metacharacters submitted by the user are therefore interpreted as command syntax.\n\nSubmitting 127.0.0.1; whoami returned the output of the ping command followed by the account name under which the web server runs, confirming arbitrary command execution.",
                'impact_narrative'   => 'An attacker with access to this function executes arbitrary commands with the privileges of the web server account. That is sufficient to read the application source and its database credentials, write a persistent web shell, and reach any other host the server can contact.',
                'reproduction_steps' => "1. Browse to /DVWA/vulnerabilities/exec/ at security level low.\n2. Submit 127.0.0.1; whoami in the IP address field.\n3. Observe the ping output followed by the account name of the web server process.\n4. Repeat with && dir to confirm the behaviour is not specific to one separator.",
                'likelihood' => 5, 'impact' => 5,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'A. Sharma', 'owner_team' => 'Application Engineering', 'status' => 'in_progress'],
        ],
        [
            'code' => 'WSTG-ATHZ-01',
            'data' => [
                'title'              => 'Local file inclusion through the page parameter',
                'vuln_class'         => 'Path Traversal / File Inclusion',
                'affected_component' => 'File Inclusion module, page parameter',
                'affected_url'       => 'http://localhost/DVWA/vulnerabilities/fi/?page=include.php',
                'description'        => "The page parameter is passed to a PHP include statement without validation, so traversal sequences and absolute paths supplied by the user resolve outside the intended directory.\n\nA traversal payload returned the contents of a system configuration file, and the php://filter wrapper returned the base64 encoded source of the application include target, exposing server-side code to the client.",
                'impact_narrative'   => 'An attacker reads arbitrary files readable by the web server account, including application source and configuration containing database credentials. Because the value reaches an include statement, any attacker-controlled file that can be written to the host escalates this to remote code execution.',
                'reproduction_steps' => "1. Browse to /DVWA/vulnerabilities/fi/?page=include.php at security level low.\n2. Replace the value with ../../../../../../windows/win.ini and observe the file contents.\n3. Replace the value with php://filter/convert.base64-encode/resource=include.php and decode the response.",
                'likelihood' => 4, 'impact' => 5,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'R. Iyer', 'owner_team' => 'Application Engineering', 'status' => 'not_started'],
        ],
        [
            'code' => 'WSTG-INPV-01',
            'data' => [
                'title'              => 'Reflected cross-site scripting in the name parameter',
                'vuln_class'         => 'Cross-Site Scripting',
                'affected_component' => 'XSS (Reflected) module, name parameter',
                'affected_url'       => 'http://localhost/DVWA/vulnerabilities/xss_r/',
                'description'        => "The name parameter is written into the HTML body of the response without output encoding. A script tag submitted in the parameter is returned verbatim and executed by the browser in the origin of the application.\n\nThe absence of a Content-Security-Policy, recorded separately as a configuration finding, means there is no secondary control that would prevent execution.",
                'impact_narrative'   => 'An attacker who persuades an authenticated user to follow a crafted link executes script in that user session. Because the session cookie is issued without HttpOnly, the payload can read the session identifier directly, so this finding combines with the cookie attribute finding to permit full session theft.',
                'reproduction_steps' => "1. Browse to /DVWA/vulnerabilities/xss_r/ at security level low.\n2. Submit <script>alert(1)</script> in the name field.\n3. Observe the payload executing in the browser.",
                'likelihood' => 5, 'impact' => 4,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'P. Nair', 'owner_team' => 'Application Engineering', 'status' => 'implemented'],
            'retest' => [
                'result' => 'partially_fixed',
                'method' => 'Resubmitted the original payload and a set of filter bypass variants in Burp Repeater.',
                'observation' => 'The literal string <script> is now stripped, so the original payload no longer executes. However the filter is a blacklist applied once: the payload <scr<script>ipt>alert(1)</script> still reaches the response intact and executes. Output encoding has not been applied, so the underlying weakness remains.',
                'residual_severity' => 'high',
            ],
        ],
        [
            'code' => 'WSTG-ATHN-03',
            'data' => [
                'title'              => 'No lockout or rate limiting on the authentication form',
                'vuln_class'         => 'Broken Authentication',
                'affected_component' => 'Brute Force module, login form',
                'affected_url'       => 'http://localhost/DVWA/vulnerabilities/brute/',
                'description'        => "The authentication form applies no throttling, account lockout or challenge after repeated failures. Two hundred consecutive attempts were submitted with no change in behaviour, and successful authentication is distinguishable from failure by response length, which makes the attack easy to automate.",
                'impact_narrative'   => 'An attacker can mount an unrestricted online password guessing attack against any known username. Combined with the default credentials still present on the instance, an account is obtained in seconds rather than the weeks a rate limited form would require.',
                'reproduction_steps' => "1. Capture a login request to /DVWA/vulnerabilities/brute/ in Burp.\n2. Send it to Intruder, mark the password parameter and load a small wordlist.\n3. Run the attack and observe that no request is throttled or blocked.\n4. Sort by response length to identify the successful attempt.",
                'likelihood' => 5, 'impact' => 4,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'S. Rao', 'owner_team' => 'Platform Security', 'status' => 'in_progress'],
        ],
        [
            'code' => 'WSTG-SESS-05',
            'data' => [
                'title'              => 'Cross-site request forgery on the password change function',
                'vuln_class'         => 'Cross-Site Request Forgery',
                'affected_component' => 'CSRF module, password change form',
                'affected_url'       => 'http://localhost/DVWA/vulnerabilities/csrf/',
                'description'        => "The password change function is authorised by the session cookie alone. There is no anti-CSRF token, the current password is not required, and the change is performed on a GET request, so it can be triggered by any tag that causes the browser to issue a request.\n\nA local proof of concept page containing a single image tag changed the password of the authenticated user.",
                'impact_narrative'   => 'An attacker who gets an authenticated user to open a page under their control takes over that account outright, because the password is changed to a value the attacker chose. Where the victim holds an administrative role, this is a complete compromise of the application.',
                'reproduction_steps' => "1. Sign in to DVWA and leave the session active.\n2. Open a local HTML file containing:\n   <img src=\"http://localhost/DVWA/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change\">\n3. Confirm the password has been changed by signing in with the new value.",
                'likelihood' => 4, 'impact' => 4,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'P. Nair', 'owner_team' => 'Application Engineering', 'status' => 'not_started'],
        ],
        [
            'code' => 'WSTG-SESS-02',
            'data' => [
                'title'              => 'Session cookie issued without HttpOnly, Secure or SameSite',
                'vuln_class'         => 'Session Management',
                'affected_component' => 'Application-wide session cookie (PHPSESSID)',
                'affected_url'       => 'http://localhost/DVWA/',
                'description'        => 'The session cookie is set with only a path attribute. HttpOnly, Secure and SameSite are all absent, so the identifier is readable from client-side script, may be transmitted over an unencrypted channel, and is attached to cross-site requests.',
                'impact_narrative'   => 'This does not create a compromise on its own, but it removes the control that would contain one. It converts the cross-site scripting finding in this report from script execution into direct session theft, and it removes the browser-level mitigation for the cross-site request forgery finding.',
                'reproduction_steps' => "1. Sign in and capture the Set-Cookie response header in the proxy history.\n2. Confirm no HttpOnly, Secure or SameSite attribute is present.\n3. In the browser console, evaluate document.cookie and observe that PHPSESSID is returned.",
                'likelihood' => 4, 'impact' => 3,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'S. Rao', 'owner_team' => 'Platform Security', 'status' => 'implemented'],
            'retest' => [
                'result' => 'fixed',
                'method' => 'Re-captured the Set-Cookie header after the configuration change and re-tested document.cookie in the browser console.',
                'observation' => 'The session cookie is now issued with HttpOnly and SameSite=Strict, and document.cookie no longer returns the session identifier. Secure is not set because the laboratory instance is served over plain HTTP, which is accepted for this environment and recorded in the constraints.',
            ],
        ],
        [
            'code' => 'WSTG-CONF-12',
            'data' => [
                'title'              => 'Browser security response headers are absent',
                'vuln_class'         => 'Security Misconfiguration',
                'affected_component' => 'Web server response headers, all pages',
                'affected_url'       => 'http://localhost/DVWA/',
                'description'        => 'No Content-Security-Policy, X-Frame-Options, X-Content-Type-Options or Referrer-Policy header is returned by any page in scope. The application can be framed by a foreign origin, and content type sniffing is not prevented.',
                'impact_narrative'   => 'The missing headers do not create a weakness by themselves, but they remove the layered defences that would blunt the injection and forgery findings raised elsewhere in this report. A restrictive CSP in particular would have prevented the reflected cross-site scripting payload from executing.',
                'reproduction_steps' => "1. Capture any response from the application in the proxy.\n2. Confirm the four headers are absent.\n3. Load a local page containing an iframe pointing at the application and confirm it renders.",
                'likelihood' => 5, 'impact' => 3,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'S. Rao', 'owner_team' => 'Platform Security', 'status' => 'in_progress'],
        ],
        [
            'code' => 'WSTG-ERRH-01',
            'data' => [
                'title'              => 'Verbose PHP errors disclose internal paths and the database layer',
                'vuln_class'         => 'Information Disclosure',
                'affected_component' => 'Global error handling',
                'affected_url'       => 'http://localhost/DVWA/vulnerabilities/sqli/',
                'description'        => 'Malformed input produces raw PHP warnings rendered into the response, including the absolute path of the executing script and the name of the failing function. Errors are displayed to the client rather than written to a log.',
                'impact_narrative'   => 'The disclosed detail removes reconnaissance cost for an attacker: it names the database access layer, confirms the injection point is reaching the database, and reveals the server directory structure that a file inclusion or upload attack would target.',
                'reproduction_steps' => "1. Submit a single quote into the id parameter of the SQL Injection module.\n2. Observe the mysqli_fetch_array warning in the response, including the absolute file path and line number.",
                'likelihood' => 5, 'impact' => 2,
                'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                'confidence' => 'confirmed',
            ],
            'remediation' => ['owner_name' => 'R. Iyer', 'owner_team' => 'Platform Security', 'status' => 'not_started'],
        ],
    ];

    $created = 0;
    foreach ($findings as $entry) {
        $testId = $testIdFor($entry['code']);
        $data = $entry['data'];
        $data['test_id'] = $testId;
        $data['ignore_duplicates'] = true;

        $finding = FindingService::create($assessmentId, $data);
        $created++;

        // Attach the traffic captured during the check to the finding as well.
        if ($testId !== null) {
            foreach (EvidenceService::listFor($assessmentId, $testId) as $item) {
                EvidenceService::attach((int) $item['id'], (int) $finding['id']);
            }
        }

        if (!empty($entry['remediation'])) {
            RemediationService::update((int) $finding['id'], $entry['remediation'] + [
                'status_note' => 'Assigned during the remediation planning meeting.',
            ]);
        }

        if (!empty($entry['retest'])) {
            RemediationService::recordRetest((int) $finding['id'], $entry['retest'] + [
                'retest_date' => date('Y-m-d', strtotime('-1 day')),
                'evidence_text' => "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n[retest capture recorded by the platform]",
            ]);
        }
    }

    // A finding raised in error, kept to demonstrate the false positive path.
    Auth::impersonateCli('lead');
    $falsePositive = FindingService::create($assessmentId, [
        'title'              => 'Suspected open redirect in the login return parameter',
        'vuln_class'         => 'Open Redirect',
        'affected_component' => 'Login form, returnTo parameter',
        'affected_url'       => 'http://localhost/DVWA/login.php',
        'description'        => 'An initial review suggested the returnTo parameter on the login form was used as a redirect destination without validation.',
        'likelihood' => 3, 'impact' => 3,
        'confidence' => 'tentative',
        'ignore_duplicates' => true,
    ]);
    FindingService::changeStatus((int) $falsePositive['id'], 'false_positive',
        'On closer inspection the parameter is never read by the application: the redirect target is a server-side constant. Raised in error during the first pass and retained here so the decision stays on record.');

    // Move the assessment through its lifecycle.
    AssessmentService::changeStatus($assessmentId, 'in_progress');

    Auth::impersonateCli('analyst');

    $stats = AssessmentService::stats($assessmentId);
    return sprintf(
        'assessment %s created: %d checks in plan, %d executed, %d findings, %d evidence items, %d retests',
        (string) $assessment['ref_code'],
        (int) $stats['tests_total'],
        (int) $stats['tests_executed'],
        $created + 1,
        (int) $stats['evidence_count'],
        (int) $stats['retest_count']
    );
}

// Standalone execution.
if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === realpath(__FILE__)) {
    echo seedDemoAssessment() . "\n";
}
