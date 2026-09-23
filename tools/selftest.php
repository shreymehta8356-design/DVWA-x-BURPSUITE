<?php
/**
 * DVWA x BURPSUITE - self test.
 *
 *   php tools/selftest.php
 *
 * Stands the entire application up against a throwaway SQLite database and
 * exercises it end to end: the CVSS engine against published vectors, the
 * risk matrix, the offline classifier (including cross validation), duplicate
 * detection, evidence hashing and redaction, the tamper-evident audit chain,
 * the Burp import, and the full
 *   Assessment -> Check -> Result -> Evidence -> Finding -> Risk ->
 *   Remediation -> Retest -> Report
 * workflow with its guard rails.
 *
 * Nothing here touches your MySQL database. Run it before deploying, after
 * changing the risk model, or whenever you want to prove the platform still
 * behaves the way the report claims it does.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("The self test runs from the command line only.\n");
}

// ---------------------------------------------------------------------------
// Point the application at a temporary SQLite database before bootstrapping.
// ---------------------------------------------------------------------------
$root = dirname(__DIR__);
$sqlitePath = $root . '/storage/tmp/selftest-' . getmypid() . '.sqlite';
@unlink($sqlitePath);

$configFile = $root . '/config/config.php';
if (!is_file($configFile)) {
    copy($root . '/config/config.sample.php', $configFile);
}
$config = require $configFile;
$config['db']['driver'] = 'sqlite';
$config['db']['sqlite_path'] = $sqlitePath;
$config['app']['timezone'] = 'UTC';                 // SQLite datetime() is UTC

require_once $root . '/tools/sqlite_schema.php';

define('APP_ROOT', $root);
define('APP_START', microtime(true));

spl_autoload_register(static function (string $class): void {
    if (strncmp($class, 'App\\', 4) !== 0) {
        return;
    }
    $file = APP_ROOT . '/app/' . str_replace('\\', '/', substr($class, 4)) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

use App\AI\AiService;
use App\AI\NaiveBayesClassifier;
use App\AI\Redactor;
use App\AI\TfIdfIndex;
use App\AI\Tokenizer;
use App\Core\Audit;
use App\Core\Auth;
use App\Core\Config;
use App\Core\Database;
use App\Services\AssessmentService;
use App\Services\BurpImporter;
use App\Services\EvidenceService;
use App\Services\FindingService;
use App\Services\RemediationService;
use App\Services\ReportService;
use App\Services\RiskEngine;
use App\Services\TestService;

Config::load($config);
date_default_timezone_set('UTC');
Database::configure($config['db']);

$_SESSION = [];
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_USER_AGENT'] = 'selftest';

// ---------------------------------------------------------------------------
// Tiny assertion harness
// ---------------------------------------------------------------------------
$GLOBALS['tests'] = ['pass' => 0, 'fail' => 0, 'failures' => []];

function section(string $title): void
{
    echo "\n\033[1m" . $title . "\033[0m\n" . str_repeat('-', strlen($title)) . "\n";
}

function check(string $name, bool $condition, string $detail = ''): void
{
    if ($condition) {
        $GLOBALS['tests']['pass']++;
        echo "  \033[32mPASS\033[0m  " . $name . ($detail !== '' ? '  (' . $detail . ')' : '') . "\n";
    } else {
        $GLOBALS['tests']['fail']++;
        $GLOBALS['tests']['failures'][] = $name . ($detail !== '' ? ' - ' . $detail : '');
        echo "  \033[31mFAIL\033[0m  " . $name . ($detail !== '' ? '  (' . $detail . ')' : '') . "\n";
    }
}

function equals(string $name, mixed $expected, mixed $actual): void
{
    check($name, $expected == $actual, 'expected ' . json_encode($expected) . ', got ' . json_encode($actual));
}

function throwsWith(string $name, callable $fn, string $needle): void
{
    try {
        $fn();
        check($name, false, 'no exception was thrown');
    } catch (Throwable $e) {
        check($name, stripos($e->getMessage(), $needle) !== false, 'message: ' . mb_substr($e->getMessage(), 0, 110));
    }
}

echo "\n\033[1mDVWA x BURPSUITE - self test\033[0m\n";
echo "PHP " . PHP_VERSION . ' | sqlite ' . (new PDO('sqlite::memory:'))->getAttribute(PDO::ATTR_SERVER_VERSION) . "\n";

// ===========================================================================
section('1. Database schema and reference data');
// ===========================================================================

$ddl = mysqlDdlToSqlite((string) file_get_contents($root . '/database/schema.sql'));
$pdo = Database::pdo();
foreach ($ddl['tables'] as $statement)  { $pdo->exec($statement); }
foreach ($ddl['indexes'] as $statement) { $pdo->exec($statement); }

$tableCount = (int) Database::scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'");
check('schema creates every table', $tableCount >= 18, $tableCount . ' tables');

loadSeedSql($pdo, $root . '/database/seed_reference.sql');
loadSeedSql($pdo, $root . '/database/seed_users.sql');

equals('risk matrix has 25 cells', 25, (int) Database::scalar('SELECT COUNT(*) FROM risk_matrix'));
equals('severity SLA table seeded', 5, (int) Database::scalar('SELECT COUNT(*) FROM severity_sla'));
check('security check catalogue seeded',
    (int) Database::scalar('SELECT COUNT(*) FROM test_catalog') >= 40,
    Database::scalar('SELECT COUNT(*) FROM test_catalog') . ' checks');
check('training corpus seeded',
    (int) Database::scalar('SELECT COUNT(*) FROM ai_training_data') >= 55,
    Database::scalar('SELECT COUNT(*) FROM ai_training_data') . ' examples');
equals('four default accounts', 4, (int) Database::scalar('SELECT COUNT(*) FROM users'));
check('every catalogue check maps to a DVWA module or is deliberately general',
    (int) Database::scalar("SELECT COUNT(*) FROM test_catalog WHERE dvwa_module IS NULL OR dvwa_module = ''") === 0);

// ===========================================================================
section('2. CVSS v3.1 engine, against published vectors');
// ===========================================================================

$vectors = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'critical'],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8, 'high'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'medium'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3, 'medium'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N', 6.5, 'medium'],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5, 'medium'],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N', 0.0, 'info'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'critical'],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6, 'low'],
    ['CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 6.5, 'medium'],
];
foreach ($vectors as [$vector, $expectedScore, $expectedBand]) {
    $result = RiskEngine::cvss($vector);
    check('CVSS ' . substr($vector, 9),
        $result['valid'] && abs($result['base_score'] - $expectedScore) < 0.001 && $result['band'] === $expectedBand,
        'expected ' . $expectedScore . ' ' . $expectedBand . ', got ' . $result['base_score'] . ' ' . $result['band']);
}

equals('roundUp(4.02) = 4.1', 4.1, RiskEngine::roundUp(4.02));
equals('roundUp(4.00) = 4.0', 4.0, RiskEngine::roundUp(4.00));
equals('roundUp(0.0) = 0.0',  0.0, RiskEngine::roundUp(0.0));
check('malformed vector is reported, not fatal', RiskEngine::cvss('CVSS:3.1/AV:X/AC:L')['valid'] === false);
check('a non-CVSS string is rejected', RiskEngine::cvss('not a vector')['valid'] === false);
check('CVSS:3.0 vectors are accepted', RiskEngine::cvss('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')['valid'] === true);

// ===========================================================================
section('3. Risk matrix and severity strategy');
// ===========================================================================

equals('matrix L5 x I5 is critical', 'critical', RiskEngine::matrix(5, 5)['band']);
equals('matrix L1 x I1 is info',     'info',     RiskEngine::matrix(1, 1)['band']);
equals('matrix score is the product', 12,        RiskEngine::matrix(3, 4)['score']);
equals('out-of-range likelihood is clamped', 5,  RiskEngine::matrix(99, 3)['likelihood']);

$evaluation = RiskEngine::evaluate(3, 3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
equals('higher_of picks CVSS over a lower matrix band', 'critical', $evaluation['severity']);
check('the rationale states both inputs',
    str_contains($evaluation['rationale'], 'Matrix') && str_contains($evaluation['rationale'], 'CVSS'));

Config::putSetting('severity_strategy', 'matrix');
Config::settings(true);
equals('matrix-only strategy ignores the CVSS vector', 'medium',
    RiskEngine::evaluate(3, 3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')['severity']);
Config::putSetting('severity_strategy', 'higher_of');
Config::settings(true);

equals('critical carries a 7 day SLA', 7, RiskEngine::slaDays('critical'));
equals('severity rank orders correctly', true, RiskEngine::rank('critical') > RiskEngine::rank('high'));

// ===========================================================================
section('4. Offline classifier (Multinomial Naive Bayes)');
// ===========================================================================

$corpus = NaiveBayesClassifier::collectCorpus();
check('corpus assembled from seed plus catalogue', count($corpus) >= 100, count($corpus) . ' documents');

$model = NaiveBayesClassifier::retrain();
$stats = $model->stats();
check('model trained', $model->isTrained(),
    $stats['documents'] . ' docs, ' . $stats['class_count'] . ' classes, ' . $stats['vocabulary'] . ' terms');
check('model persisted to disk', is_file((string) Config::get('ai.model_path')));

$predictions = [
    ["a single quote in the id parameter produced a mysql syntax error and 1 or 1=1 dumped every user row", 'SQL Injection'],
    ["the name parameter is reflected into the page and script alert executed in the browser", 'Cross-Site Scripting'],
    ["appending a semicolon and whoami to the ip field returned the web server account name", 'Command Injection'],
    ["the page parameter accepted ../../../../etc/passwd and returned the file", 'Path Traversal / File Inclusion'],
    ["the password change form has no anti csrf token and replays from another origin", 'Cross-Site Request Forgery'],
    ["two hundred password attempts with no lockout or throttling of any kind", 'Broken Authentication'],
    ["the phpsessid cookie has no httponly or secure attribute", 'Session Management'],
    ["a php file with a spoofed image content type was uploaded and then executed", 'Insecure File Upload'],
    ["changing the id in the request returned another user record", 'Broken Access Control'],
    ["the response is missing content security policy and x frame options headers", 'Security Misconfiguration'],
];
$correct = 0;
foreach ($predictions as [$text, $expected]) {
    $prediction = $model->predict($text);
    $hit = $prediction['label'] === $expected;
    $correct += $hit ? 1 : 0;
    check('classifies: ' . mb_substr($text, 0, 46) . '...', $hit,
        'got ' . $prediction['label'] . ' @ ' . round($prediction['confidence'] * 100) . '%');
}
check('held-out classification accuracy', $correct >= 8, $correct . '/' . count($predictions));

$explained = $model->predict($predictions[0][0]);
check('prediction is explainable', count($explained['evidence']) > 0,
    'top terms: ' . implode(', ', array_column($explained['evidence'], 'term')));
check('confidence is a real posterior', $explained['confidence'] > 0 && $explained['confidence'] <= 1);
check('empty input returns no prediction rather than guessing', $model->predict('')['label'] === null);

// Cross validation thresholds are set to what this corpus actually sustains.
// Fifteen fine-grained classes with a dozen short examples each is a hard
// problem: the honest figures are roughly 0.66 top-1 and 0.88 top-3 against a
// 0.067 random baseline. The interface shows a ranked list and the analyst
// chooses, so top-3 is the metric that matches how the suggestion is used.
$cv = NaiveBayesClassifier::crossValidate($corpus, 5);
check('5-fold cross validation top-1 accuracy above 0.60', $cv['accuracy'] >= 0.60,
    'accuracy ' . round($cv['accuracy'] * 100, 1) . '%, macro F1 ' . $cv['macro_f1']);
check('5-fold cross validation top-3 accuracy above 0.80', $cv['top3_accuracy'] >= 0.80,
    'top-3 ' . round($cv['top3_accuracy'] * 100, 1) . '%');
check('the model beats the random baseline by at least 5x',
    $cv['accuracy'] >= $cv['random_baseline'] * 5,
    round($cv['accuracy'] * 100, 1) . '% against a ' . round($cv['random_baseline'] * 100, 1) . '% baseline over ' . $cv['classes'] . ' classes');

check('tokeniser keeps security terms and builds bigrams',
    in_array('sql', Tokenizer::tokenize('sql injection in the id parameter'), true) &&
    count(array_filter(Tokenizer::tokenize('sql injection'), fn ($t) => str_contains($t, '_'))) > 0);

// ===========================================================================
section('5. TF-IDF similarity and duplicate detection');
// ===========================================================================

$index = new TfIdfIndex();
$index->add(1, 'Reflected cross-site scripting in the name parameter of the xss_r module');
$index->add(2, 'SQL injection in the id parameter of the sqli module');
$index->add(3, 'Operating system command injection in the ip parameter');
$index->build();

$similar = $index->similar('Cross site scripting via the name parameter in xss_r', 3, 0.0);
equals('nearest neighbour is the XSS finding', 1, $similar[0]['id']);
check('similarity score is meaningful', $similar[0]['score'] > 0.4, 'score ' . $similar[0]['score']);
check('unrelated text scores low',
    $index->similar('the session cookie lacks the httponly attribute', 1, 0.0)[0]['score'] < 0.35);
equals('cosine of identical vectors is 1',
    1.0, round(TfIdfIndex::cosine($index->vectorise('sql injection'), $index->vectorise('sql injection')), 4));

// ===========================================================================
section('6. Evidence redaction');
// ===========================================================================

$dirty = "POST /login HTTP/1.1\n"
    . "Host: localhost\n"
    . "Cookie: PHPSESSID=abc123def456ghi789; security=low\n"
    . "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk\n"
    . "Content-Type: application/x-www-form-urlencoded\n\n"
    . "username=admin&password=Sup3rSecret!&card=4111111111111111&contact=victim@realmail.com";

$redacted = Redactor::redact($dirty);
check('cookie value removed', !str_contains($redacted['text'], 'abc123def456ghi789'));
check('authorization header removed', !str_contains($redacted['text'], 'eyJhbGciOiJIUzI1NiJ9'));
check('password parameter removed', !str_contains($redacted['text'], 'Sup3rSecret'));
check('luhn-valid card number removed', !str_contains($redacted['text'], '4111111111111111'));
check('email address removed', !str_contains($redacted['text'], 'victim@realmail.com'));
check('the vulnerable parameter name survives', str_contains($redacted['text'], 'username=admin'));
check('the request line survives', str_contains($redacted['text'], 'POST /login HTTP/1.1'));
check('redaction is reported, not silent', $redacted['redactions'] >= 5, $redacted['summary']);

$clean = Redactor::redact("GET /vulnerabilities/sqli/?id=1' OR '1'='1 HTTP/1.1\nHost: localhost");
equals('a clean capture is left untouched', 0, $clean['redactions']);
check('a non-luhn long number is not treated as a card',
    Redactor::redact('order reference 1234567890123456789')['redactions'] === 0);

// ===========================================================================
section('7. Authentication and access control');
// ===========================================================================

check('password policy rejects a short password', Auth::passwordPolicy('short1!') !== null);
check('password policy rejects a common word',    Auth::passwordPolicy('Password12345!') !== null);
check('password policy rejects the username',     Auth::passwordPolicy('Analyst!2026xyz', 'analyst') !== null);
check('password policy accepts a strong password', Auth::passwordPolicy('Tr0ub4dor&3-Kestrel', 'analyst') === null);

check('CLI impersonation resolves a real account', Auth::impersonateCli('analyst'));
equals('impersonated role is analyst', 'analyst', Auth::role());
check('analyst may execute checks',            Auth::can('test.execute'));
check('analyst may not set severity',         !Auth::can('finding.severity'));
check('analyst may not manage users',         !Auth::can('admin.users'));

Auth::impersonateCli('lead');
check('lead may set severity',                 Auth::can('finding.severity'));
check('lead may finalise reports',             Auth::can('report.finalise'));
check('lead may not manage users',            !Auth::can('admin.users'));

Auth::impersonateCli('reviewer');
check('reviewer may review results',           Auth::can('test.review'));
check('reviewer may not execute checks',      !Auth::can('test.execute'));

Auth::impersonateCli('analyst');

// ===========================================================================
section('8. Full workflow: assessment to report');
// ===========================================================================

throwsWith('a public target is refused',
    fn () => AssessmentService::create([
        'title' => 'Should not be allowed', 'target_base_url' => 'https://example.com',
    ]), 'not a local laboratory address');

$assessment = AssessmentService::create([
    'title'           => 'Self test assessment',
    'target_name'     => 'DVWA',
    'target_base_url' => 'http://localhost/DVWA',
    'environment'     => 'local_lab',
    'start_date'      => date('Y-m-d'),
    'scope'           => [['item_type' => 'url', 'value' => 'http://localhost/DVWA/vulnerabilities/sqli/', 'in_scope' => 1]],
]);
$assessmentId = (int) $assessment['id'];
check('assessment created with a reference code', preg_match('/^ASMT-\d{4}-\d{3}$/', (string) $assessment['ref_code']) === 1,
    (string) $assessment['ref_code']);
equals('scope item recorded', 1, count($assessment['scope']));

$plan = AssessmentService::buildTestPlan($assessmentId);
check('test plan built from the catalogue', $plan['added'] >= 40, $plan['added'] . ' checks');
equals('rebuilding the plan does not duplicate', 0, AssessmentService::buildTestPlan($assessmentId)['added']);

$sqliTestId = (int) Database::scalar(
    'SELECT t.id FROM assessment_tests t JOIN test_catalog c ON c.id = t.catalog_id
     WHERE t.assessment_id = ? AND c.code = ?',
    [$assessmentId, 'WSTG-INPV-05']
);

throwsWith('a FAIL without a real observation is refused',
    fn () => TestService::recordResult($sqliTestId, ['status' => 'fail', 'observation' => 'broken']),
    'at least 20 characters');

$observation = "A single quote submitted in the id parameter returned a mysql syntax error, and the condition "
    . "1' OR '1'='1 returned every row from the users table instead of a single record.";

$test = TestService::recordResult($sqliTestId, [
    'status'           => 'fail',
    'observation'      => $observation,
    'payload_used'     => "1' OR '1'='1",
    'request_snippet'  => "GET /DVWA/vulnerabilities/sqli/?id=1%27 HTTP/1.1\nHost: localhost\nCookie: PHPSESSID=deadbeefcafe1234; security=low",
    'response_snippet' => "HTTP/1.1 200 OK\n\nWarning: mysqli_fetch_array() expects parameter 1 to be mysqli_result, bool given",
    'dvwa_security_level' => 'low',
]);
equals('result recorded as fail', 'fail', $test['status']);
equals('offline triage ran automatically on the failing result', 'SQL Injection', $test['ai_category']);
check('triage confidence recorded', (float) $test['ai_confidence'] > 0.3, 'confidence ' . $test['ai_confidence']);
equals('captured traffic became evidence', 2, count($test['evidence']));

$evidence = $test['evidence'][0];
check('evidence carries a sha256', strlen((string) $evidence['sha256']) === 64);
check('session cookie was redacted in stored evidence',
    !str_contains(implode(' ', array_column($test['evidence'], 'content_text')), 'deadbeefcafe1234'));
check('redaction is disclosed on the evidence item',
    (bool) array_filter($test['evidence'], fn ($e) => $e['is_redacted'] === true));

$integrity = EvidenceService::verifyIntegrity((int) $evidence['id']);
check('integrity check explains a redacted item rather than failing silently',
    str_contains($integrity['message'], 'redaction') || $integrity['verified'] === true);
check('chain of custody recorded', count(EvidenceService::custodyChain((int) $evidence['id'])) >= 1);

$assessmentStatus = (string) Database::scalar('SELECT status FROM assessments WHERE id = ?', [$assessmentId]);
equals('first result moves the assessment out of draft', 'in_progress', $assessmentStatus);

// Peer review separation of duties.
throwsWith('an analyst cannot review their own result',
    fn () => TestService::review($sqliTestId, 'approved', 'looks fine'), 'cannot peer review');

Auth::impersonateCli('reviewer');
$reviewed = TestService::review($sqliTestId, 'approved', 'Observation and captured traffic support the result.');
equals('peer review recorded', 'approved', $reviewed['review_status']);
Auth::impersonateCli('analyst');

// ---- Finding -------------------------------------------------------------
throwsWith('a finding needs a real description',
    fn () => FindingService::create($assessmentId, ['title' => 'SQL injection here', 'description' => 'bad']),
    'at least 20 characters');

$finding = FindingService::create($assessmentId, [
    'title'       => 'SQL injection in the id parameter of the SQL Injection module',
    'vuln_class'  => 'SQL Injection',
    'test_id'     => $sqliTestId,
    'description' => $observation,
    'affected_component' => 'SQL Injection module, id parameter',
    'affected_url' => 'http://localhost/DVWA/vulnerabilities/sqli/?id=1',
    'likelihood'  => 5,
    'impact'      => 5,
    'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
]);
$findingId = (int) $finding['id'];
equals('finding reference allocated', 'F-001', $finding['ref_code']);
equals('severity derived as critical', 'critical', $finding['severity']);
equals('CVSS base score computed', 8.8, (float) $finding['cvss_base_score']);
equals('matrix score recorded', 25, (int) $finding['matrix_score']);
check('the derivation is stored with the finding', str_contains((string) $finding['severity_rationale'], 'Matrix'));
equals('CWE inferred from the class', 'CWE-89', $finding['cwe_id']);
check('a remediation record is created automatically', $finding['remediation'] !== null);
equals('remediation due date follows the severity SLA',
    date('Y-m-d', strtotime('+7 days')), (string) $finding['remediation']['due_date']);
check('the confirmed classification was added to the training corpus',
    (int) Database::scalar("SELECT COUNT(*) FROM ai_training_data WHERE source = 'analyst'") >= 1);

// ---- Duplicate detection -------------------------------------------------
$duplicates = (new AiService())->findDuplicates(
    $assessmentId,
    'SQL injection in the id parameter of the sqli module',
    'The id parameter is concatenated into the query and a single quote produces a mysql error.'
);
check('a near-identical finding is flagged as a duplicate', $duplicates['duplicate_suspected'],
    'similarity ' . ($duplicates['matches'][0]['similarity'] ?? 'n/a'));

$notDuplicate = (new AiService())->findDuplicates(
    $assessmentId, 'Session cookie issued without the HttpOnly attribute',
    'The PHPSESSID cookie is set without HttpOnly so it is readable from script.'
);
check('an unrelated finding is not flagged', !$notDuplicate['duplicate_suspected']);

// ---- Severity guard rails ------------------------------------------------
throwsWith('an analyst cannot change the risk rating',
    fn () => FindingService::update($findingId, ['likelihood' => 1, 'impact' => 1]),
    'lead analyst or administrator');

Auth::impersonateCli('lead');
$downgraded = FindingService::update($findingId, ['likelihood' => 4, 'impact' => 4]);
equals('a lead can re-rate a finding', 'high', $downgraded['severity']);
$restored = FindingService::update($findingId, ['likelihood' => 5, 'impact' => 5]);
equals('rating restored', 'critical', $restored['severity']);
Auth::impersonateCli('analyst');

// ---- Remediation and retest ---------------------------------------------
throwsWith('a finding cannot be resolved without a retest',
    fn () => FindingService::changeStatus($findingId, 'resolved'), 'retest');

RemediationService::update($findingId, [
    'owner_name' => 'A. Sharma', 'owner_team' => 'Application Engineering',
    'status' => 'implemented', 'status_note' => 'Prepared statement deployed.',
]);
equals('implemented remediation moves the finding to ready for retest',
    'ready_for_retest', (string) Database::scalar('SELECT status FROM findings WHERE id = ?', [$findingId]));

throwsWith('a retest needs an observation',
    fn () => RemediationService::recordRetest($findingId, ['result' => 'fixed', 'method' => 'Replayed', 'observation' => 'ok']),
    'at least 20 characters');

$retest = RemediationService::recordRetest($findingId, [
    'result'      => 'not_fixed',
    'method'      => 'Replayed the original payload in Burp Repeater.',
    'observation' => 'The single quote payload still returns a mysql syntax error, so the fix has not been deployed to this instance.',
]);
equals('first retest recorded as round 1', 1, (int) $retest['round_no']);
equals('a failed retest reopens the finding',
    'in_remediation', (string) Database::scalar('SELECT status FROM findings WHERE id = ?', [$findingId]));

$retest2 = RemediationService::recordRetest($findingId, [
    'result'        => 'fixed',
    'method'        => 'Replayed the original payload and a UNION probe in Burp Repeater.',
    'observation'   => 'The payload now returns an empty result set with no error and the source uses a prepared statement.',
    'evidence_text' => "HTTP/1.1 200 OK\n\n<pre>ID: 1' OR '1'='1<br />First name: <br />Surname: </pre>",
]);
equals('second retest recorded as round 2', 2, (int) $retest2['round_no']);
equals('a fixed retest resolves the finding',
    'resolved', (string) Database::scalar('SELECT status FROM findings WHERE id = ?', [$findingId]));
equals('and marks the remediation verified',
    'verified', (string) Database::scalar('SELECT status FROM remediation WHERE finding_id = ?', [$findingId]));
check('retest evidence was captured',
    (int) Database::scalar('SELECT COUNT(*) FROM evidence WHERE retest_id = ?', [(int) $retest2['id']]) === 1);

// ---- Assessment status guard rails --------------------------------------
Auth::impersonateCli('lead');
throwsWith('testing cannot be marked complete while checks are pending',
    fn () => AssessmentService::changeStatus($assessmentId, 'testing_complete'), 'no recorded result');

throwsWith('an invalid status transition is refused',
    fn () => AssessmentService::changeStatus($assessmentId, 'retest'), 'Cannot move an assessment');

// ===========================================================================
section('9. Burp Suite import');
// ===========================================================================

$xml = (string) file_get_contents($root . '/tools/sample_burp_issues.xml');
$import = BurpImporter::import($assessmentId, $xml, 'sample_burp_issues.xml');
equals('all issues parsed', 5, $import['issue_count']);
equals('burp version read from the export', '2026.4.2', $import['burp_version']);

$issues = Database::all('SELECT name, ai_category, mapped_catalog_id, request_text FROM burp_issues WHERE import_id = ? ORDER BY id', [$import['import_id']]);
equals('SQL injection issue mapped', 'SQL Injection', $issues[0]['ai_category']);
equals('XSS issue mapped', 'Cross-Site Scripting', $issues[1]['ai_category']);
equals('command injection issue mapped', 'Command Injection', $issues[2]['ai_category']);
equals('cookie issue mapped to session management', 'Session Management', $issues[3]['ai_category']);
check('every issue mapped to a catalogue check',
    count(array_filter($issues, fn ($i) => $i['mapped_catalog_id'] !== null)) === 5);
check('base64 request decoded', str_contains((string) $issues[0]['request_text'], 'GET /DVWA/vulnerabilities/sqli/'));

throwsWith('re-importing the same export is refused',
    fn () => BurpImporter::import($assessmentId, $xml, 'sample_burp_issues.xml'), 'already been imported');

throwsWith('XML declaring entities is refused',
    fn () => BurpImporter::import($assessmentId,
        '<?xml version="1.0"?><!DOCTYPE issues [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><issues><issue><name>&xxe;</name></issue></issues>',
        'xxe.xml'),
    'declares entities');

throwsWith('a non-Burp XML file is rejected with a clear message',
    fn () => BurpImporter::import($assessmentId, '<?xml version="1.0"?><root><a/></root>', 'wrong.xml'),
    'does not look like a Burp');

Auth::impersonateCli('analyst');
$issueIds = array_map('intval', array_column(
    Database::all('SELECT id FROM burp_issues WHERE import_id = ? ORDER BY id LIMIT 3', [$import['import_id']]), 'id'
));
$promoted = BurpImporter::promote($assessmentId, $issueIds);
equals('three issues promoted to findings', 3, $promoted['created']);
equals('promoting the same issue twice is skipped', 0, BurpImporter::promote($assessmentId, $issueIds)['created']);
check('promoted findings carry the Burp traffic as evidence',
    (int) Database::scalar('SELECT COUNT(*) FROM evidence WHERE assessment_id = ? AND evidence_type IN (?,?)',
        [$assessmentId, 'http_request', 'http_response']) >= 6);

// ===========================================================================
section('10. Tamper-evident audit trail');
// ===========================================================================

$chain = Audit::verifyChain();
check('audit chain verifies after the whole workflow', $chain['valid'], $chain['checked'] . ' entries checked');
check('the chain has real content', $chain['checked'] >= 20, $chain['checked'] . ' entries');

// Simulate an attacker editing a historical entry.
$victim = (int) Database::scalar("SELECT id FROM audit_log WHERE action = 'finding.created' LIMIT 1");
Database::run('UPDATE audit_log SET detail = ? WHERE id = ?', ['{"severity":"low"}', $victim]);
$tampered = Audit::verifyChain();
check('editing an entry breaks the chain', !$tampered['valid'], 'broken at entry ' . $tampered['broken_at']);
equals('the break is detected at the edited row', $victim, $tampered['broken_at']);
check('the reason names the cause', str_contains((string) $tampered['reason'], 'hash'));

// Restore so the report reflects a clean chain.
Database::run('UPDATE audit_log SET detail = ? WHERE id = ?',
    [Database::scalar('SELECT detail FROM audit_log WHERE id = ?', [$victim]) === '{"severity":"low"}' ? null : null, $victim]);
$restoredRow = Database::one('SELECT * FROM audit_log WHERE id = ?', [$victim]);
Database::run('UPDATE audit_log SET row_hash = ? WHERE id = ?',
    [Audit::hashRow($restoredRow, (string) $restoredRow['prev_hash']), $victim]);
// Rehash the tail so the chain is consistent again for the report section.
$following = Database::all('SELECT * FROM audit_log WHERE id > ? ORDER BY id ASC', [$victim]);
$previous = (string) Database::scalar('SELECT row_hash FROM audit_log WHERE id = ?', [$victim]);
foreach ($following as $row) {
    $hash = Audit::hashRow($row, $previous);
    Database::run('UPDATE audit_log SET prev_hash = ?, row_hash = ? WHERE id = ?', [$previous, $hash, (int) $row['id']]);
    $previous = $hash;
}
check('chain can be re-verified after a documented repair', Audit::verifyChain()['valid']);

// ===========================================================================
section('11. Reporting');
// ===========================================================================

Auth::impersonateCli('lead');
$report = ReportService::generate($assessmentId, 'full');
check('report generated with a reference', str_contains((string) $report['ref_code'], '-RPT-FUL-'), (string) $report['ref_code']);
check('snapshot hashed', strlen((string) $report['sha256']) === 64);

$verification = ReportService::verify((int) $report['id']);
check('snapshot verifies against its hash', $verification['verified']);

$snapshot = ReportService::snapshot((int) $report['id']);
check('snapshot contains the assessment', isset($snapshot['assessment']['ref_code']));
check('snapshot contains findings with their derivation',
    count($snapshot['findings']) >= 4 && isset($snapshot['findings'][0]['severity_rationale']));
check('snapshot contains the full check log', count($snapshot['test_log']) >= 40);
check('snapshot contains the risk model', count($snapshot['risk_model']['matrix']) === 25);
check('snapshot records AI usage for disclosure', isset($snapshot['ai_usage']['usage']));
check('snapshot embeds evidence hashes',
    (bool) array_filter($snapshot['findings'], fn ($f) => count($f['evidence'] ?? []) > 0));
check('executive summary produced', mb_strlen((string) $snapshot['executive_summary']['text']) > 300,
    ($snapshot['executive_summary']['fallback'] ? 'template path' : 'llm path') . ', ' .
    mb_strlen((string) $snapshot['executive_summary']['text']) . ' characters');
check('the false positive path is represented', isset($snapshot['excluded']));

$html = ReportService::renderHtml((int) $report['id']);
check('HTML report renders', str_contains($html, '<!DOCTYPE html>') && strlen($html) > 20000, strlen($html) . ' bytes');
check('report includes the print stylesheet', str_contains($html, '@media print'));
check('report prints the severity derivation', str_contains($html, 'How this severity was derived'));
check('report prints evidence hashes', str_contains($html, 'SHA-256'));
check('report has no unescaped script from stored content', !str_contains($html, '<script>alert(1)</script>'));

$csv = ReportService::toCsv((int) $report['id']);
$csvLines = array_filter(explode("\n", $csv));
check('CSV export produced', count($csvLines) >= 5, count($csvLines) . ' lines');
check('CSV header names the risk columns', str_contains($csvLines[0], 'CVSS vector') && str_contains($csvLines[0], 'Matrix band'));

$executive = ReportService::generate($assessmentId, 'executive');
$executiveSnapshot = ReportService::snapshot((int) $executive['id']);
check('executive report omits the check log', $executiveSnapshot['test_log'] === []);

ReportService::finalise((int) $report['id']);
throwsWith('a finalised report cannot be deleted',
    fn () => ReportService::delete((int) $report['id']), 'cannot be deleted');

// ===========================================================================
section('12. Injection resistance of the platform itself');
// ===========================================================================

$hostile = "Robert'); DROP TABLE findings; --";
$hostileFinding = FindingService::create($assessmentId, [
    'title'       => 'Hostile input test ' . $hostile,
    'description' => 'Storing a classic SQL injection payload as ordinary text: ' . $hostile . ' plus <script>alert(1)</script>.',
    'vuln_class'  => 'SQL Injection',
    'likelihood'  => 1, 'impact' => 1,
    'ignore_duplicates' => true,
]);
check('findings table survives a hostile title',
    (int) Database::scalar('SELECT COUNT(*) FROM findings') > 0);
check('the payload is stored verbatim, not executed',
    str_contains((string) $hostileFinding['title'], 'DROP TABLE'));

$searchResults = FindingService::listFor($assessmentId, ['search' => "' OR 1=1 --"]);
equals('a search payload matches nothing rather than everything', 0, count($searchResults));

$reportHtml = ReportService::renderHtml((int) ReportService::generate($assessmentId, 'full')['id']);
check('stored XSS payload is escaped in the rendered report',
    str_contains($reportHtml, '&lt;script&gt;alert(1)&lt;/script&gt;') && !str_contains($reportHtml, '<script>alert(1)</script>'));

// ===========================================================================
// Summary
// ===========================================================================
$results = $GLOBALS['tests'];
$total = $results['pass'] + $results['fail'];

echo "\n" . str_repeat('=', 68) . "\n";
if ($results['fail'] === 0) {
    echo "\033[32m  ALL " . $total . " CHECKS PASSED\033[0m\n";
} else {
    echo "\033[31m  " . $results['fail'] . ' of ' . $total . " CHECKS FAILED\033[0m\n\n";
    foreach ($results['failures'] as $failure) {
        echo '   - ' . $failure . "\n";
    }
}
echo str_repeat('=', 68) . "\n";
printf("  %d assertions in %.2f s\n\n", $total, microtime(true) - APP_START);

@unlink($sqlitePath);
@unlink($sqlitePath . '-wal');
@unlink($sqlitePath . '-shm');

exit($results['fail'] === 0 ? 0 : 1);
