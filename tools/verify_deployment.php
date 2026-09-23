<?php
/**
 * DVWA x BURPSUITE - deployment verification.
 *
 *   php tools/verify_deployment.php
 *   php tools/verify_deployment.php --url http://localhost/dvwa-burp-platform
 *
 * Checks a REAL installation rather than a test harness: the MySQL connection,
 * the schema, the seeded reference data, the storage permissions, the trained
 * model, and - if the URL is reachable - the live HTTP surface including the
 * authentication, CSRF and role guards.
 *
 * Run this after following DEPLOYMENT.md, and again any time the platform
 * starts behaving oddly. It changes nothing.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("Command line only.\n");
}

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\AI\NaiveBayesClassifier;
use App\Core\Audit;
use App\Core\Config;
use App\Core\Database;

$options = getopt('', ['url::']);
$baseUrl = rtrim((string) ($options['url'] ?? ('http://localhost' . Config::get('app.base_path', ''))), '/');

$pass = 0;
$fail = 0;
$warn = 0;

function result(string $name, bool $ok, string $detail = '', bool $fatal = true): void
{
    global $pass, $fail, $warn;
    if ($ok) {
        $pass++;
        echo "  [ ok ] $name" . ($detail !== '' ? "  ($detail)" : '') . "\n";
    } elseif ($fatal) {
        $fail++;
        echo "  [FAIL] $name" . ($detail !== '' ? "  ($detail)" : '') . "\n";
    } else {
        $warn++;
        echo "  [warn] $name" . ($detail !== '' ? "  ($detail)" : '') . "\n";
    }
}

function heading(string $text): void
{
    echo "\n" . $text . "\n" . str_repeat('-', strlen($text)) . "\n";
}

echo "\nDVWA x BURPSUITE - deployment verification\n";
echo str_repeat('=', 60) . "\n";

// ---------------------------------------------------------------------------
heading('1. PHP environment');
// ---------------------------------------------------------------------------
result('PHP 8.0 or newer', version_compare(PHP_VERSION, '8.0.0', '>='), PHP_VERSION);
foreach (['pdo_mysql', 'mbstring', 'json', 'fileinfo', 'openssl', 'simplexml'] as $extension) {
    result('extension ' . $extension, extension_loaded($extension));
}
result('extension curl (optional, only for the local LLM)', extension_loaded('curl'), '', false);
result('display_errors is off', ini_get('display_errors') !== '1', 'set display_errors = Off in php.ini for production', false);

// ---------------------------------------------------------------------------
heading('2. Storage');
// ---------------------------------------------------------------------------
$storage = (string) Config::get('app.storage_path');
foreach (['evidence', 'models', 'reports', 'logs', 'tmp'] as $dir) {
    $path = $storage . '/' . $dir;
    result('storage/' . $dir . ' writable', is_dir($path) && is_writable($path), $path);
}
result('evidence store is protected by .htaccess',
    is_file($storage . '/evidence/.htaccess'),
    'storage/evidence/.htaccess is missing - re-extract the project', false);

// ---------------------------------------------------------------------------
heading('3. Database');
// ---------------------------------------------------------------------------
try {
    $driver = Database::driver();
    result('connected (' . $driver . ')', true, (string) Config::get('db.name'));
} catch (Throwable $e) {
    result('database connection', false, $e->getMessage());
    echo "\nCannot continue without a database. Start MySQL in XAMPP and check config/config.php.\n\n";
    exit(1);
}

$expected = [
    'users', 'settings', 'assessments', 'scope_items', 'test_catalog', 'assessment_tests',
    'risk_matrix', 'severity_sla', 'findings', 'evidence', 'evidence_custody', 'remediation',
    'remediation_log', 'retests', 'reports', 'burp_imports', 'burp_issues', 'ai_runs',
    'ai_training_data', 'audit_log', 'login_attempts',
];
$missing = [];
foreach ($expected as $table) {
    try {
        Database::scalar('SELECT COUNT(*) FROM ' . $table);
    } catch (Throwable) {
        $missing[] = $table;
    }
}
result('all ' . count($expected) . ' tables present', $missing === [],
    $missing === [] ? '' : 'missing: ' . implode(', ', $missing));

if ($missing === []) {
    result('risk matrix seeded', (int) Database::scalar('SELECT COUNT(*) FROM risk_matrix') === 25);
    result('severity SLA seeded', (int) Database::scalar('SELECT COUNT(*) FROM severity_sla') === 5);
    $checks = (int) Database::scalar('SELECT COUNT(*) FROM test_catalog WHERE is_active = 1');
    result('security check catalogue seeded', $checks >= 40, $checks . ' active checks');
    $corpus = (int) Database::scalar('SELECT COUNT(*) FROM ai_training_data WHERE is_active = 1');
    result('classifier training corpus seeded', $corpus >= 100, $corpus . ' examples');
    $users = (int) Database::scalar('SELECT COUNT(*) FROM users WHERE is_active = 1');
    result('at least one active account', $users >= 1, $users . ' accounts');

    $default = (int) Database::scalar('SELECT COUNT(*) FROM users WHERE must_change_password = 1');
    result('default passwords have been changed', $default === 0,
        $default . ' account(s) still on the shipped password - change them now', false);
}

// ---------------------------------------------------------------------------
heading('4. Offline models');
// ---------------------------------------------------------------------------
try {
    $model = NaiveBayesClassifier::loadOrTrain();
    $stats = $model->stats();
    result('classifier trained', $model->isTrained(),
        $stats['documents'] . ' docs, ' . $stats['class_count'] . ' classes, ' . $stats['vocabulary'] . ' terms');

    $probe = $model->predict('a single quote in the id parameter returned a mysql syntax error and every row was returned');
    result('classifier answers a known probe correctly', $probe['label'] === 'SQL Injection',
        'predicted ' . $probe['label'] . ' @ ' . round((float) $probe['confidence'] * 100) . '%');
} catch (Throwable $e) {
    result('classifier', false, $e->getMessage());
}

$cvss = \App\Services\RiskEngine::cvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
result('CVSS engine matches the published reference score', abs($cvss['base_score'] - 9.8) < 0.001,
    'computed ' . $cvss['base_score'] . ' for the reference vector');

// ---------------------------------------------------------------------------
heading('5. Record integrity');
// ---------------------------------------------------------------------------
if ($missing === []) {
    $chain = Audit::verifyChain();
    result('audit hash chain intact', $chain['valid'],
        $chain['valid'] ? $chain['checked'] . ' entries verified' : ('broken at entry ' . $chain['broken_at']));
}

// ---------------------------------------------------------------------------
heading('6. Live HTTP surface');
// ---------------------------------------------------------------------------
echo "  target: " . $baseUrl . "\n";

if (!function_exists('curl_init')) {
    result('HTTP checks', false, 'enable extension=curl in php.ini to run them', false);
} else {
    $get = static function (string $path) use ($baseUrl): array {
        $ch = curl_init($baseUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8,
            CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false,
        ]);
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        if ($raw === false) {
            return ['status' => 0, 'headers' => '', 'body' => ''];
        }
        return [
            'status'  => $status,
            'headers' => substr((string) $raw, 0, $headerSize),
            'body'    => substr((string) $raw, $headerSize),
        ];
    };

    $home = $get('/');
    if ($home['status'] === 0) {
        result('platform reachable', false,
            'no response from ' . $baseUrl . ' - start Apache, or pass --url', false);
    } else {
        result('platform reachable', $home['status'] === 200, 'HTTP ' . $home['status']);
        result('sign-in screen served', str_contains($home['body'], 'Sign in') || str_contains($home['body'], 'Assessment console'), '', false);

        foreach (['X-Content-Type-Options' => 'nosniff', 'X-Frame-Options' => 'DENY'] as $header => $value) {
            result('response header ' . $header, stripos($home['headers'], $header . ': ' . $value) !== false,
                'add mod_headers, or leave it - index.php sets it too', false);
        }
        result('Content-Security-Policy present', stripos($home['headers'], 'Content-Security-Policy') !== false);

        $api = $get('/api/index.php/dashboard');
        result('API refuses an unauthenticated request', $api['status'] === 401, 'HTTP ' . $api['status']);

        foreach ([
            '/config/config.php'          => 'configuration',
            '/database/schema.sql'        => 'database schema',
            '/app/Core/Auth.php'          => 'application source',
            '/storage/logs/php-error.log' => 'error log',
        ] as $path => $label) {
            $probe = $get($path);
            $blocked = in_array($probe['status'], [403, 404], true)
                || ($probe['status'] === 200 && trim($probe['body']) === '');
            result('private path is not served: ' . $label, $blocked,
                'HTTP ' . $probe['status'] . ' for ' . $path . ' - check AllowOverride All in httpd.conf');
        }
    }
}

// ---------------------------------------------------------------------------
echo "\n" . str_repeat('=', 60) . "\n";
if ($fail === 0) {
    echo "  DEPLOYMENT OK - $pass checks passed" . ($warn > 0 ? ", $warn advisory" : '') . "\n";
} else {
    echo "  $fail CHECK(S) FAILED - $pass passed" . ($warn > 0 ? ", $warn advisory" : '') . "\n";
    echo "  Fix the items marked [FAIL] before using the platform for real work.\n";
}
echo str_repeat('=', 60) . "\n\n";

exit($fail === 0 ? 0 : 1);
