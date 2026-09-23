<?php
/**
 * DVWA x BURPSUITE - command line installer.
 *
 *   php tools/install.php
 *   php tools/install.php --force          reinstall, dropping existing data
 *   php tools/install.php --no-demo        skip the worked demo assessment
 *
 * Creates the database, imports the schema and seed data, checks the storage
 * directories, trains the offline classifier and prints the sign-in details.
 * Everything it does can also be done by hand from database/*.sql.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This installer runs from the command line only.\n");
}

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\AI\NaiveBayesClassifier;
use App\Core\Config;
use App\Core\Database;

$options = getopt('', ['force', 'no-demo', 'help']);
if (isset($options['help'])) {
    echo "Usage: php tools/install.php [--force] [--no-demo]\n";
    exit(0);
}
$force = isset($options['force']);
$withDemo = !isset($options['no-demo']);

line();
say('DVWA x BURPSUITE - installer');
line();

// ---------------------------------------------------------------------------
// 1. Environment
// ---------------------------------------------------------------------------
step('Checking the PHP environment');
ok('PHP ' . PHP_VERSION, version_compare(PHP_VERSION, '8.0.0', '>='), 'PHP 8.0 or newer is required.');

foreach (['pdo_mysql' => true, 'mbstring' => true, 'json' => true, 'fileinfo' => true,
          'openssl' => true, 'simplexml' => true, 'curl' => false] as $extension => $required) {
    $loaded = extension_loaded($extension);
    if ($required) {
        ok('extension ' . $extension, $loaded, 'Enable extension=' . $extension . ' in php.ini and restart Apache.');
    } elseif (!$loaded) {
        warn('extension ' . $extension . ' is not enabled - the optional local LLM assistant will be unavailable.');
    } else {
        ok('extension ' . $extension, true);
    }
}

// ---------------------------------------------------------------------------
// 2. Storage
// ---------------------------------------------------------------------------
step('Checking storage directories');
$storage = (string) Config::get('app.storage_path', APP_ROOT . '/storage');
foreach (['evidence', 'models', 'reports', 'logs', 'tmp'] as $dir) {
    $path = $storage . '/' . $dir;
    if (!is_dir($path)) {
        @mkdir($path, 0775, true);
    }
    ok('storage/' . $dir . ' writable', is_dir($path) && is_writable($path),
        'Grant write permission on ' . $path);
}

// ---------------------------------------------------------------------------
// 3. Database
// ---------------------------------------------------------------------------
step('Connecting to MySQL');
$db = (array) Config::get('db', []);
$dsn = sprintf('mysql:host=%s;port=%d;charset=%s', $db['host'] ?? '127.0.0.1', (int) ($db['port'] ?? 3306), $db['charset'] ?? 'utf8mb4');

try {
    $pdo = new PDO($dsn, (string) ($db['user'] ?? 'root'), (string) ($db['pass'] ?? ''), [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    ok('connected to ' . ($db['host'] ?? '127.0.0.1') . ':' . ($db['port'] ?? 3306), true);
} catch (PDOException $e) {
    fail('Could not connect to MySQL: ' . $e->getMessage()
        . "\n  Start MySQL in the XAMPP control panel and check the credentials in config/config.php.");
}

$name = (string) ($db['name'] ?? 'dvwa_burp_platform');
$exists = (bool) $pdo->query('SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '
    . $pdo->quote($name))->fetchColumn();

if ($exists && !$force) {
    $tables = (int) $pdo->query('SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '
        . $pdo->quote($name))->fetchColumn();
    if ($tables > 0) {
        warn('Database "' . $name . '" already exists with ' . $tables . ' table(s).');
        say('  Re-running the schema will DROP those tables and every assessment in them.');
        if (!confirm('  Continue and reinstall? [y/N] ')) {
            say("\nInstallation cancelled. Nothing was changed.");
            exit(0);
        }
    }
}

step('Importing the schema');
runSqlFile($pdo, APP_ROOT . '/database/schema.sql');
ok('schema.sql imported', true);

$pdo->exec('USE `' . str_replace('`', '', $name) . '`');

step('Importing reference data');
runSqlFile($pdo, APP_ROOT . '/database/seed_reference.sql');
ok('risk matrix, SLA table, settings, ' .
    (int) $pdo->query('SELECT COUNT(*) FROM test_catalog')->fetchColumn() . ' security checks, ' .
    (int) $pdo->query('SELECT COUNT(*) FROM ai_training_data')->fetchColumn() . ' training examples', true);

step('Creating accounts');
runSqlFile($pdo, APP_ROOT . '/database/seed_users.sql');
ok((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() . ' default accounts created', true);

// ---------------------------------------------------------------------------
// 4. Train the offline classifier
// ---------------------------------------------------------------------------
step('Training the offline classifier');
try {
    Database::configure(Config::get('db', []));
    $model = NaiveBayesClassifier::retrain();
    $stats = $model->stats();
    ok($stats['documents'] . ' documents, ' . $stats['class_count'] . ' classes, ' .
       $stats['vocabulary'] . ' term vocabulary', true);
} catch (Throwable $e) {
    warn('Could not train the classifier now: ' . $e->getMessage()
        . ' - it will train itself on first use.');
}

// ---------------------------------------------------------------------------
// 5. Optional demo assessment
// ---------------------------------------------------------------------------
if ($withDemo) {
    step('Building the worked demo assessment');
    try {
        require __DIR__ . '/seed_demo.php';
        $summary = seedDemoAssessment();
        ok($summary, true);
    } catch (Throwable $e) {
        warn('Demo seed skipped: ' . $e->getMessage());
    }
}

// ---------------------------------------------------------------------------
// Done
// ---------------------------------------------------------------------------
line();
say('Installation complete.');
line();
say('  Open:      http://localhost' . Config::get('app.base_path', '/dvwa-burp-platform') . '/');
say('');
say('  admin    / Admin@DVWA2026     full control');
say('  lead     / Lead@DVWA2026      owns assessments, finalises reports');
say('  analyst  / Analyst@DVWA2026   runs checks, records evidence');
say('  reviewer / Review@DVWA2026    read only plus peer review');
say('');
say('  Change every one of these on first sign-in. Each account is already');
say('  flagged "must change password".');
line();

// ===========================================================================
// Helpers
// ===========================================================================

function runSqlFile(PDO $pdo, string $path): void
{
    if (!is_file($path)) {
        fail('Missing SQL file: ' . $path);
    }
    $sql = (string) file_get_contents($path);

    // Strip comments, then split on semicolons at end of line. The bundled SQL
    // deliberately contains no stored routines, so this is sufficient.
    $sql = preg_replace('/^\s*--.*$/m', '', $sql) ?? $sql;
    $statements = array_filter(array_map('trim', preg_split('/;\s*[\r\n]/', $sql) ?: []));

    foreach ($statements as $statement) {
        if ($statement === '' || $statement === ';') {
            continue;
        }
        try {
            $pdo->exec($statement);
        } catch (PDOException $e) {
            fail("SQL failed:\n  " . mb_substr($statement, 0, 200) . "\n  " . $e->getMessage());
        }
    }
}

function step(string $text): void { echo "\n> " . $text . "\n"; }
function say(string $text): void  { echo $text . "\n"; }
function line(): void             { echo str_repeat('-', 68) . "\n"; }

function ok(string $text, bool $passed, string $hint = ''): void
{
    echo ($passed ? '  [ ok ] ' : '  [FAIL] ') . $text . "\n";
    if (!$passed) {
        if ($hint !== '') { echo '         ' . $hint . "\n"; }
        exit(1);
    }
}

function warn(string $text): void { echo '  [warn] ' . $text . "\n"; }

function fail(string $text): never
{
    echo "\n  [FAIL] " . $text . "\n\n";
    exit(1);
}

function confirm(string $prompt): bool
{
    echo $prompt;
    $answer = trim((string) fgets(STDIN));
    return in_array(strtolower($answer), ['y', 'yes'], true);
}
