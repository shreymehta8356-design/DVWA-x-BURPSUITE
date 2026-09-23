<?php
/**
 * DVWA x BURPSUITE - application bootstrap.
 *
 * Loaded by every entry point (index.php, api/index.php, tools/*.php).
 * Registers the autoloader, loads configuration, hardens the session and
 * installs the error handlers.
 */

declare(strict_types=1);

define('APP_ROOT', dirname(__DIR__));
define('APP_START', microtime(true));

// ---------------------------------------------------------------------------
// PSR-4 style autoloader for the App\ namespace
// ---------------------------------------------------------------------------
spl_autoload_register(static function (string $class): void {
    $prefix = 'App\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = APP_ROOT . '/app/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

use App\Core\Config;
use App\Core\Database;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
$configFile = APP_ROOT . '/config/config.php';
if (!is_file($configFile)) {
    http_response_code(500);
    exit('Configuration missing. Copy config/config.sample.php to config/config.php.');
}
Config::load(require $configFile);

date_default_timezone_set(Config::get('app.timezone', 'UTC'));
mb_internal_encoding('UTF-8');

// ---------------------------------------------------------------------------
// Error handling - never leak internals to the client
// ---------------------------------------------------------------------------
$debug = (bool) Config::get('app.debug', false);
error_reporting(E_ALL);
ini_set('display_errors', $debug ? '1' : '0');
ini_set('log_errors', '1');
$logDir = Config::get('app.storage_path', APP_ROOT . '/storage') . '/logs';
if (!is_dir($logDir)) {
    @mkdir($logDir, 0775, true);
}
ini_set('error_log', $logDir . '/php-error.log');

set_exception_handler(static function (Throwable $e) use ($debug): void {
    error_log('[uncaught] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    if (!headers_sent()) {
        http_response_code(500);
    }
    $isApi = str_contains($_SERVER['REQUEST_URI'] ?? '', '/api/');
    if ($isApi) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'ok'    => false,
            'error' => $debug ? $e->getMessage() : 'Internal server error.',
            'trace' => $debug ? $e->getTraceAsString() : null,
        ], JSON_UNESCAPED_SLASHES);
    } else {
        echo '<h1>Internal server error</h1>';
        if ($debug) {
            echo '<pre>' . htmlspecialchars((string) $e, ENT_QUOTES, 'UTF-8') . '</pre>';
        }
    }
    exit;
});

// ---------------------------------------------------------------------------
// Storage directories
// ---------------------------------------------------------------------------
foreach (['evidence', 'models', 'reports', 'logs', 'tmp'] as $dir) {
    $path = Config::get('app.storage_path', APP_ROOT . '/storage') . '/' . $dir;
    if (!is_dir($path)) {
        @mkdir($path, 0775, true);
    }
}

// ---------------------------------------------------------------------------
// Session hardening (skipped on the CLI)
// ---------------------------------------------------------------------------
if (PHP_SAPI !== 'cli' && session_status() === PHP_SESSION_NONE) {
    $s = Config::get('session', []);
    session_name($s['name'] ?? 'DVWABURPSID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => rtrim(Config::get('app.base_path', ''), '/') . '/',
        'domain'   => '',
        'secure'   => (bool) ($s['cookie_secure'] ?? false),
        'httponly' => true,
        'samesite' => $s['cookie_samesite'] ?? 'Strict',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    session_start();
}

// ---------------------------------------------------------------------------
// Database singleton is created lazily on first use by Database::pdo()
// ---------------------------------------------------------------------------
Database::configure(Config::get('db', []));
