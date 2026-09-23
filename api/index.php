<?php
/**
 * DVWA x BURPSUITE - JSON API front controller.
 *
 * Every request from the browser interface arrives here. Routing, the auth
 * and CSRF guards, and the error envelope all live in one place so no
 * endpoint can accidentally be published without them.
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\Core\Http;
use App\Core\Router;

// Security headers for the API surface.
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

// The interface is same-origin; refuse cross-origin preflight outright.
if (Http::method() === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$router = new Router();
require __DIR__ . '/routes.php';

try {
    $router->dispatch(Http::method(), Http::path());
} catch (RuntimeException | InvalidArgumentException $e) {
    // Domain errors: the message is written for the analyst, so show it.
    Http::fail($e->getMessage(), 422);
} catch (Throwable $e) {
    error_log('[api] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    Http::fail(
        \App\Core\Config::get('app.debug') ? $e->getMessage() : 'An unexpected error occurred. Check storage/logs/php-error.log.',
        500
    );
}
