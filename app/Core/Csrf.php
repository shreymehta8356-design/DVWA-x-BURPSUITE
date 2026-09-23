<?php

declare(strict_types=1);

namespace App\Core;

/**
 * Synchroniser token pattern.
 *
 * A per-session random token must accompany every state changing request,
 * sent either in the X-CSRF-Token header (used by the SPA) or a _csrf field.
 * Comparison is constant time.
 */
final class Csrf
{
    private const KEY = '_csrf_token';

    public static function token(): string
    {
        if (empty($_SESSION[self::KEY])) {
            self::rotate();
        }
        return (string) $_SESSION[self::KEY];
    }

    public static function rotate(): void
    {
        $_SESSION[self::KEY] = bin2hex(random_bytes(32));
    }

    public static function isValid(?string $candidate): bool
    {
        $expected = $_SESSION[self::KEY] ?? '';
        if ($expected === '' || $candidate === null || $candidate === '') {
            return false;
        }
        return hash_equals((string) $expected, $candidate);
    }

    public static function requireValidToken(): void
    {
        $header = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        $body   = Http::body()['_csrf'] ?? null;
        $candidate = is_string($header) ? $header : (is_string($body) ? $body : null);

        if (!self::isValid($candidate)) {
            Audit::log('csrf.rejected', 'route', null, ['path' => Http::path()]);
            Http::fail('CSRF token missing or invalid. Reload the page and try again.', 419, ['code' => 'csrf']);
        }
    }
}
