<?php

declare(strict_types=1);

namespace App\Core;

/**
 * Request reading and JSON responses.
 *
 * Input is read only through these helpers so that every value entering the
 * application is typed and length-bounded at the boundary.
 */
final class Http
{
    /** @var array<string,mixed>|null */
    private static ?array $jsonBody = null;

    public static function method(): string
    {
        return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    }

    public static function path(): string
    {
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $base = rtrim((string) Config::get('app.base_path', ''), '/');
        if ($base !== '' && str_starts_with($path, $base)) {
            $path = substr($path, strlen($base));
        }
        // Strip the api front-controller prefix when present.
        if (str_starts_with($path, '/api/index.php')) {
            $path = substr($path, strlen('/api/index.php'));
        } elseif (str_starts_with($path, '/api')) {
            $path = substr($path, strlen('/api'));
        }
        $path = '/' . trim($path, '/');
        return $path === '/' ? '/' : rtrim($path, '/');
    }

    public static function clientIp(): string
    {
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        return substr($ip, 0, 45);
    }

    public static function userAgent(): string
    {
        return substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
    }

    /** @return array<string,mixed> */
    public static function body(): array
    {
        if (self::$jsonBody !== null) {
            return self::$jsonBody;
        }
        $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
        if (str_contains($contentType, 'application/json')) {
            $raw = file_get_contents('php://input') ?: '';
            $decoded = json_decode($raw, true);
            self::$jsonBody = is_array($decoded) ? $decoded : [];
        } else {
            self::$jsonBody = $_POST;
        }
        return self::$jsonBody;
    }

    public static function input(string $key, mixed $default = null): mixed
    {
        $body = self::body();
        if (array_key_exists($key, $body)) {
            return $body[$key];
        }
        return $_GET[$key] ?? $default;
    }

    public static function str(string $key, string $default = '', int $maxLength = 65535): string
    {
        $value = self::input($key, $default);
        if (is_array($value) || is_object($value)) {
            return $default;
        }
        $value = trim((string) $value);
        // Strip control characters except tab, newline and carriage return.
        $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '';
        return mb_substr($value, 0, $maxLength);
    }

    public static function int(string $key, int $default = 0): int
    {
        $value = self::input($key, null);
        if ($value === null || $value === '' || !is_scalar($value)) {
            return $default;
        }
        return (int) $value;
    }

    public static function float(string $key, float $default = 0.0): float
    {
        $value = self::input($key, null);
        if ($value === null || $value === '' || !is_scalar($value)) {
            return $default;
        }
        return (float) $value;
    }

    public static function bool(string $key, bool $default = false): bool
    {
        $value = self::input($key, null);
        if ($value === null || $value === '') {
            return $default;
        }
        if (is_bool($value)) {
            return $value;
        }
        return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true);
    }

    /** @return array<int,mixed> */
    public static function arr(string $key): array
    {
        $value = self::input($key, []);
        return is_array($value) ? array_values($value) : [];
    }

    /** Returns the value only when it is a member of $allowed, otherwise the fallback. */
    public static function enum(string $key, array $allowed, string $fallback): string
    {
        $value = self::str($key, $fallback, 64);
        return in_array($value, $allowed, true) ? $value : $fallback;
    }

    public static function dateOrNull(string $key): ?string
    {
        $value = self::str($key, '', 10);
        if ($value === '') {
            return null;
        }
        $d = \DateTime::createFromFormat('Y-m-d', $value);
        return ($d && $d->format('Y-m-d') === $value) ? $value : null;
    }

    // -----------------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------------

    public static function json(mixed $payload, int $status = 200): never
    {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store, no-cache, must-revalidate');
            header('Referrer-Policy: no-referrer');
        }
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    public static function ok(mixed $data = null, array $extra = []): never
    {
        self::json(array_merge(['ok' => true, 'data' => $data], $extra));
    }

    public static function fail(string $message, int $status = 400, array $extra = []): never
    {
        self::json(array_merge(['ok' => false, 'error' => $message], $extra), $status);
    }

    /** Escapes for HTML output. Used by the report templates. */
    public static function e(?string $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
