<?php

declare(strict_types=1);

namespace App\Core;

/**
 * Dot-notation access to the configuration array, plus a cached view of the
 * admin-editable `settings` table so runtime toggles are a single call away.
 */
final class Config
{
    /** @var array<string,mixed> */
    private static array $data = [];

    /** @var array<string,string>|null */
    private static ?array $settings = null;

    /** @param array<string,mixed> $data */
    public static function load(array $data): void
    {
        self::$data = $data;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        $node = self::$data;
        foreach (explode('.', $key) as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return $default;
            }
            $node = $node[$segment];
        }
        return $node;
    }

    /** @return array<string,mixed> */
    public static function all(): array
    {
        return self::$data;
    }

    // -----------------------------------------------------------------------
    // Database-backed settings
    // -----------------------------------------------------------------------

    /** @return array<string,string> */
    public static function settings(bool $refresh = false): array
    {
        if (self::$settings === null || $refresh) {
            self::$settings = [];
            try {
                $rows = Database::all('SELECT skey, svalue FROM settings');
                foreach ($rows as $row) {
                    self::$settings[$row['skey']] = (string) ($row['svalue'] ?? '');
                }
            } catch (\Throwable) {
                self::$settings = [];
            }
        }
        return self::$settings;
    }

    public static function setting(string $key, mixed $default = null): mixed
    {
        $all = self::settings();
        return array_key_exists($key, $all) ? $all[$key] : $default;
    }

    public static function settingBool(string $key, bool $default = false): bool
    {
        $value = self::setting($key);
        if ($value === null || $value === '') {
            return $default;
        }
        return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true);
    }

    public static function settingFloat(string $key, float $default = 0.0): float
    {
        $value = self::setting($key);
        return ($value === null || $value === '') ? $default : (float) $value;
    }

    public static function settingInt(string $key, int $default = 0): int
    {
        $value = self::setting($key);
        return ($value === null || $value === '') ? $default : (int) $value;
    }

    public static function putSetting(string $key, string $value, ?int $userId = null): void
    {
        $driver = Database::driver();
        if ($driver === 'sqlite') {
            Database::run(
                'INSERT INTO settings (skey, svalue, updated_by, updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP)
                 ON CONFLICT(skey) DO UPDATE SET svalue = excluded.svalue,
                     updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP',
                [$key, $value, $userId]
            );
        } else {
            Database::run(
                'INSERT INTO settings (skey, svalue, updated_by, updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP)
                 ON DUPLICATE KEY UPDATE svalue = VALUES(svalue),
                     updated_by = VALUES(updated_by), updated_at = CURRENT_TIMESTAMP',
                [$key, $value, $userId]
            );
        }
        self::$settings = null;
    }
}
