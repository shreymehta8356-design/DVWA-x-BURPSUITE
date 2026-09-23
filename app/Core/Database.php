<?php

declare(strict_types=1);

namespace App\Core;

use PDO;
use PDOException;
use PDOStatement;
use RuntimeException;

/**
 * Thin PDO wrapper.
 *
 * Every statement in this application goes through here and every one of them
 * is prepared with bound parameters - the platform never concatenates user
 * input into SQL. Emulated prepares are disabled so the driver sends real
 * parameterised statements to the server.
 *
 * The MySQL driver is the supported deployment target (XAMPP). The SQLite
 * driver exists so tools/selftest.php can exercise the whole application
 * without a database server.
 */
final class Database
{
    private static ?PDO $pdo = null;
    /** @var array<string,mixed> */
    private static array $config = [];
    private static int $queryCount = 0;

    /** @param array<string,mixed> $config */
    public static function configure(array $config): void
    {
        self::$config = $config;
        self::$pdo = null;
    }

    public static function driver(): string
    {
        return (string) (self::$config['driver'] ?? 'mysql');
    }

    public static function pdo(): PDO
    {
        if (self::$pdo instanceof PDO) {
            return self::$pdo;
        }

        $c = self::$config;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_STRINGIFY_FETCHES  => false,
        ];

        try {
            if (self::driver() === 'sqlite') {
                $path = (string) ($c['sqlite_path'] ?? (APP_ROOT . '/storage/tmp/selftest.sqlite'));
                self::$pdo = new PDO('sqlite:' . $path, null, null, $options);
                self::$pdo->exec('PRAGMA foreign_keys = ON');
                self::$pdo->exec('PRAGMA journal_mode = WAL');
            } else {
                $dsn = sprintf(
                    'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                    $c['host'] ?? '127.0.0.1',
                    (int) ($c['port'] ?? 3306),
                    $c['name'] ?? 'dvwa_burp_platform',
                    $c['charset'] ?? 'utf8mb4'
                );
                self::$pdo = new PDO($dsn, (string) ($c['user'] ?? 'root'), (string) ($c['pass'] ?? ''), $options);
                self::$pdo->exec("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'");
            }
        } catch (PDOException $e) {
            throw new RuntimeException(
                'Database connection failed. Check config/config.php and that MySQL is running in XAMPP. ('
                . $e->getMessage() . ')',
                0,
                $e
            );
        }

        return self::$pdo;
    }

    /** @param array<int|string,mixed> $params */
    public static function run(string $sql, array $params = []): PDOStatement
    {
        self::$queryCount++;
        $stmt = self::pdo()->prepare($sql);
        $stmt->execute(self::normalise($params));
        return $stmt;
    }

    /**
     * @param  array<int|string,mixed> $params
     * @return array<int,array<string,mixed>>
     */
    public static function all(string $sql, array $params = []): array
    {
        /** @var array<int,array<string,mixed>> $rows */
        $rows = self::run($sql, $params)->fetchAll();
        return $rows;
    }

    /**
     * @param  array<int|string,mixed> $params
     * @return array<string,mixed>|null
     */
    public static function one(string $sql, array $params = []): ?array
    {
        $row = self::run($sql, $params)->fetch();
        return $row === false ? null : $row;
    }

    /** @param array<int|string,mixed> $params */
    public static function scalar(string $sql, array $params = []): mixed
    {
        $value = self::run($sql, $params)->fetchColumn();
        return $value === false ? null : $value;
    }

    /**
     * Insert helper. Column names come from the caller (never from request
     * data) and values are always bound.
     *
     * @param array<string,mixed> $data
     */
    public static function insert(string $table, array $data): int
    {
        $columns = array_keys($data);
        $placeholders = implode(',', array_fill(0, count($columns), '?'));
        $sql = 'INSERT INTO ' . self::quoteIdent($table) . ' ('
            . implode(',', array_map([self::class, 'quoteIdent'], $columns))
            . ") VALUES ($placeholders)";
        self::run($sql, array_values($data));
        return (int) self::pdo()->lastInsertId();
    }

    /**
     * @param array<string,mixed>      $data
     * @param array<int|string,mixed>  $whereParams
     */
    public static function update(string $table, array $data, string $where, array $whereParams = []): int
    {
        if ($data === []) {
            return 0;
        }
        $sets = [];
        foreach (array_keys($data) as $column) {
            $sets[] = self::quoteIdent($column) . ' = ?';
        }
        $sql = 'UPDATE ' . self::quoteIdent($table) . ' SET ' . implode(', ', $sets) . ' WHERE ' . $where;
        $stmt = self::run($sql, array_merge(array_values($data), array_values($whereParams)));
        return $stmt->rowCount();
    }

    /** @param array<int|string,mixed> $params */
    public static function delete(string $table, string $where, array $params = []): int
    {
        $stmt = self::run('DELETE FROM ' . self::quoteIdent($table) . ' WHERE ' . $where, $params);
        return $stmt->rowCount();
    }

    public static function begin(): void
    {
        if (!self::pdo()->inTransaction()) {
            self::pdo()->beginTransaction();
        }
    }

    public static function commit(): void
    {
        if (self::pdo()->inTransaction()) {
            self::pdo()->commit();
        }
    }

    public static function rollback(): void
    {
        if (self::pdo()->inTransaction()) {
            self::pdo()->rollBack();
        }
    }

    public static function queryCount(): int
    {
        return self::$queryCount;
    }

    /**
     * Booleans are stored as TINYINT(1); PDO would otherwise bind them as
     * native booleans which MySQL in strict mode rejects for integer columns.
     *
     * @param  array<int|string,mixed> $params
     * @return array<int|string,mixed>
     */
    private static function normalise(array $params): array
    {
        foreach ($params as $key => $value) {
            if (is_bool($value)) {
                $params[$key] = $value ? 1 : 0;
            } elseif ($value instanceof \DateTimeInterface) {
                $params[$key] = $value->format('Y-m-d H:i:s');
            } elseif (is_array($value)) {
                $params[$key] = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }
        }
        return $params;
    }

    /** Identifiers are developer-supplied constants; this is belt and braces. */
    private static function quoteIdent(string $identifier): string
    {
        $clean = preg_replace('/[^A-Za-z0-9_]/', '', $identifier) ?? '';
        if ($clean === '') {
            throw new RuntimeException('Invalid SQL identifier.');
        }
        return '`' . $clean . '`';
    }
}
