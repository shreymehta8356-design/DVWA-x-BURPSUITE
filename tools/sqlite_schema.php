<?php
/**
 * MySQL -> SQLite DDL translation, used ONLY by tools/selftest.php.
 *
 * The supported deployment target is MySQL/MariaDB under XAMPP. This
 * translation exists so the whole application - services, controllers, models,
 * the AI layer and the report engine - can be exercised end to end on a
 * machine with no database server, which is what makes the self test usable
 * as a pre-deployment check and in a marking environment.
 *
 * It handles exactly the constructs used in database/schema.sql and is not a
 * general purpose converter.
 */

declare(strict_types=1);

/**
 * @return array{tables:array<int,string>,indexes:array<int,string>}
 */
function mysqlDdlToSqlite(string $sql): array
{
    // Drop statements SQLite has no concept of.
    $sql = preg_replace('/^\s*--.*$/m', '', $sql) ?? $sql;
    $sql = preg_replace('/^\s*(SET|USE|CREATE DATABASE)\b[^;]*;/mi', '', $sql) ?? $sql;

    $tables = [];
    $indexes = [];

    // DROP TABLE IF EXISTS `x`;  ... CREATE TABLE `x` ( ... ) ENGINE=...;
    preg_match_all('/CREATE\s+TABLE\s+`?(\w+)`?\s*\((.*?)\)\s*ENGINE=[^;]*;/is', $sql, $matches, PREG_SET_ORDER);

    foreach ($matches as $match) {
        $table = $match[1];
        $body  = $match[2];

        $columns = [];
        $autoIncrementColumn = null;

        foreach (splitDefinitions($body) as $definition) {
            $definition = trim($definition);
            if ($definition === '') {
                continue;
            }

            // Secondary indexes become separate CREATE INDEX statements.
            if (preg_match('/^KEY\s+`?(\w+)`?\s*\((.+)\)$/i', $definition, $m)) {
                $indexes[] = 'CREATE INDEX IF NOT EXISTS ' . $m[1] . ' ON ' . $table . ' (' . cleanColumns($m[2]) . ')';
                continue;
            }
            if (preg_match('/^UNIQUE\s+KEY\s+`?(\w+)`?\s*\((.+)\)$/i', $definition, $m)) {
                $indexes[] = 'CREATE UNIQUE INDEX IF NOT EXISTS ' . $m[1] . ' ON ' . $table . ' (' . cleanColumns($m[2]) . ')';
                continue;
            }

            // PRIMARY KEY on the auto-increment column is folded into the column.
            if (preg_match('/^PRIMARY\s+KEY\s*\(\s*`?(\w+)`?\s*\)$/i', $definition, $m)) {
                if ($autoIncrementColumn === $m[1]) {
                    continue;
                }
                $columns[] = 'PRIMARY KEY (' . $m[1] . ')';
                continue;
            }

            // Foreign keys pass through, minus the constraint name syntax SQLite
            // accepts but does not need.
            if (preg_match('/^CONSTRAINT\s+`?\w+`?\s+(FOREIGN\s+KEY.*)$/is', $definition, $m)) {
                $columns[] = str_replace('`', '', $m[1]);
                continue;
            }

            // Ordinary column.
            if (preg_match('/^`?(\w+)`?\s+(.*)$/s', $definition, $m)) {
                $name = $m[1];
                $rest = $m[2];

                if (stripos($rest, 'AUTO_INCREMENT') !== false) {
                    $autoIncrementColumn = $name;
                    $columns[] = $name . ' INTEGER PRIMARY KEY AUTOINCREMENT';
                    continue;
                }
                $columns[] = $name . ' ' . translateType($rest);
                continue;
            }

            $columns[] = str_replace('`', '', $definition);
        }

        $tables[] = 'DROP TABLE IF EXISTS ' . $table;
        $tables[] = 'CREATE TABLE ' . $table . " (\n  " . implode(",\n  ", $columns) . "\n)";
    }

    return ['tables' => $tables, 'indexes' => $indexes];
}

/** Splits a CREATE TABLE body on commas that are not inside parentheses. */
function splitDefinitions(string $body): array
{
    $parts = [];
    $depth = 0;
    $buffer = '';
    $length = strlen($body);

    for ($i = 0; $i < $length; $i++) {
        $char = $body[$i];
        if ($char === '(') { $depth++; }
        if ($char === ')') { $depth--; }
        if ($char === ',' && $depth === 0) {
            $parts[] = $buffer;
            $buffer = '';
            continue;
        }
        $buffer .= $char;
    }
    if (trim($buffer) !== '') {
        $parts[] = $buffer;
    }
    return $parts;
}

function cleanColumns(string $columns): string
{
    return preg_replace('/[`\s]/', '', $columns) ?? $columns;
}

function translateType(string $definition): string
{
    $out = $definition;
    $out = preg_replace('/\bUNSIGNED\b/i', '', $out) ?? $out;
    $out = preg_replace('/\bMEDIUMTEXT\b|\bLONGTEXT\b|\bTINYTEXT\b/i', 'TEXT', $out) ?? $out;
    $out = preg_replace('/\bTINYINT\s*\(\s*\d+\s*\)/i', 'INTEGER', $out) ?? $out;
    $out = preg_replace('/\b(BIGINT|INT|SMALLINT|TINYINT)\b(\s*\(\s*\d+\s*\))?/i', 'INTEGER', $out) ?? $out;
    $out = preg_replace('/\bDECIMAL\s*\(\s*\d+\s*,\s*\d+\s*\)/i', 'REAL', $out) ?? $out;
    $out = preg_replace('/\b(VARCHAR|CHAR)\s*\(\s*\d+\s*\)/i', 'TEXT', $out) ?? $out;
    $out = preg_replace('/\bDATETIME\b/i', 'TEXT', $out) ?? $out;
    $out = preg_replace('/\bDATE\b/i', 'TEXT', $out) ?? $out;
    $out = str_replace('`', '', $out);
    return trim(preg_replace('/\s+/', ' ', $out) ?? $out);
}

/**
 * Loads seed SQL (plain DELETE/INSERT statements) into any PDO connection.
 */
function loadSeedSql(PDO $pdo, string $path): void
{
    $sql = (string) file_get_contents($path);
    $sql = preg_replace('/^\s*--.*$/m', '', $sql) ?? $sql;
    $sql = preg_replace('/^\s*(SET|USE)\b[^;]*;/mi', '', $sql) ?? $sql;

    foreach (splitStatements($sql) as $statement) {
        $statement = trim($statement);
        if ($statement === '') {
            continue;
        }
        $pdo->exec($statement);
    }
}

/** Splits on semicolons that are not inside a quoted string. */
function splitStatements(string $sql): array
{
    $statements = [];
    $buffer = '';
    $inString = false;
    $length = strlen($sql);

    for ($i = 0; $i < $length; $i++) {
        $char = $sql[$i];

        if ($inString) {
            if ($char === '\\') {                       // escaped character
                $buffer .= $char . ($sql[$i + 1] ?? '');
                $i++;
                continue;
            }
            if ($char === "'") {
                if (($sql[$i + 1] ?? '') === "'") {     // doubled quote
                    $buffer .= "''";
                    $i++;
                    continue;
                }
                $inString = false;
            }
            $buffer .= $char;
            continue;
        }

        if ($char === "'") {
            $inString = true;
            $buffer .= $char;
            continue;
        }
        if ($char === ';') {
            $statements[] = $buffer;
            $buffer = '';
            continue;
        }
        $buffer .= $char;
    }

    if (trim($buffer) !== '') {
        $statements[] = $buffer;
    }
    return $statements;
}
