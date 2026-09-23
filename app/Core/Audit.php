<?php

declare(strict_types=1);

namespace App\Core;

/**
 * Tamper-evident audit trail.
 *
 * Every row stores a SHA-256 over its own canonical content plus the previous
 * row's hash, forming a chain. Deleting or editing any historical row breaks
 * verification from that point forward, which is what makes the generated
 * report defensible: Admin > Audit Trail can re-walk the chain and prove the
 * record has not been altered since it was written.
 */
final class Audit
{
    public const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * @param array<string,mixed>|null $detail
     */
    public static function log(
        string $action,
        ?string $entityType = null,
        ?int $entityId = null,
        ?array $detail = null,
        ?int $assessmentId = null,
        ?int $actorId = null,
        ?string $actorUsername = null
    ): void {
        try {
            $actorId ??= Auth::id();
            $actorUsername ??= (Auth::check() ? Auth::username() : 'system');

            $prev = (string) (Database::scalar('SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1') ?? self::GENESIS);

            $row = [
                'actor_id'       => $actorId,
                'actor_username' => mb_substr((string) $actorUsername, 0, 64),
                'actor_ip'       => PHP_SAPI === 'cli' ? 'cli' : Http::clientIp(),
                'action'         => mb_substr($action, 0, 60),
                'entity_type'    => $entityType !== null ? mb_substr($entityType, 0, 40) : null,
                'entity_id'      => $entityId,
                'assessment_id'  => $assessmentId,
                'detail'         => $detail !== null
                    ? json_encode(self::sanitise($detail), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                    : null,
                'created_at'     => date('Y-m-d H:i:s'),
            ];

            $row['prev_hash'] = $prev;
            $row['row_hash']  = self::hashRow($row, $prev);

            Database::insert('audit_log', $row);
        } catch (\Throwable $e) {
            // Auditing must never break the user-facing operation, but a
            // failure to audit is itself worth recording on disk.
            error_log('[audit] failed to write entry: ' . $e->getMessage());
        }
    }

    /**
     * Canonical serialisation used for the chain. Column order is fixed here
     * so a re-walk produces byte-identical input.
     *
     * @param array<string,mixed> $row
     */
    public static function hashRow(array $row, string $prevHash): string
    {
        $canonical = implode('|', [
            (string) ($row['actor_id'] ?? ''),
            (string) ($row['actor_username'] ?? ''),
            (string) ($row['actor_ip'] ?? ''),
            (string) ($row['action'] ?? ''),
            (string) ($row['entity_type'] ?? ''),
            (string) ($row['entity_id'] ?? ''),
            (string) ($row['assessment_id'] ?? ''),
            (string) ($row['detail'] ?? ''),
            (string) ($row['created_at'] ?? ''),
            $prevHash,
        ]);
        return hash('sha256', $canonical);
    }

    /**
     * Re-walks the chain and reports the first broken link.
     *
     * @return array{valid:bool,checked:int,broken_at:int|null,reason:string|null}
     */
    public static function verifyChain(int $limit = 100000): array
    {
        $rows = Database::all(
            'SELECT id, actor_id, actor_username, actor_ip, action, entity_type, entity_id,
                    assessment_id, detail, created_at, prev_hash, row_hash
             FROM audit_log ORDER BY id ASC LIMIT ' . max(1, $limit)
        );

        $expectedPrev = self::GENESIS;
        $checked = 0;

        foreach ($rows as $row) {
            $checked++;
            if ((string) $row['prev_hash'] !== $expectedPrev) {
                return [
                    'valid'     => false,
                    'checked'   => $checked,
                    'broken_at' => (int) $row['id'],
                    'reason'    => 'Previous-hash link does not match the preceding entry (a row was removed or reordered).',
                ];
            }
            $recomputed = self::hashRow($row, (string) $row['prev_hash']);
            if (!hash_equals((string) $row['row_hash'], $recomputed)) {
                return [
                    'valid'     => false,
                    'checked'   => $checked,
                    'broken_at' => (int) $row['id'],
                    'reason'    => 'Row content does not match its stored hash (the entry was edited after it was written).',
                ];
            }
            $expectedPrev = (string) $row['row_hash'];
        }

        return ['valid' => true, 'checked' => $checked, 'broken_at' => null, 'reason' => null];
    }

    /**
     * Audit details are shown back to users, so drop anything that looks like
     * a secret before it is written.
     *
     * @param  array<string,mixed> $detail
     * @return array<string,mixed>
     */
    private static function sanitise(array $detail): array
    {
        $blocked = ['password', 'pass', 'new_password', 'current_password', 'api_key', 'token', 'secret', '_csrf'];
        $out = [];
        foreach ($detail as $key => $value) {
            if (in_array(strtolower((string) $key), $blocked, true)) {
                $out[$key] = '[redacted]';
                continue;
            }
            if (is_array($value)) {
                $out[$key] = self::sanitise($value);
            } elseif (is_scalar($value) || $value === null) {
                $out[$key] = is_string($value) ? mb_substr($value, 0, 500) : $value;
            } else {
                $out[$key] = '[object]';
            }
        }
        return $out;
    }
}
