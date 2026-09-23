<?php

declare(strict_types=1);

namespace App\Services;

use App\AI\AiService;
use App\Core\Audit;
use App\Core\Auth;
use App\Core\Database;
use RuntimeException;

/**
 * Remediation tracking and retesting.
 *
 * A finding is not closed because someone says it was fixed - it is closed
 * because a retest recorded a "fixed" result with its own evidence. The two
 * halves of that promise live here.
 */
final class RemediationService
{
    public const STATUSES = ['not_started', 'in_progress', 'implemented', 'verified', 'deferred', 'accepted'];
    public const EFFORT   = ['low', 'medium', 'high'];
    public const RESULTS  = ['fixed', 'partially_fixed', 'not_fixed', 'not_testable'];

    /**
     * Creates the remediation record that accompanies every finding, seeded
     * from the curated knowledge base and with a due date derived from the
     * severity SLA.
     */
    public static function ensureFor(int $findingId, string $vulnClass, string $severity): array
    {
        $existing = Database::one('SELECT * FROM remediation WHERE finding_id = ?', [$findingId]);
        if ($existing !== null) {
            return $existing;
        }

        $kb = AiService::knowledgeBase()[$vulnClass] ?? null;
        $slaDays = RiskEngine::slaDays($severity);

        Database::insert('remediation', [
            'finding_id'          => $findingId,
            'recommendation'      => $kb['remediation'] ?? null,
            'secure_code_example' => $kb['secure_code'] ?? null,
            'reference_links'     => $kb['references'] ?? null,
            'effort'              => self::effortFor($vulnClass),
            'priority'            => max(1, 6 - RiskEngine::rank($severity)),
            'due_date'            => date('Y-m-d', strtotime('+' . $slaDays . ' days')),
            'sla_days'            => $slaDays,
            'status'              => 'not_started',
            'ai_assisted'         => $kb !== null ? 1 : 0,
            'created_by'          => Auth::id(),
        ]);

        return Database::one('SELECT * FROM remediation WHERE finding_id = ?', [$findingId]) ?? [];
    }

    /** @param array<string,mixed> $input */
    public static function update(int $findingId, array $input): array
    {
        $finding = Database::one('SELECT assessment_id, severity, ref_code FROM findings WHERE id = ?', [$findingId]);
        if ($finding === null) {
            throw new RuntimeException('Finding not found.');
        }
        $existing = self::ensureFor($findingId, '', (string) $finding['severity']);

        $data = [];
        foreach (['recommendation' => 20000, 'secure_code_example' => 20000, 'reference_links' => 4000, 'notes' => 10000,
                  'owner_name' => 120, 'owner_team' => 120] as $field => $limit) {
            if (array_key_exists($field, $input)) {
                $value = trim((string) $input[$field]);
                $data[$field] = $value !== '' ? mb_substr($value, 0, $limit) : null;
            }
        }
        if (isset($input['effort']) && in_array($input['effort'], self::EFFORT, true)) {
            $data['effort'] = $input['effort'];
        }
        if (isset($input['priority'])) {
            $data['priority'] = max(1, min(5, (int) $input['priority']));
        }
        if (array_key_exists('due_date', $input)) {
            $date = trim((string) $input['due_date']);
            $data['due_date'] = $date !== '' ? $date : null;
        }

        $newStatus = null;
        if (isset($input['status'])) {
            if (!in_array($input['status'], self::STATUSES, true)) {
                throw new RuntimeException('Remediation status must be one of: ' . implode(', ', self::STATUSES) . '.');
            }
            $newStatus = (string) $input['status'];
            if ($newStatus === 'verified') {
                $verified = (int) Database::scalar("SELECT COUNT(*) FROM retests WHERE finding_id = ? AND result = 'fixed'", [$findingId]);
                if ($verified === 0) {
                    throw new RuntimeException('Remediation can only be marked "verified" after a retest records a "fixed" result.');
                }
            }
            $data['status'] = $newStatus;
        }

        if ($data !== []) {
            $data['updated_at'] = date('Y-m-d H:i:s');
            Database::update('remediation', $data, 'finding_id = ?', [$findingId]);
        }

        if ($newStatus !== null && $newStatus !== (string) $existing['status']) {
            Database::insert('remediation_log', [
                'remediation_id' => (int) $existing['id'],
                'from_status'    => (string) $existing['status'],
                'to_status'      => $newStatus,
                'note'           => mb_substr((string) ($input['status_note'] ?? ''), 0, 500) ?: null,
                'actor_id'       => Auth::id(),
                'actor_name'     => Auth::check() ? Auth::username() : 'system',
            ]);

            // Keep the finding lifecycle in step with the remediation status.
            $findingStatus = match ($newStatus) {
                'in_progress' => 'in_remediation',
                'implemented' => 'ready_for_retest',
                default       => null,
            };
            if ($findingStatus !== null) {
                Database::update('findings', ['status' => $findingStatus, 'updated_at' => date('Y-m-d H:i:s')], 'id = ?', [$findingId]);
            }

            Audit::log('remediation.status_changed', 'finding', $findingId, [
                'ref_code' => $finding['ref_code'], 'from' => $existing['status'], 'to' => $newStatus,
            ], (int) $finding['assessment_id']);
        } elseif ($data !== []) {
            Audit::log('remediation.updated', 'finding', $findingId, ['fields' => array_keys($data)], (int) $finding['assessment_id']);
        }

        return self::findFor($findingId) ?? [];
    }

    /** Recomputes the due date when a severity change moves the SLA. */
    public static function realignSla(int $findingId, string $severity): void
    {
        $slaDays = RiskEngine::slaDays($severity);
        $row = Database::one('SELECT status, created_at FROM remediation WHERE finding_id = ?', [$findingId]);
        if ($row === null || in_array((string) $row['status'], ['implemented', 'verified', 'accepted'], true)) {
            return;
        }
        $base = strtotime((string) $row['created_at']) ?: time();
        Database::update('remediation', [
            'sla_days'  => $slaDays,
            'due_date'  => date('Y-m-d', $base + $slaDays * 86400),
            'priority'  => max(1, 6 - RiskEngine::rank($severity)),
            'updated_at' => date('Y-m-d H:i:s'),
        ], 'finding_id = ?', [$findingId]);
    }

    /** @return array<string,mixed>|null */
    public static function findFor(int $findingId): ?array
    {
        $row = Database::one(
            'SELECT r.*, u.full_name AS created_by_name FROM remediation r
             LEFT JOIN users u ON u.id = r.created_by WHERE r.finding_id = ?',
            [$findingId]
        );
        if ($row === null) {
            return null;
        }
        $row['id'] = (int) $row['id'];
        $row['finding_id'] = (int) $row['finding_id'];
        $row['priority'] = (int) $row['priority'];
        $row['sla_days'] = $row['sla_days'] !== null ? (int) $row['sla_days'] : null;
        $row['is_overdue'] = !empty($row['due_date'])
            && strtotime((string) $row['due_date']) < strtotime(date('Y-m-d'))
            && !in_array((string) $row['status'], ['implemented', 'verified', 'accepted'], true);
        $row['days_remaining'] = !empty($row['due_date'])
            ? (int) floor((strtotime((string) $row['due_date']) - strtotime(date('Y-m-d'))) / 86400)
            : null;
        $row['history'] = Database::all(
            'SELECT from_status, to_status, note, actor_name, created_at FROM remediation_log
             WHERE remediation_id = ? ORDER BY id ASC',
            [$row['id']]
        );
        return $row;
    }

    /** @return array<int,array<string,mixed>> */
    public static function trackerFor(int $assessmentId): array
    {
        $rows = Database::all(
            "SELECT f.id AS finding_id, f.ref_code, f.title, f.severity, f.status AS finding_status,
                    r.status, r.owner_name, r.owner_team, r.due_date, r.sla_days, r.priority, r.effort,
                    (SELECT COUNT(*) FROM retests rt WHERE rt.finding_id = f.id) AS retest_count,
                    (SELECT result FROM retests rt WHERE rt.finding_id = f.id ORDER BY round_no DESC LIMIT 1) AS last_retest_result
             FROM findings f
             LEFT JOIN remediation r ON r.finding_id = f.id
             WHERE f.assessment_id = ? AND f.status NOT IN ('false_positive','duplicate')
             ORDER BY CASE f.severity
                        WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                        WHEN 'low' THEN 2 ELSE 1 END DESC, r.due_date ASC",
            [$assessmentId]
        );
        $today = strtotime(date('Y-m-d'));
        foreach ($rows as &$row) {
            $row['finding_id'] = (int) $row['finding_id'];
            $row['retest_count'] = (int) $row['retest_count'];
            $row['is_overdue'] = !empty($row['due_date'])
                && strtotime((string) $row['due_date']) < $today
                && !in_array((string) $row['status'], ['implemented', 'verified', 'accepted'], true);
            $row['days_remaining'] = !empty($row['due_date'])
                ? (int) floor((strtotime((string) $row['due_date']) - $today) / 86400)
                : null;
        }
        return $rows;
    }

    // =======================================================================
    // Retesting
    // =======================================================================

    /**
     * @param  array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function recordRetest(int $findingId, array $input): array
    {
        $finding = Database::one('SELECT assessment_id, ref_code, severity, status FROM findings WHERE id = ?', [$findingId]);
        if ($finding === null) {
            throw new RuntimeException('Finding not found.');
        }

        $result = (string) ($input['result'] ?? '');
        if (!in_array($result, self::RESULTS, true)) {
            throw new RuntimeException('Retest result must be one of: ' . implode(', ', self::RESULTS) . '.');
        }
        $observation = trim((string) ($input['observation'] ?? ''));
        if (mb_strlen($observation) < 20) {
            throw new RuntimeException('Record what the retest actually showed, in at least 20 characters.');
        }
        $method = trim((string) ($input['method'] ?? ''));
        if ($method === '') {
            throw new RuntimeException('Record how the retest was performed so it can be repeated.');
        }

        $round = (int) Database::scalar('SELECT COALESCE(MAX(round_no), 0) FROM retests WHERE finding_id = ?', [$findingId]) + 1;

        $residual = null;
        if (in_array($result, ['partially_fixed', 'not_fixed'], true)) {
            $residual = in_array($input['residual_severity'] ?? '', RiskEngine::SEVERITIES, true)
                ? (string) $input['residual_severity']
                : ($result === 'partially_fixed' ? self::stepDown((string) $finding['severity']) : (string) $finding['severity']);
        }

        $retestId = Database::insert('retests', [
            'finding_id'        => $findingId,
            'round_no'          => $round,
            'retest_date'       => $input['retest_date'] ?? date('Y-m-d'),
            'tester_id'         => Auth::id(),
            'method'            => mb_substr($method, 0, 200),
            'result'            => $result,
            'observation'       => mb_substr($observation, 0, 20000),
            'residual_severity' => $residual,
            'closes_finding'    => $result === 'fixed' ? 1 : 0,
        ]);

        // Attach retest evidence when it was supplied with the result.
        $evidenceText = trim((string) ($input['evidence_text'] ?? ''));
        if ($evidenceText !== '') {
            EvidenceService::captureText((int) $finding['assessment_id'], [
                'evidence_type' => 'http_response',
                'title'         => 'Retest round ' . $round . ' - ' . $finding['ref_code'],
                'description'   => 'Evidence captured during retest round ' . $round . '.',
                'content_text'  => $evidenceText,
                'finding_id'    => $findingId,
                'retest_id'     => $retestId,
            ]);
        }

        // Drive the finding and remediation lifecycle from the retest outcome.
        if ($result === 'fixed') {
            Database::update('findings', [
                'status'      => 'resolved',
                'closed_at'   => date('Y-m-d H:i:s'),
                'verified_by' => Auth::id(),
                'updated_at'  => date('Y-m-d H:i:s'),
            ], 'id = ?', [$findingId]);
            Database::update('remediation', ['status' => 'verified', 'updated_at' => date('Y-m-d H:i:s')], 'finding_id = ?', [$findingId]);
        } else {
            Database::update('findings', [
                'status'     => 'in_remediation',
                'closed_at'  => null,
                'updated_at' => date('Y-m-d H:i:s'),
            ], 'id = ?', [$findingId]);
            Database::update('remediation', ['status' => 'in_progress', 'updated_at' => date('Y-m-d H:i:s')], 'finding_id = ?', [$findingId]);
        }

        Audit::log('retest.recorded', 'finding', $findingId, [
            'ref_code' => $finding['ref_code'], 'round' => $round, 'result' => $result,
        ], (int) $finding['assessment_id']);

        return Database::one(
            'SELECT r.*, u.full_name AS tester_name FROM retests r LEFT JOIN users u ON u.id = r.tester_id WHERE r.id = ?',
            [$retestId]
        ) ?? [];
    }

    /** @return array<int,array<string,mixed>> */
    public static function retestsFor(int $findingId): array
    {
        $rows = Database::all(
            'SELECT r.*, u.full_name AS tester_name, u.username AS tester_username
             FROM retests r LEFT JOIN users u ON u.id = r.tester_id
             WHERE r.finding_id = ? ORDER BY r.round_no ASC',
            [$findingId]
        );
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['round_no'] = (int) $row['round_no'];
            $row['closes_finding'] = (int) $row['closes_finding'] === 1;
        }
        return $rows;
    }

    private static function stepDown(string $severity): string
    {
        $rank = max(1, RiskEngine::rank($severity) - 1);
        return RiskEngine::SEVERITIES[$rank - 1] ?? 'low';
    }

    private static function effortFor(string $vulnClass): string
    {
        return match ($vulnClass) {
            'SQL Injection', 'Cross-Site Scripting', 'Open Redirect',
            'Security Misconfiguration', 'Information Disclosure'      => 'low',
            'Broken Access Control', 'Business Logic Flaw',
            'Cryptographic Failure'                                    => 'high',
            default                                                    => 'medium',
        };
    }
}
