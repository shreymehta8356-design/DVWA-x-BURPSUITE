<?php

declare(strict_types=1);

namespace App\Services;

use App\AI\AiService;
use App\Core\Audit;
use App\Core\Auth;
use App\Core\Config;
use App\Core\Database;
use RuntimeException;

/**
 * Execution of predefined security checks and recording of results.
 *
 * A result is one of PASS, FAIL, MANUAL REVIEW or NOT APPLICABLE, always with
 * an observation. FAIL and MANUAL REVIEW additionally require an observation
 * of substance, because those are the results that become findings and end up
 * in front of a reader who was not in the room.
 */
final class TestService
{
    public const RESULTS = ['pending', 'in_progress', 'pass', 'fail', 'manual_review', 'not_applicable'];
    public const REVIEW_STATES = ['unreviewed', 'approved', 'rework'];

    /** @return array<int,array<string,mixed>> */
    public static function listFor(int $assessmentId, array $filters = []): array
    {
        $sql = 'SELECT t.id, t.assessment_id, t.catalog_id, t.sequence, t.status, t.observation,
                       t.payload_used, t.dvwa_security_level, t.tested_at, t.review_status, t.review_note,
                       t.ai_category, t.ai_confidence,
                       c.code, c.title, c.category, c.owasp_top10, c.cwe_id, c.description,
                       c.test_objective, c.test_steps, c.tools_hint, c.expected_secure_behaviour,
                       c.default_likelihood, c.default_impact, c.default_cvss_vector, c.dvwa_module,
                       ut.username AS tested_by_username, ut.full_name AS tested_by_name,
                       ur.username AS reviewed_by_username,
                       (SELECT COUNT(*) FROM evidence e WHERE e.test_id = t.id) AS evidence_count,
                       (SELECT COUNT(*) FROM findings f WHERE f.test_id = t.id) AS finding_count
                FROM assessment_tests t
                JOIN test_catalog c ON c.id = t.catalog_id
                LEFT JOIN users ut ON ut.id = t.tested_by
                LEFT JOIN users ur ON ur.id = t.reviewed_by
                WHERE t.assessment_id = ?';
        $params = [$assessmentId];

        if (!empty($filters['status']) && in_array($filters['status'], self::RESULTS, true)) {
            $sql .= ' AND t.status = ?';
            $params[] = $filters['status'];
        }
        if (!empty($filters['category'])) {
            $sql .= ' AND c.category = ?';
            $params[] = $filters['category'];
        }
        if (!empty($filters['search'])) {
            $sql .= ' AND (c.title LIKE ? OR c.code LIKE ? OR t.observation LIKE ?)';
            $like = '%' . $filters['search'] . '%';
            array_push($params, $like, $like, $like);
        }
        $sql .= ' ORDER BY c.code ASC';

        $rows = Database::all($sql, $params);
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['catalog_id'] = (int) $row['catalog_id'];
            $row['evidence_count'] = (int) $row['evidence_count'];
            $row['finding_count'] = (int) $row['finding_count'];
            $row['ai_confidence'] = $row['ai_confidence'] !== null ? (float) $row['ai_confidence'] : null;
        }
        return $rows;
    }

    /** @return array<string,mixed>|null */
    public static function find(int $testId): ?array
    {
        $row = Database::one(
            'SELECT t.*, c.code, c.title, c.category, c.owasp_top10, c.cwe_id, c.description,
                    c.test_objective, c.test_steps, c.tools_hint, c.expected_secure_behaviour,
                    c.default_likelihood, c.default_impact, c.default_cvss_vector, c.dvwa_module,
                    ut.full_name AS tested_by_name, ur.full_name AS reviewed_by_name
             FROM assessment_tests t
             JOIN test_catalog c ON c.id = t.catalog_id
             LEFT JOIN users ut ON ut.id = t.tested_by
             LEFT JOIN users ur ON ur.id = t.reviewed_by
             WHERE t.id = ?',
            [$testId]
        );
        if ($row === null) {
            return null;
        }
        $row['id'] = (int) $row['id'];
        $row['assessment_id'] = (int) $row['assessment_id'];
        $row['evidence'] = EvidenceService::listFor((int) $row['assessment_id'], (int) $row['id']);
        return $row;
    }

    /**
     * Records the outcome of a check.
     *
     * @param  array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function recordResult(int $testId, array $input): array
    {
        $test = Database::one('SELECT t.*, c.code, c.title FROM assessment_tests t JOIN test_catalog c ON c.id = t.catalog_id WHERE t.id = ?', [$testId]);
        if ($test === null) {
            throw new RuntimeException('Check not found in this assessment.');
        }

        $status = (string) ($input['status'] ?? '');
        if (!in_array($status, self::RESULTS, true)) {
            throw new RuntimeException('Result must be one of: ' . implode(', ', self::RESULTS) . '.');
        }

        $observation = trim((string) ($input['observation'] ?? ''));
        if (in_array($status, ['fail', 'manual_review'], true) && mb_strlen($observation) < 20) {
            throw new RuntimeException('A FAIL or MANUAL REVIEW result needs an observation of at least 20 characters describing what was seen.');
        }
        if ($status === 'not_applicable' && $observation === '') {
            throw new RuntimeException('Record why this check does not apply to the target.');
        }

        $assessmentId = (int) $test['assessment_id'];

        // Offline triage runs automatically on a failing result so the analyst
        // sees a suggested class the moment they save.
        $aiCategory = null;
        $aiConfidence = null;
        $aiEngine = null;
        if ($status === 'fail' && $observation !== '' && Config::settingBool('ai_enabled', true)) {
            $prediction = (new AiService())->classifier()->predict($observation, 1);
            if ($prediction['label'] !== null && $prediction['confidence'] >= Config::settingFloat('ai_triage_min_confidence', 0.35)) {
                $aiCategory = $prediction['label'];
                $aiConfidence = (float) $prediction['confidence'];
                $aiEngine = 'naive_bayes';
            }
        }

        Database::update('assessment_tests', [
            'status'              => $status,
            'observation'         => mb_substr($observation, 0, 20000),
            'request_snippet'     => mb_substr((string) ($input['request_snippet'] ?? ''), 0, 20000) ?: null,
            'response_snippet'    => mb_substr((string) ($input['response_snippet'] ?? ''), 0, 20000) ?: null,
            'payload_used'        => mb_substr((string) ($input['payload_used'] ?? ''), 0, 2000) ?: null,
            'dvwa_security_level' => mb_substr((string) ($input['dvwa_security_level'] ?? ''), 0, 16) ?: null,
            'tested_by'           => Auth::id(),
            'tested_at'           => date('Y-m-d H:i:s'),
            'review_status'       => 'unreviewed',
            'reviewed_by'         => null,
            'reviewed_at'         => null,
            'ai_category'         => $aiCategory,
            'ai_confidence'       => $aiConfidence,
            'ai_engine'           => $aiEngine,
            'updated_at'          => date('Y-m-d H:i:s'),
        ], 'id = ?', [$testId]);

        // Captured traffic becomes first-class evidence, hashed and redacted.
        foreach ([['request_snippet', 'http_request', 'Request'], ['response_snippet', 'http_response', 'Response']] as [$field, $type, $label]) {
            $content = trim((string) ($input[$field] ?? ''));
            if ($content === '') {
                continue;
            }
            EvidenceService::captureText($assessmentId, [
                'evidence_type' => $type,
                'title'         => $label . ' - ' . $test['code'],
                'description'   => 'Captured while executing ' . $test['code'] . ' (' . $test['title'] . ').',
                'content_text'  => $content,
                'test_id'       => $testId,
            ]);
        }

        // Move the assessment out of draft on first recorded result.
        if ((string) Database::scalar('SELECT status FROM assessments WHERE id = ?', [$assessmentId]) === 'draft') {
            Database::update('assessments', ['status' => 'in_progress'], 'id = ?', [$assessmentId]);
        }

        Audit::log('test.result_recorded', 'test', $testId, [
            'code' => $test['code'], 'status' => $status, 'ai_category' => $aiCategory,
        ], $assessmentId);

        return self::find($testId) ?? [];
    }

    /** Peer review sign-off on a recorded result. */
    public static function review(int $testId, string $reviewStatus, string $note = ''): array
    {
        if (!in_array($reviewStatus, self::REVIEW_STATES, true)) {
            throw new RuntimeException('Review status must be one of: ' . implode(', ', self::REVIEW_STATES) . '.');
        }
        $test = Database::one('SELECT assessment_id, status, tested_by FROM assessment_tests WHERE id = ?', [$testId]);
        if ($test === null) {
            throw new RuntimeException('Check not found.');
        }
        if (in_array((string) $test['status'], ['pending', 'in_progress'], true)) {
            throw new RuntimeException('This check has no recorded result to review yet.');
        }
        if ((int) $test['tested_by'] === Auth::id() && Auth::role() !== 'admin') {
            throw new RuntimeException('Separation of duties: you cannot peer review a result you recorded yourself.');
        }
        if ($reviewStatus === 'rework' && trim($note) === '') {
            throw new RuntimeException('Explain what needs reworking.');
        }

        Database::update('assessment_tests', [
            'review_status' => $reviewStatus,
            'reviewed_by'   => Auth::id(),
            'reviewed_at'   => date('Y-m-d H:i:s'),
            'review_note'   => mb_substr($note, 0, 500) ?: null,
        ], 'id = ?', [$testId]);

        Audit::log('test.reviewed', 'test', $testId, ['review' => $reviewStatus], (int) $test['assessment_id']);
        return self::find($testId) ?? [];
    }

    public static function remove(int $testId): void
    {
        $test = Database::one('SELECT assessment_id, catalog_id, status FROM assessment_tests WHERE id = ?', [$testId]);
        if ($test === null) {
            return;
        }
        if (!in_array((string) $test['status'], ['pending', 'in_progress'], true)) {
            throw new RuntimeException('A check with a recorded result cannot be removed from the plan. Mark it NOT APPLICABLE instead so the decision stays on record.');
        }
        Database::delete('assessment_tests', 'id = ?', [$testId]);
        Audit::log('test.removed_from_plan', 'test', $testId, null, (int) $test['assessment_id']);
    }

    /** @return array<int,string> */
    public static function categories(): array
    {
        return array_map(
            static fn ($r) => (string) $r['category'],
            Database::all('SELECT DISTINCT category FROM test_catalog WHERE is_active = 1 ORDER BY category')
        );
    }

    /** Coverage by category, for the workspace progress panel. @return array<int,array<string,mixed>> */
    public static function coverage(int $assessmentId): array
    {
        $rows = Database::all(
            "SELECT c.category,
                    COUNT(*) AS total,
                    SUM(CASE WHEN t.status = 'pass' THEN 1 ELSE 0 END) AS pass,
                    SUM(CASE WHEN t.status = 'fail' THEN 1 ELSE 0 END) AS fail,
                    SUM(CASE WHEN t.status = 'manual_review' THEN 1 ELSE 0 END) AS manual_review,
                    SUM(CASE WHEN t.status = 'not_applicable' THEN 1 ELSE 0 END) AS not_applicable,
                    SUM(CASE WHEN t.status IN ('pending','in_progress') THEN 1 ELSE 0 END) AS pending
             FROM assessment_tests t JOIN test_catalog c ON c.id = t.catalog_id
             WHERE t.assessment_id = ? GROUP BY c.category ORDER BY c.category",
            [$assessmentId]
        );
        foreach ($rows as &$row) {
            foreach (['total', 'pass', 'fail', 'manual_review', 'not_applicable', 'pending'] as $key) {
                $row[$key] = (int) $row[$key];
            }
            $row['progress'] = $row['total'] > 0 ? (int) round(($row['total'] - $row['pending']) / $row['total'] * 100) : 0;
        }
        return $rows;
    }
}
