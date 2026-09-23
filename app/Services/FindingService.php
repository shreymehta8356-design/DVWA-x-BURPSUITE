<?php

declare(strict_types=1);

namespace App\Services;

use App\AI\AiService;
use App\Core\Audit;
use App\Core\Auth;
use App\Core\Database;
use RuntimeException;

/**
 * Findings: creation, classification, risk evaluation and status lifecycle.
 *
 * Every severity written to a finding carries the rationale that produced it,
 * so the report can show the working rather than asserting a number.
 */
final class FindingService
{
    public const STATUSES = ['open', 'in_remediation', 'ready_for_retest', 'resolved', 'risk_accepted', 'false_positive', 'duplicate'];
    public const CONFIDENCE = ['confirmed', 'probable', 'tentative'];

    public const VULN_CLASSES = [
        'SQL Injection', 'Cross-Site Scripting', 'Command Injection', 'Path Traversal / File Inclusion',
        'Cross-Site Request Forgery', 'Insecure File Upload', 'Broken Authentication', 'Session Management',
        'Broken Access Control', 'Open Redirect', 'Security Misconfiguration', 'Information Disclosure',
        'Cryptographic Failure', 'Business Logic Flaw', 'Server-Side Request Forgery',
    ];

    /**
     * @param  array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function create(int $assessmentId, array $input): array
    {
        $title = trim((string) ($input['title'] ?? ''));
        if (mb_strlen($title) < 8) {
            throw new RuntimeException('Give the finding a descriptive title of at least 8 characters.');
        }
        $description = trim((string) ($input['description'] ?? ''));
        if (mb_strlen($description) < 20) {
            throw new RuntimeException('The description must explain what was found in at least 20 characters.');
        }

        $vulnClass = (string) ($input['vuln_class'] ?? '');
        $likelihood = max(1, min(5, (int) ($input['likelihood'] ?? 3)));
        $impact     = max(1, min(5, (int) ($input['impact'] ?? 3)));
        $vector     = trim((string) ($input['cvss_vector'] ?? ''));
        if ($vector === '' && $vulnClass !== '') {
            $vector = RiskEngine::suggestVector($vulnClass);
        }

        $risk = RiskEngine::evaluate($likelihood, $impact, $vector ?: null, self::overrideFrom($input));

        $testId = isset($input['test_id']) && $input['test_id'] ? (int) $input['test_id'] : null;
        if ($testId !== null) {
            $owner = (int) Database::scalar('SELECT assessment_id FROM assessment_tests WHERE id = ?', [$testId]);
            if ($owner !== $assessmentId) {
                throw new RuntimeException('That check does not belong to this assessment.');
            }
        }

        $id = Database::insert('findings', [
            'assessment_id'      => $assessmentId,
            'ref_code'           => self::nextRefCode($assessmentId),
            'test_id'            => $testId,
            'title'              => mb_substr($title, 0, 220),
            'vuln_class'         => $vulnClass !== '' ? mb_substr($vulnClass, 0, 80) : null,
            'cwe_id'             => mb_substr((string) ($input['cwe_id'] ?? ($vulnClass !== '' ? RiskEngine::cweFor($vulnClass) : '')), 0, 20) ?: null,
            'owasp_top10'        => mb_substr((string) ($input['owasp_top10'] ?? ($vulnClass !== '' ? RiskEngine::owaspFor($vulnClass) : '')), 0, 80) ?: null,
            'affected_component' => mb_substr((string) ($input['affected_component'] ?? ''), 0, 200) ?: null,
            'affected_url'       => mb_substr((string) ($input['affected_url'] ?? ''), 0, 255) ?: null,
            'description'        => mb_substr($description, 0, 20000),
            'impact_narrative'   => mb_substr((string) ($input['impact_narrative'] ?? ''), 0, 10000) ?: null,
            'reproduction_steps' => mb_substr((string) ($input['reproduction_steps'] ?? ''), 0, 20000) ?: null,
            'likelihood'         => $likelihood,
            'impact'             => $impact,
            'matrix_score'       => $risk['matrix']['score'],
            'matrix_band'        => $risk['matrix']['band'],
            'cvss_vector'        => $risk['cvss']['vector'] ?? null,
            'cvss_base_score'    => $risk['cvss']['base_score'] ?? null,
            'cvss_band'          => $risk['cvss']['band'] ?? null,
            'severity'           => $risk['severity'],
            'severity_source'    => $risk['source'],
            'severity_rationale' => $risk['rationale'],
            'confidence'         => in_array($input['confidence'] ?? '', self::CONFIDENCE, true) ? (string) $input['confidence'] : 'confirmed',
            'status'             => in_array($input['status'] ?? '', self::STATUSES, true) ? (string) $input['status'] : 'open',
            'ai_assisted_fields' => isset($input['ai_assisted_fields']) ? json_encode($input['ai_assisted_fields']) : null,
            'created_by'         => Auth::id(),
        ]);

        // Every finding gets a remediation record from the moment it exists, so
        // nothing can be reported without a plan and an owner.
        RemediationService::ensureFor($id, $vulnClass, $risk['severity']);

        // Analyst-confirmed classifications feed the offline classifier.
        if ($vulnClass !== '' && ($input['learn'] ?? true)) {
            (new AiService())->learnFromFinding($description, $vulnClass);
        }

        Audit::log('finding.created', 'finding', $id, [
            'title' => $title, 'severity' => $risk['severity'], 'source' => $risk['source'],
        ], $assessmentId);

        return self::find($id) ?? [];
    }

    /**
     * @param  array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function update(int $findingId, array $input): array
    {
        $existing = Database::one('SELECT * FROM findings WHERE id = ?', [$findingId]);
        if ($existing === null) {
            throw new RuntimeException('Finding not found.');
        }
        $assessmentId = (int) $existing['assessment_id'];

        $data = [];
        foreach (['title', 'vuln_class', 'cwe_id', 'owasp_top10', 'affected_component', 'affected_url',
                  'description', 'impact_narrative', 'reproduction_steps'] as $field) {
            if (array_key_exists($field, $input)) {
                $data[$field] = $input[$field] !== '' ? mb_substr((string) $input[$field], 0, 20000) : null;
            }
        }
        if (isset($input['confidence']) && in_array($input['confidence'], self::CONFIDENCE, true)) {
            $data['confidence'] = $input['confidence'];
        }

        // Risk is recomputed whenever any of its inputs move.
        $touchesRisk = array_intersect_key($input, array_flip(['likelihood', 'impact', 'cvss_vector', 'severity_override']));
        if ($touchesRisk !== []) {
            if (!Auth::can('finding.severity')) {
                throw new RuntimeException('Only a lead analyst or administrator can change the risk rating of a finding.');
            }
            $likelihood = max(1, min(5, (int) ($input['likelihood'] ?? $existing['likelihood'])));
            $impact     = max(1, min(5, (int) ($input['impact'] ?? $existing['impact'])));
            $vector     = array_key_exists('cvss_vector', $input)
                ? trim((string) $input['cvss_vector'])
                : (string) ($existing['cvss_vector'] ?? '');

            $risk = RiskEngine::evaluate($likelihood, $impact, $vector ?: null, self::overrideFrom($input));

            $data['likelihood']         = $likelihood;
            $data['impact']             = $impact;
            $data['matrix_score']       = $risk['matrix']['score'];
            $data['matrix_band']        = $risk['matrix']['band'];
            $data['cvss_vector']        = $risk['cvss']['vector'] ?? null;
            $data['cvss_base_score']    = $risk['cvss']['base_score'] ?? null;
            $data['cvss_band']          = $risk['cvss']['band'] ?? null;
            $data['severity']           = $risk['severity'];
            $data['severity_source']    = $risk['source'];
            $data['severity_rationale'] = $risk['rationale'];

            if ($risk['severity'] !== $existing['severity']) {
                RemediationService::realignSla($findingId, $risk['severity']);
            }
        }

        if ($data === []) {
            return self::find($findingId) ?? [];
        }
        $data['updated_at'] = date('Y-m-d H:i:s');
        Database::update('findings', $data, 'id = ?', [$findingId]);

        Audit::log('finding.updated', 'finding', $findingId, [
            'fields' => array_keys($data),
            'severity' => $data['severity'] ?? $existing['severity'],
        ], $assessmentId);

        return self::find($findingId) ?? [];
    }

    public static function changeStatus(int $findingId, string $status, string $note = ''): array
    {
        if (!in_array($status, self::STATUSES, true)) {
            throw new RuntimeException('Unknown finding status "' . $status . '".');
        }
        $existing = Database::one('SELECT assessment_id, status, severity FROM findings WHERE id = ?', [$findingId]);
        if ($existing === null) {
            throw new RuntimeException('Finding not found.');
        }

        // Resolution has to be earned by a retest, not asserted.
        if ($status === 'resolved') {
            $verified = (int) Database::scalar(
                "SELECT COUNT(*) FROM retests WHERE finding_id = ? AND result = 'fixed'",
                [$findingId]
            );
            if ($verified === 0) {
                throw new RuntimeException('A finding can only be marked resolved after a retest records a "fixed" result. Record the retest first.');
            }
        }
        if (in_array($status, ['risk_accepted', 'false_positive'], true) && trim($note) === '') {
            throw new RuntimeException('Recording "' . str_replace('_', ' ', $status) . '" requires a written justification.');
        }
        if (in_array($status, ['risk_accepted', 'false_positive'], true) && !Auth::can('finding.severity')) {
            throw new RuntimeException('Only a lead analyst or administrator can accept risk or mark a finding a false positive.');
        }

        $data = ['status' => $status, 'updated_at' => date('Y-m-d H:i:s')];
        if (in_array($status, ['resolved', 'risk_accepted', 'false_positive', 'duplicate'], true)) {
            $data['closed_at'] = date('Y-m-d H:i:s');
            $data['verified_by'] = Auth::id();
        } else {
            $data['closed_at'] = null;
        }
        if (trim($note) !== '') {
            $existingNote = (string) Database::scalar('SELECT severity_rationale FROM findings WHERE id = ?', [$findingId]);
            $data['severity_rationale'] = mb_substr(
                $existingNote . "\n\n[" . date('Y-m-d H:i') . ' | ' . Auth::username() . ' | status -> '
                . str_replace('_', ' ', $status) . '] ' . trim($note),
                0,
                20000
            );
        }

        Database::update('findings', $data, 'id = ?', [$findingId]);
        Audit::log('finding.status_changed', 'finding', $findingId, [
            'from' => $existing['status'], 'to' => $status, 'note' => $note,
        ], (int) $existing['assessment_id']);

        return self::find($findingId) ?? [];
    }

    public static function markDuplicate(int $findingId, int $duplicateOf, float $similarity): array
    {
        if ($findingId === $duplicateOf) {
            throw new RuntimeException('A finding cannot be a duplicate of itself.');
        }
        $primary = Database::one('SELECT assessment_id, ref_code FROM findings WHERE id = ?', [$duplicateOf]);
        $target  = Database::one('SELECT assessment_id FROM findings WHERE id = ?', [$findingId]);
        if ($primary === null || $target === null || $primary['assessment_id'] !== $target['assessment_id']) {
            throw new RuntimeException('Both findings must exist in the same assessment.');
        }

        Database::update('findings', [
            'status'           => 'duplicate',
            'duplicate_of'     => $duplicateOf,
            'similarity_score' => round($similarity, 4),
            'closed_at'        => date('Y-m-d H:i:s'),
            'updated_at'       => date('Y-m-d H:i:s'),
        ], 'id = ?', [$findingId]);

        Audit::log('finding.marked_duplicate', 'finding', $findingId, [
            'duplicate_of' => $primary['ref_code'], 'similarity' => $similarity,
        ], (int) $target['assessment_id']);

        return self::find($findingId) ?? [];
    }

    /** @return array<string,mixed>|null */
    public static function find(int $findingId): ?array
    {
        $row = Database::one(
            'SELECT f.*, t.id AS linked_test_id, c.code AS test_code, c.title AS test_title,
                    uc.full_name AS created_by_name, uv.full_name AS verified_by_name,
                    d.ref_code AS duplicate_of_ref
             FROM findings f
             LEFT JOIN assessment_tests t ON t.id = f.test_id
             LEFT JOIN test_catalog c ON c.id = t.catalog_id
             LEFT JOIN users uc ON uc.id = f.created_by
             LEFT JOIN users uv ON uv.id = f.verified_by
             LEFT JOIN findings d ON d.id = f.duplicate_of
             WHERE f.id = ?',
            [$findingId]
        );
        if ($row === null) {
            return null;
        }
        $row = self::present($row);
        $row['remediation'] = RemediationService::findFor($findingId);
        $row['retests']     = RemediationService::retestsFor($findingId);
        $row['evidence']    = EvidenceService::listFor((int) $row['assessment_id'], null, $findingId);
        $row['risk_detail'] = RiskEngine::evaluate(
            (int) $row['likelihood'],
            (int) $row['impact'],
            $row['cvss_vector'] ?: null,
            $row['severity_source'] === 'override' ? (string) $row['severity'] : null
        );
        return $row;
    }

    /**
     * @param  array<string,mixed> $filters
     * @return array<int,array<string,mixed>>
     */
    public static function listFor(int $assessmentId, array $filters = []): array
    {
        $sql = 'SELECT f.*, c.code AS test_code, uc.full_name AS created_by_name,
                       r.status AS remediation_status, r.due_date, r.owner_name,
                       (SELECT COUNT(*) FROM evidence e WHERE e.finding_id = f.id) AS evidence_count,
                       (SELECT COUNT(*) FROM retests rt WHERE rt.finding_id = f.id) AS retest_count
                FROM findings f
                LEFT JOIN assessment_tests t ON t.id = f.test_id
                LEFT JOIN test_catalog c ON c.id = t.catalog_id
                LEFT JOIN users uc ON uc.id = f.created_by
                LEFT JOIN remediation r ON r.finding_id = f.id
                WHERE f.assessment_id = ?';
        $params = [$assessmentId];

        if (!empty($filters['severity'])) {
            $sql .= ' AND f.severity = ?';
            $params[] = $filters['severity'];
        }
        if (!empty($filters['status'])) {
            $sql .= ' AND f.status = ?';
            $params[] = $filters['status'];
        }
        if (!empty($filters['vuln_class'])) {
            $sql .= ' AND f.vuln_class = ?';
            $params[] = $filters['vuln_class'];
        }
        if (!empty($filters['search'])) {
            $sql .= ' AND (f.title LIKE ? OR f.description LIKE ? OR f.ref_code LIKE ?)';
            $like = '%' . $filters['search'] . '%';
            array_push($params, $like, $like, $like);
        }
        // Severity descending, then reference code.
        $sql .= " ORDER BY CASE f.severity
                    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2 ELSE 1 END DESC, f.ref_code ASC";

        return array_map([self::class, 'present'], Database::all($sql, $params));
    }

    public static function delete(int $findingId): void
    {
        $row = Database::one('SELECT assessment_id, ref_code FROM findings WHERE id = ?', [$findingId]);
        if ($row === null) {
            return;
        }
        Audit::log('finding.deleted', 'finding', $findingId, ['ref_code' => $row['ref_code']], (int) $row['assessment_id']);
        Database::delete('findings', 'id = ?', [$findingId]);
    }

    public static function nextRefCode(int $assessmentId): string
    {
        $n = (int) Database::scalar('SELECT COUNT(*) FROM findings WHERE assessment_id = ?', [$assessmentId]);
        do {
            $n++;
            $code = sprintf('F-%03d', $n);
            $exists = (int) Database::scalar(
                'SELECT COUNT(*) FROM findings WHERE assessment_id = ? AND ref_code = ?',
                [$assessmentId, $code]
            );
        } while ($exists > 0 && $n < 10000);
        return $code;
    }

    /**
     * @param  array<string,mixed> $row
     * @return array<string,mixed>
     */
    public static function present(array $row): array
    {
        $row['id']              = (int) $row['id'];
        $row['assessment_id']   = (int) $row['assessment_id'];
        $row['likelihood']      = (int) $row['likelihood'];
        $row['impact']          = (int) $row['impact'];
        $row['matrix_score']    = $row['matrix_score'] !== null ? (int) $row['matrix_score'] : null;
        $row['cvss_base_score'] = $row['cvss_base_score'] !== null ? (float) $row['cvss_base_score'] : null;
        $row['evidence_count']  = isset($row['evidence_count']) ? (int) $row['evidence_count'] : 0;
        $row['retest_count']    = isset($row['retest_count']) ? (int) $row['retest_count'] : 0;
        $row['severity_colour'] = RiskEngine::colourFor((string) $row['severity']);
        $row['severity_rank']   = RiskEngine::rank((string) $row['severity']);
        $row['is_open']         = !in_array((string) $row['status'], ['resolved', 'risk_accepted', 'false_positive', 'duplicate'], true);
        if (!empty($row['due_date'])) {
            $row['is_overdue'] = $row['is_open'] && strtotime((string) $row['due_date']) < strtotime(date('Y-m-d'));
        }
        return $row;
    }

    /** @param array<string,mixed> $input */
    private static function overrideFrom(array $input): ?string
    {
        $override = trim((string) ($input['severity_override'] ?? ''));
        if ($override === '' || !in_array($override, RiskEngine::SEVERITIES, true)) {
            return null;
        }
        if (!Auth::can('finding.severity')) {
            throw new RuntimeException('Only a lead analyst or administrator can override a computed severity.');
        }
        return $override;
    }
}
