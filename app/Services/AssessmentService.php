<?php

declare(strict_types=1);

namespace App\Services;

use App\Core\Audit;
use App\Core\Auth;
use App\Core\Database;
use RuntimeException;

/**
 * Assessment lifecycle: creation, scope, test-plan construction and the
 * status machine that drives the workflow
 *
 *   Assessment -> Security Test -> Result -> Evidence -> Finding -> Risk
 *              -> Remediation -> Retest -> Report
 */
final class AssessmentService
{
    public const STATUSES = ['draft', 'in_progress', 'testing_complete', 'in_remediation', 'retest', 'closed'];
    public const ENVIRONMENTS = ['local_lab', 'development', 'staging', 'uat'];

    /** Permitted status transitions. Anything else is refused. */
    private const TRANSITIONS = [
        'draft'            => ['in_progress', 'closed'],
        'in_progress'      => ['testing_complete', 'draft', 'closed'],
        'testing_complete' => ['in_remediation', 'in_progress', 'closed'],
        'in_remediation'   => ['retest', 'testing_complete', 'closed'],
        'retest'           => ['closed', 'in_remediation'],
        'closed'           => ['in_remediation'],
    ];

    /**
     * @param  array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function create(array $input): array
    {
        $title = trim((string) ($input['title'] ?? ''));
        if ($title === '') {
            throw new RuntimeException('An assessment title is required.');
        }
        $targetUrl = trim((string) ($input['target_base_url'] ?? ''));
        if ($targetUrl === '' || !filter_var($targetUrl, FILTER_VALIDATE_URL)) {
            throw new RuntimeException('A valid target base URL is required, for example http://localhost/dvwa.');
        }
        self::assertLabTarget($targetUrl);

        $environment = in_array($input['environment'] ?? '', self::ENVIRONMENTS, true)
            ? (string) $input['environment'] : 'local_lab';

        $id = Database::insert('assessments', [
            'ref_code'            => self::nextRefCode(),
            'title'               => mb_substr($title, 0, 200),
            'target_name'         => mb_substr(trim((string) ($input['target_name'] ?? 'DVWA')), 0, 160),
            'target_base_url'     => mb_substr($targetUrl, 0, 255),
            'target_type'         => mb_substr((string) ($input['target_type'] ?? 'dvwa'), 0, 40),
            'environment'         => $environment,
            'methodology'         => mb_substr((string) ($input['methodology'] ?? 'OWASP WSTG v4.2'), 0, 120),
            'classification'      => mb_substr((string) ($input['classification'] ?? 'INTERNAL'), 0, 40),
            'objective'           => mb_substr((string) ($input['objective'] ?? ''), 0, 5000),
            'constraints'         => mb_substr((string) ($input['constraints'] ?? ''), 0, 5000),
            'rules_of_engagement' => mb_substr((string) ($input['rules_of_engagement'] ?? self::defaultRoe()), 0, 8000),
            'status'              => 'draft',
            'start_date'          => $input['start_date'] ?? null,
            'end_date'            => $input['end_date'] ?? null,
            'lead_analyst_id'     => isset($input['lead_analyst_id']) && $input['lead_analyst_id'] ? (int) $input['lead_analyst_id'] : Auth::id(),
            'created_by'          => Auth::id(),
        ]);

        // Scope items.
        foreach ((array) ($input['scope'] ?? []) as $item) {
            if (!is_array($item) || trim((string) ($item['value'] ?? '')) === '') {
                continue;
            }
            Database::insert('scope_items', [
                'assessment_id' => $id,
                'item_type'     => mb_substr((string) ($item['item_type'] ?? 'url'), 0, 30),
                'value'         => mb_substr(trim((string) $item['value']), 0, 255),
                'in_scope'      => !empty($item['in_scope']) ? 1 : 0,
                'notes'         => mb_substr((string) ($item['notes'] ?? ''), 0, 255),
            ]);
        }

        Audit::log('assessment.created', 'assessment', $id, ['title' => $title, 'target' => $targetUrl], $id);
        return self::find($id) ?? [];
    }

    /**
     * Refuses anything that is not obviously a local laboratory target. The
     * platform documents assessments of a controlled environment; pointing it
     * at a public host is out of scope by design.
     */
    public static function assertLabTarget(string $url): void
    {
        $host = strtolower((string) (parse_url($url, PHP_URL_HOST) ?: ''));
        if ($host === '') {
            throw new RuntimeException('Could not read a host from the target URL.');
        }
        $allowed = ['localhost', '127.0.0.1', '::1', 'dvwa', 'dvwa.local', 'host.docker.internal'];
        if (in_array($host, $allowed, true)) {
            return;
        }
        if (str_ends_with($host, '.local') || str_ends_with($host, '.localhost') || str_ends_with($host, '.test')) {
            return;
        }
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            // Private and loopback ranges only.
            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return;
            }
        }
        throw new RuntimeException(
            'Target "' . $host . '" is not a local laboratory address. This platform is for controlled offline '
            . 'environments only - use localhost, a private address, or a .local/.test hostname.'
        );
    }

    public static function nextRefCode(): string
    {
        $year = date('Y');
        $count = (int) Database::scalar(
            'SELECT COUNT(*) FROM assessments WHERE ref_code LIKE ?',
            ['ASMT-' . $year . '-%']
        );
        do {
            $count++;
            $code = sprintf('ASMT-%s-%03d', $year, $count);
            $exists = Database::scalar('SELECT COUNT(*) FROM assessments WHERE ref_code = ?', [$code]);
        } while ((int) $exists > 0 && $count < 10000);
        return $code;
    }

    /** @return array<string,mixed>|null */
    public static function find(int $id): ?array
    {
        $row = Database::one(
            'SELECT a.*, ul.username AS lead_username, ul.full_name AS lead_name,
                    uc.username AS creator_username
             FROM assessments a
             LEFT JOIN users ul ON ul.id = a.lead_analyst_id
             LEFT JOIN users uc ON uc.id = a.created_by
             WHERE a.id = ?',
            [$id]
        );
        if ($row === null) {
            return null;
        }
        $row['id'] = (int) $row['id'];
        $row['scope'] = Database::all(
            'SELECT id, item_type, value, in_scope, notes FROM scope_items WHERE assessment_id = ? ORDER BY in_scope DESC, id ASC',
            [$id]
        );
        $row['stats'] = self::stats($id);
        return $row;
    }

    /** @return array<int,array<string,mixed>> */
    public static function listAll(?string $status = null, string $search = ''): array
    {
        $sql = 'SELECT a.id, a.ref_code, a.title, a.target_name, a.target_base_url, a.environment,
                       a.status, a.start_date, a.end_date, a.created_at, u.full_name AS lead_name,
                       (SELECT COUNT(*) FROM assessment_tests t WHERE t.assessment_id = a.id) AS tests_total,
                       (SELECT COUNT(*) FROM assessment_tests t WHERE t.assessment_id = a.id AND t.status NOT IN (\'pending\',\'in_progress\')) AS tests_done,
                       (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id) AS findings_total,
                       (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity IN (\'critical\',\'high\') AND f.status NOT IN (\'resolved\',\'false_positive\',\'duplicate\')) AS findings_serious
                FROM assessments a
                LEFT JOIN users u ON u.id = a.lead_analyst_id
                WHERE 1 = 1';
        $params = [];
        if ($status !== null && in_array($status, self::STATUSES, true)) {
            $sql .= ' AND a.status = ?';
            $params[] = $status;
        }
        if (trim($search) !== '') {
            $sql .= ' AND (a.title LIKE ? OR a.ref_code LIKE ? OR a.target_name LIKE ?)';
            $like = '%' . trim($search) . '%';
            array_push($params, $like, $like, $like);
        }
        $sql .= ' ORDER BY a.created_at DESC, a.id DESC';

        $rows = Database::all($sql, $params);
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['tests_total'] = (int) $row['tests_total'];
            $row['tests_done'] = (int) $row['tests_done'];
            $row['findings_total'] = (int) $row['findings_total'];
            $row['findings_serious'] = (int) $row['findings_serious'];
            $row['progress'] = $row['tests_total'] > 0 ? (int) round($row['tests_done'] / $row['tests_total'] * 100) : 0;
        }
        return $rows;
    }

    /**
     * Adds predefined checks to the assessment test plan.
     *
     * @param  array<int,int> $catalogIds  empty means "every active check"
     * @return array{added:int,skipped:int}
     */
    public static function buildTestPlan(int $assessmentId, array $catalogIds = [], ?string $categoryFilter = null): array
    {
        if ($catalogIds === []) {
            $sql = 'SELECT id FROM test_catalog WHERE is_active = 1';
            $params = [];
            if ($categoryFilter !== null && $categoryFilter !== '') {
                $sql .= ' AND category = ?';
                $params[] = $categoryFilter;
            }
            $sql .= ' ORDER BY code ASC';
            $catalogIds = array_map(static fn ($r) => (int) $r['id'], Database::all($sql, $params));
        }

        $existing = [];
        foreach (Database::all('SELECT catalog_id FROM assessment_tests WHERE assessment_id = ?', [$assessmentId]) as $row) {
            $existing[(int) $row['catalog_id']] = true;
        }

        $sequence = (int) (Database::scalar('SELECT COALESCE(MAX(`sequence`), 0) FROM assessment_tests WHERE assessment_id = ?', [$assessmentId]) ?? 0);
        $added = 0;
        $skipped = 0;

        Database::begin();
        try {
            foreach ($catalogIds as $catalogId) {
                $catalogId = (int) $catalogId;
                if ($catalogId <= 0 || isset($existing[$catalogId])) {
                    $skipped++;
                    continue;
                }
                $sequence++;
                Database::insert('assessment_tests', [
                    'assessment_id' => $assessmentId,
                    'catalog_id'    => $catalogId,
                    'sequence'      => $sequence,
                    'status'        => 'pending',
                ]);
                $existing[$catalogId] = true;
                $added++;
            }
            Database::commit();
        } catch (\Throwable $e) {
            Database::rollback();
            throw $e;
        }

        Audit::log('assessment.test_plan_built', 'assessment', $assessmentId, ['added' => $added, 'skipped' => $skipped], $assessmentId);
        return ['added' => $added, 'skipped' => $skipped];
    }

    /** @param array<string,mixed> $input */
    public static function update(int $id, array $input): array
    {
        $allowed = ['title', 'target_name', 'target_base_url', 'environment', 'methodology', 'classification',
                    'objective', 'constraints', 'rules_of_engagement', 'start_date', 'end_date', 'lead_analyst_id'];
        $data = [];
        foreach ($allowed as $field) {
            if (array_key_exists($field, $input)) {
                $data[$field] = $input[$field];
            }
        }
        if (isset($data['target_base_url'])) {
            self::assertLabTarget((string) $data['target_base_url']);
        }
        if ($data !== []) {
            $data['updated_at'] = date('Y-m-d H:i:s');
            Database::update('assessments', $data, 'id = ?', [$id]);
            Audit::log('assessment.updated', 'assessment', $id, ['fields' => array_keys($data)], $id);
        }
        return self::find($id) ?? [];
    }

    public static function changeStatus(int $id, string $newStatus): array
    {
        $current = (string) Database::scalar('SELECT status FROM assessments WHERE id = ?', [$id]);
        if ($current === '') {
            throw new RuntimeException('Assessment not found.');
        }
        if (!in_array($newStatus, self::STATUSES, true)) {
            throw new RuntimeException('Unknown status "' . $newStatus . '".');
        }
        if ($current === $newStatus) {
            return self::find($id) ?? [];
        }
        if (!in_array($newStatus, self::TRANSITIONS[$current] ?? [], true)) {
            throw new RuntimeException(
                'Cannot move an assessment from "' . str_replace('_', ' ', $current) . '" to "'
                . str_replace('_', ' ', $newStatus) . '". Permitted next states: '
                . implode(', ', array_map(static fn ($s) => str_replace('_', ' ', $s), self::TRANSITIONS[$current] ?? []))
            );
        }

        // Guard rails that make the workflow meaningful.
        if ($newStatus === 'testing_complete') {
            $pending = (int) Database::scalar(
                "SELECT COUNT(*) FROM assessment_tests WHERE assessment_id = ? AND status IN ('pending','in_progress')",
                [$id]
            );
            if ($pending > 0) {
                throw new RuntimeException($pending . ' check(s) still have no recorded result. Record PASS, FAIL, MANUAL REVIEW or NOT APPLICABLE for every check first.');
            }
        }
        if ($newStatus === 'closed') {
            $open = (int) Database::scalar(
                "SELECT COUNT(*) FROM findings WHERE assessment_id = ?
                 AND severity IN ('critical','high') AND status NOT IN ('resolved','risk_accepted','false_positive','duplicate')",
                [$id]
            );
            if ($open > 0) {
                throw new RuntimeException($open . ' critical or high finding(s) are still open. Resolve, retest, or formally accept the risk before closing.');
            }
        }

        Database::update('assessments', ['status' => $newStatus, 'updated_at' => date('Y-m-d H:i:s')], 'id = ?', [$id]);
        Audit::log('assessment.status_changed', 'assessment', $id, ['from' => $current, 'to' => $newStatus], $id);
        return self::find($id) ?? [];
    }

    public static function delete(int $id): void
    {
        Audit::log('assessment.deleted', 'assessment', $id, null, $id);
        Database::delete('assessments', 'id = ?', [$id]);
    }

    /** @return array<string,mixed> */
    public static function stats(int $assessmentId): array
    {
        $testCounts = [];
        foreach (Database::all(
            'SELECT status, COUNT(*) AS n FROM assessment_tests WHERE assessment_id = ? GROUP BY status',
            [$assessmentId]
        ) as $row) {
            $testCounts[(string) $row['status']] = (int) $row['n'];
        }

        $severityCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        foreach (Database::all(
            "SELECT severity, COUNT(*) AS n FROM findings
             WHERE assessment_id = ? AND status NOT IN ('false_positive','duplicate') GROUP BY severity",
            [$assessmentId]
        ) as $row) {
            $severityCounts[(string) $row['severity']] = (int) $row['n'];
        }

        $statusCounts = [];
        foreach (Database::all(
            'SELECT status, COUNT(*) AS n FROM findings WHERE assessment_id = ? GROUP BY status',
            [$assessmentId]
        ) as $row) {
            $statusCounts[(string) $row['status']] = (int) $row['n'];
        }

        $total = array_sum($testCounts);
        $executed = $total - ($testCounts['pending'] ?? 0) - ($testCounts['in_progress'] ?? 0);

        $remediation = [];
        foreach (Database::all(
            'SELECT r.status, COUNT(*) AS n FROM remediation r
             JOIN findings f ON f.id = r.finding_id WHERE f.assessment_id = ? GROUP BY r.status',
            [$assessmentId]
        ) as $row) {
            $remediation[(string) $row['status']] = (int) $row['n'];
        }

        $overdue = (int) Database::scalar(
            "SELECT COUNT(*) FROM remediation r JOIN findings f ON f.id = r.finding_id
             WHERE f.assessment_id = ? AND r.due_date IS NOT NULL AND r.due_date < ?
               AND r.status NOT IN ('implemented','verified','accepted')",
            [$assessmentId, date('Y-m-d')]
        );

        return [
            'tests_total'    => $total,
            'tests_executed' => $executed,
            'tests_pending'  => ($testCounts['pending'] ?? 0) + ($testCounts['in_progress'] ?? 0),
            'tests_pass'     => $testCounts['pass'] ?? 0,
            'tests_fail'     => $testCounts['fail'] ?? 0,
            'tests_manual'   => $testCounts['manual_review'] ?? 0,
            'tests_na'       => $testCounts['not_applicable'] ?? 0,
            'progress'       => $total > 0 ? (int) round($executed / $total * 100) : 0,
            'critical'       => $severityCounts['critical'],
            'high'           => $severityCounts['high'],
            'medium'         => $severityCounts['medium'],
            'low'            => $severityCounts['low'],
            'info'           => $severityCounts['info'],
            'findings_total' => array_sum($severityCounts),
            'findings_open'  => ($statusCounts['open'] ?? 0) + ($statusCounts['in_remediation'] ?? 0) + ($statusCounts['ready_for_retest'] ?? 0),
            'resolved'       => $statusCounts['resolved'] ?? 0,
            'risk_accepted'  => $statusCounts['risk_accepted'] ?? 0,
            'false_positive' => $statusCounts['false_positive'] ?? 0,
            'evidence_count' => (int) Database::scalar('SELECT COUNT(*) FROM evidence WHERE assessment_id = ?', [$assessmentId]),
            'retest_count'   => (int) Database::scalar(
                'SELECT COUNT(*) FROM retests r JOIN findings f ON f.id = r.finding_id WHERE f.assessment_id = ?',
                [$assessmentId]
            ),
            'remediation'    => $remediation,
            'overdue'        => $overdue,
            'risk_score'     => self::riskScore($severityCounts),
        ];
    }

    /**
     * A single 0-100 posture number for the dashboard. Weighted by severity so
     * one critical outweighs a pile of informational observations. The weights
     * are printed in the report so the number is never a black box.
     *
     * @param array<string,int> $severityCounts
     */
    public static function riskScore(array $severityCounts): int
    {
        $weights = ['critical' => 40, 'high' => 20, 'medium' => 8, 'low' => 3, 'info' => 1];
        $penalty = 0;
        foreach ($weights as $severity => $weight) {
            $penalty += ($severityCounts[$severity] ?? 0) * $weight;
        }
        return max(0, 100 - min(100, $penalty));
    }

    private static function defaultRoe(): string
    {
        return "1. Testing is performed only against the target named in this assessment, hosted on the local machine.\n"
            . "2. No testing is performed against any Internet-facing system.\n"
            . "3. Destructive techniques, denial of service and data destruction are out of scope.\n"
            . "4. All traffic is captured through the local proxy and retained as evidence.\n"
            . "5. Any credential or personal data encountered is redacted before it is stored as evidence.\n"
            . "6. Findings are recorded in this platform only; no third-party service receives assessment data.";
    }
}
