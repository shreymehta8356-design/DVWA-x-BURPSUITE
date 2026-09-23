<?php

declare(strict_types=1);

namespace App\Services;

use App\Core\Database;

/**
 * Aggregates for the platform dashboard. Everything here is computed in SQL
 * so the interface stays responsive as the assessment history grows.
 */
final class DashboardService
{
    /** @return array<string,mixed> */
    public static function overview(): array
    {
        $assessments = [];
        foreach (Database::all('SELECT status, COUNT(*) AS n FROM assessments GROUP BY status') as $row) {
            $assessments[(string) $row['status']] = (int) $row['n'];
        }

        $severity = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        foreach (Database::all(
            "SELECT severity, COUNT(*) AS n FROM findings
             WHERE status NOT IN ('false_positive','duplicate') GROUP BY severity"
        ) as $row) {
            $severity[(string) $row['severity']] = (int) $row['n'];
        }

        $findingStatus = [];
        foreach (Database::all('SELECT status, COUNT(*) AS n FROM findings GROUP BY status') as $row) {
            $findingStatus[(string) $row['status']] = (int) $row['n'];
        }

        $remediation = [];
        foreach (Database::all('SELECT status, COUNT(*) AS n FROM remediation GROUP BY status') as $row) {
            $remediation[(string) $row['status']] = (int) $row['n'];
        }

        $byClass = [];
        foreach (Database::all(
            "SELECT vuln_class, COUNT(*) AS n FROM findings
             WHERE vuln_class IS NOT NULL AND status NOT IN ('false_positive','duplicate')
             GROUP BY vuln_class ORDER BY n DESC"
        ) as $row) {
            $byClass[] = ['label' => (string) $row['vuln_class'], 'value' => (int) $row['n']];
        }

        $byOwasp = [];
        foreach (Database::all(
            "SELECT owasp_top10, COUNT(*) AS n FROM findings
             WHERE owasp_top10 IS NOT NULL AND status NOT IN ('false_positive','duplicate')
             GROUP BY owasp_top10 ORDER BY n DESC"
        ) as $row) {
            $byOwasp[] = ['label' => (string) $row['owasp_top10'], 'value' => (int) $row['n']];
        }

        $testOutcomes = [];
        foreach (Database::all('SELECT status, COUNT(*) AS n FROM assessment_tests GROUP BY status') as $row) {
            $testOutcomes[(string) $row['status']] = (int) $row['n'];
        }

        $overdue = (int) Database::scalar(
            "SELECT COUNT(*) FROM remediation r JOIN findings f ON f.id = r.finding_id
             WHERE r.due_date IS NOT NULL AND r.due_date < ?
               AND r.status NOT IN ('implemented','verified','accepted')
               AND f.status NOT IN ('resolved','risk_accepted','false_positive','duplicate')",
            [date('Y-m-d')]
        );

        $retest = [];
        foreach (Database::all('SELECT result, COUNT(*) AS n FROM retests GROUP BY result') as $row) {
            $retest[(string) $row['result']] = (int) $row['n'];
        }

        return [
            'assessments' => [
                'total'   => array_sum($assessments),
                'active'  => ($assessments['in_progress'] ?? 0) + ($assessments['testing_complete'] ?? 0)
                             + ($assessments['in_remediation'] ?? 0) + ($assessments['retest'] ?? 0),
                'draft'   => $assessments['draft'] ?? 0,
                'closed'  => $assessments['closed'] ?? 0,
                'by_status' => $assessments,
            ],
            'findings' => [
                'total'     => array_sum($severity),
                'severity'  => $severity,
                'by_status' => $findingStatus,
                'open'      => ($findingStatus['open'] ?? 0) + ($findingStatus['in_remediation'] ?? 0) + ($findingStatus['ready_for_retest'] ?? 0),
                'resolved'  => $findingStatus['resolved'] ?? 0,
                'by_class'  => $byClass,
                'by_owasp'  => $byOwasp,
            ],
            'tests' => [
                'total'    => array_sum($testOutcomes),
                'outcomes' => $testOutcomes,
                'executed' => array_sum($testOutcomes) - ($testOutcomes['pending'] ?? 0) - ($testOutcomes['in_progress'] ?? 0),
            ],
            'remediation' => [
                'by_status' => $remediation,
                'overdue'   => $overdue,
            ],
            'retests'  => $retest,
            'evidence' => [
                'total'    => (int) Database::scalar('SELECT COUNT(*) FROM evidence'),
                'redacted' => (int) Database::scalar('SELECT COUNT(*) FROM evidence WHERE is_redacted = 1'),
            ],
            'reports' => [
                'total' => (int) Database::scalar('SELECT COUNT(*) FROM reports'),
                'final' => (int) Database::scalar("SELECT COUNT(*) FROM reports WHERE status = 'final'"),
            ],
            'ai' => self::aiSummary(),
            'risk_score' => AssessmentService::riskScore($severity),
            'recent'     => self::recentActivity(12),
            'attention'  => self::needsAttention(),
        ];
    }

    /** @return array<string,mixed> */
    public static function aiSummary(): array
    {
        $byTask = [];
        foreach (Database::all(
            'SELECT task, engine, COUNT(*) AS n, AVG(confidence) AS avg_conf FROM ai_runs GROUP BY task, engine ORDER BY n DESC'
        ) as $row) {
            $byTask[] = [
                'task'       => (string) $row['task'],
                'engine'     => (string) $row['engine'],
                'runs'       => (int) $row['n'],
                'confidence' => $row['avg_conf'] !== null ? round((float) $row['avg_conf'], 3) : null,
            ];
        }
        return [
            'total_runs'     => (int) Database::scalar('SELECT COUNT(*) FROM ai_runs'),
            'accepted'       => (int) Database::scalar('SELECT COUNT(*) FROM ai_runs WHERE accepted = 1'),
            'rejected'       => (int) Database::scalar('SELECT COUNT(*) FROM ai_runs WHERE accepted = 0'),
            'training_rows'  => (int) Database::scalar('SELECT COUNT(*) FROM ai_training_data WHERE is_active = 1'),
            'by_task'        => $byTask,
        ];
    }

    /** @return array<int,array<string,mixed>> */
    public static function recentActivity(int $limit = 15): array
    {
        $limit = max(1, min(100, $limit));
        return Database::all(
            'SELECT a.id, a.action, a.entity_type, a.entity_id, a.actor_username, a.created_at,
                    s.ref_code AS assessment_ref
             FROM audit_log a
             LEFT JOIN assessments s ON s.id = a.assessment_id
             ORDER BY a.id DESC LIMIT ' . $limit
        );
    }

    /** Items a lead should look at first. @return array<string,array<int,array<string,mixed>>> */
    public static function needsAttention(): array
    {
        return [
            'overdue_remediation' => Database::all(
                "SELECT f.id AS finding_id, f.ref_code, f.title, f.severity, r.due_date, r.owner_name,
                        a.ref_code AS assessment_ref, a.id AS assessment_id
                 FROM remediation r
                 JOIN findings f ON f.id = r.finding_id
                 JOIN assessments a ON a.id = f.assessment_id
                 WHERE r.due_date < ? AND r.status NOT IN ('implemented','verified','accepted')
                   AND f.status NOT IN ('resolved','risk_accepted','false_positive','duplicate')
                 ORDER BY r.due_date ASC LIMIT 10",
                [date('Y-m-d')]
            ),
            'awaiting_retest' => Database::all(
                "SELECT f.id AS finding_id, f.ref_code, f.title, f.severity, a.ref_code AS assessment_ref, a.id AS assessment_id
                 FROM findings f JOIN assessments a ON a.id = f.assessment_id
                 WHERE f.status = 'ready_for_retest'
                 ORDER BY CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                          WHEN 'low' THEN 2 ELSE 1 END DESC LIMIT 10"
            ),
            'awaiting_review' => Database::all(
                "SELECT t.id AS test_id, c.code, c.title, t.status, a.ref_code AS assessment_ref, a.id AS assessment_id
                 FROM assessment_tests t
                 JOIN test_catalog c ON c.id = t.catalog_id
                 JOIN assessments a ON a.id = t.assessment_id
                 WHERE t.review_status = 'unreviewed' AND t.status IN ('fail','manual_review')
                 ORDER BY t.tested_at DESC LIMIT 10"
            ),
        ];
    }

    /**
     * Findings raised per day, for the trend sparkline.
     *
     * @return array<int,array{date:string,count:int}>
     */
    public static function findingTrend(int $days = 30): array
    {
        $days = max(7, min(180, $days));
        $since = date('Y-m-d', strtotime('-' . ($days - 1) . ' days'));

        $counts = [];
        foreach (Database::all(
            "SELECT SUBSTR(created_at, 1, 10) AS d, COUNT(*) AS n FROM findings
             WHERE created_at >= ? GROUP BY SUBSTR(created_at, 1, 10)",
            [$since . ' 00:00:00']
        ) as $row) {
            $counts[(string) $row['d']] = (int) $row['n'];
        }

        $series = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $date = date('Y-m-d', strtotime('-' . $i . ' days'));
            $series[] = ['date' => $date, 'count' => $counts[$date] ?? 0];
        }
        return $series;
    }
}
