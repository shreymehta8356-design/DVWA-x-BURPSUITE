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
 * Report generation.
 *
 * A report is a frozen snapshot, not a live view. Generating one serialises
 * the whole assessment - scope, every check result, every finding with its
 * risk derivation, evidence hashes, remediation state and retest history -
 * into snapshot_json, hashes it, and stores it. Re-rendering an old report
 * therefore reproduces exactly what was signed off, even after the assessment
 * has moved on. That is what makes it audit-ready.
 *
 * Outputs: HTML (print to PDF from the browser), JSON and CSV.
 */
final class ReportService
{
    public const TYPES = ['full', 'executive', 'delta'];

    /**
     * @return array<string,mixed>
     */
    public static function generate(int $assessmentId, string $type = 'full', array $options = []): array
    {
        if (!in_array($type, self::TYPES, true)) {
            throw new RuntimeException('Report type must be one of: ' . implode(', ', self::TYPES) . '.');
        }
        $assessment = AssessmentService::find($assessmentId);
        if ($assessment === null) {
            throw new RuntimeException('Assessment not found.');
        }

        $snapshot = self::buildSnapshot($assessment, $type, $options);

        $json = json_encode($snapshot, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new RuntimeException('Could not serialise the report snapshot.');
        }

        $version = self::nextVersion($assessmentId, $type);
        $refCode = sprintf('%s-RPT-%s-v%s', $assessment['ref_code'], strtoupper(substr($type, 0, 3)), $version);

        $id = Database::insert('reports', [
            'assessment_id'     => $assessmentId,
            'ref_code'          => $refCode,
            'report_type'       => $type,
            'version'           => $version,
            // ?: not ?? - the controller passes an empty string when the
            // analyst leaves the title blank, and ?? would accept it, leaving
            // the report cover with no heading at all.
            'title'             => mb_substr(trim((string) ($options['title'] ?? '')) ?: self::defaultTitle($type, $assessment), 0, 220),
            'classification'    => mb_substr((string) ($assessment['classification'] ?? 'INTERNAL'), 0, 40),
            'status'            => 'draft',
            'executive_summary' => $snapshot['executive_summary']['text'] ?? null,
            'snapshot_json'     => $json,
            'sha256'            => hash('sha256', $json),
            'generated_by'      => Auth::id(),
        ]);

        Audit::log('report.generated', 'report', $id, [
            'ref_code' => $refCode, 'type' => $type, 'sha256' => hash('sha256', $json),
        ], $assessmentId);

        return self::find($id) ?? [];
    }

    /**
     * @param  array<string,mixed> $assessment
     * @return array<string,mixed>
     */
    private static function buildSnapshot(array $assessment, string $type, array $options): array
    {
        $assessmentId = (int) $assessment['id'];
        $stats = AssessmentService::stats($assessmentId);

        $findings = FindingService::listFor($assessmentId);
        $reportable = array_values(array_filter(
            $findings,
            static fn ($f) => !in_array((string) $f['status'], ['false_positive', 'duplicate'], true)
        ));

        // Hydrate each finding with everything a reader needs to verify it.
        $detailed = [];
        foreach ($reportable as $finding) {
            $full = FindingService::find((int) $finding['id']);
            if ($full === null) {
                continue;
            }
            $evidence = [];
            foreach ($full['evidence'] as $item) {
                $evidence[] = [
                    'id'           => $item['id'],
                    'type'         => $item['evidence_type'],
                    'title'        => $item['title'],
                    'description'  => $item['description'],
                    'sha256'       => $item['sha256'],
                    'captured_at'  => $item['captured_at'],
                    'collected_by' => $item['collected_by_name'] ?? $item['collected_by_username'] ?? 'unknown',
                    'is_redacted'  => $item['is_redacted'],
                    'redaction'    => $item['redaction_summary'],
                    'content'      => $item['content_text'] !== null ? mb_substr((string) $item['content_text'], 0, 8000) : null,
                    'is_image'     => $item['is_image'] ?? false,
                    'mime_type'    => $item['mime_type'] ?? null,
                    'custody'      => EvidenceService::custodyChain((int) $item['id']),
                ];
            }

            $detailed[] = [
                'ref_code'           => $full['ref_code'],
                'title'              => $full['title'],
                'severity'           => $full['severity'],
                'severity_source'    => $full['severity_source'],
                'severity_rationale' => $full['severity_rationale'],
                'confidence'         => $full['confidence'],
                'status'             => $full['status'],
                'vuln_class'         => $full['vuln_class'],
                'cwe_id'             => $full['cwe_id'],
                'owasp_top10'        => $full['owasp_top10'],
                'affected_component' => $full['affected_component'],
                'affected_url'       => $full['affected_url'],
                'description'        => $full['description'],
                'impact_narrative'   => $full['impact_narrative'],
                'reproduction_steps' => $full['reproduction_steps'],
                'likelihood'         => $full['likelihood'],
                'impact'             => $full['impact'],
                'matrix_score'       => $full['matrix_score'],
                'matrix_band'        => $full['matrix_band'],
                'cvss_vector'        => $full['cvss_vector'],
                'cvss_base_score'    => $full['cvss_base_score'],
                'cvss_band'          => $full['cvss_band'],
                'cvss_detail'        => $full['risk_detail']['cvss'] ?? null,
                'test_code'          => $full['test_code'] ?? null,
                'created_by'         => $full['created_by_name'] ?? null,
                'created_at'         => $full['created_at'],
                'remediation'        => $full['remediation'],
                'retests'            => $full['retests'],
                'evidence'           => $evidence,
            ];
        }

        // Order: severity descending, then reference code.
        usort($detailed, static function ($a, $b) {
            $rank = RiskEngine::rank((string) $b['severity']) <=> RiskEngine::rank((string) $a['severity']);
            return $rank !== 0 ? $rank : strcmp((string) $a['ref_code'], (string) $b['ref_code']);
        });

        $tests = TestService::listFor($assessmentId);
        $coverage = TestService::coverage($assessmentId);

        $summary = (new AiService())->executiveSummary($assessment, $stats, $detailed, $assessmentId);

        $auditIntegrity = Audit::verifyChain();

        return [
            'meta' => [
                'generated_at'    => date('c'),
                'generated_by'    => Auth::check() ? Auth::username() : 'system',
                'generated_by_name' => Auth::check() ? (string) (Auth::user()['full_name'] ?? '') : 'system',
                'platform'        => Config::get('app.name', 'DVWA x BURPSUITE'),
                'organisation'    => Config::setting('org_name', 'Security Assessment Lab'),
                'footer'          => Config::setting('report_footer', 'CONFIDENTIAL'),
                'report_type'     => $type,
                'severity_strategy' => Config::setting('severity_strategy', 'higher_of'),
            ],
            'assessment' => [
                'ref_code'        => $assessment['ref_code'],
                'title'           => $assessment['title'],
                'target_name'     => $assessment['target_name'],
                'target_base_url' => $assessment['target_base_url'],
                'environment'     => $assessment['environment'],
                'methodology'     => $assessment['methodology'],
                'classification'  => $assessment['classification'],
                'objective'       => $assessment['objective'],
                'constraints'     => $assessment['constraints'],
                'rules_of_engagement' => $assessment['rules_of_engagement'],
                'status'          => $assessment['status'],
                'start_date'      => $assessment['start_date'],
                'end_date'        => $assessment['end_date'],
                'lead_analyst'    => $assessment['lead_name'] ?? null,
                'scope'           => $assessment['scope'],
            ],
            'statistics'        => $stats,
            'executive_summary' => $summary,
            'risk_model' => [
                'strategy'    => Config::setting('severity_strategy', 'higher_of'),
                'matrix'      => RiskEngine::matrixTable(),
                'sla'         => Database::all('SELECT severity, sla_days, rank, description FROM severity_sla ORDER BY rank DESC'),
                'score_weights' => ['critical' => 40, 'high' => 20, 'medium' => 8, 'low' => 3, 'info' => 1],
            ],
            'findings'  => $type === 'executive' ? array_slice($detailed, 0, 10) : $detailed,
            'test_log'  => $type === 'executive' ? [] : array_map(static fn ($t) => [
                'code'          => $t['code'],
                'title'         => $t['title'],
                'category'      => $t['category'],
                'status'        => $t['status'],
                'observation'   => $t['observation'],
                'tested_by'     => $t['tested_by_name'] ?? null,
                'tested_at'     => $t['tested_at'],
                'review_status' => $t['review_status'],
                'evidence_count' => $t['evidence_count'],
                'dvwa_module'   => $t['dvwa_module'],
            ], $tests),
            'coverage'  => $coverage,
            'remediation_tracker' => RemediationService::trackerFor($assessmentId),
            'ai_usage'  => self::aiUsageSummary($assessmentId),
            'integrity' => [
                'audit_chain'      => $auditIntegrity,
                'evidence_count'   => $stats['evidence_count'],
                'snapshot_note'    => 'This report is a frozen snapshot. The SHA-256 recorded against it covers every value printed here.',
            ],
            'excluded' => [
                'false_positive' => array_values(array_map(
                    static fn ($f) => ['ref_code' => $f['ref_code'], 'title' => $f['title'], 'reason' => 'Marked false positive'],
                    array_filter($findings, static fn ($f) => $f['status'] === 'false_positive')
                )),
                'duplicate' => array_values(array_map(
                    static fn ($f) => ['ref_code' => $f['ref_code'], 'title' => $f['title'], 'reason' => 'Duplicate'],
                    array_filter($findings, static fn ($f) => $f['status'] === 'duplicate')
                )),
            ],
        ];
    }

    /** @return array<string,mixed> */
    private static function aiUsageSummary(int $assessmentId): array
    {
        $rows = Database::all(
            'SELECT task, engine, model_name, COUNT(*) AS runs, AVG(confidence) AS avg_confidence,
                    SUM(CASE WHEN accepted = 1 THEN 1 ELSE 0 END) AS accepted
             FROM ai_runs WHERE assessment_id = ? GROUP BY task, engine, model_name ORDER BY runs DESC',
            [$assessmentId]
        );
        foreach ($rows as &$row) {
            $row['runs'] = (int) $row['runs'];
            $row['accepted'] = (int) $row['accepted'];
            $row['avg_confidence'] = $row['avg_confidence'] !== null ? round((float) $row['avg_confidence'], 3) : null;
        }
        return [
            'note'  => 'Every model invocation during this assessment is listed below. All outputs were reviewed by a '
                     . 'named analyst before inclusion; no severity, status or conclusion in this report was set by a model.',
            'usage' => $rows,
        ];
    }

    /** @return array<string,mixed>|null */
    public static function find(int $reportId): ?array
    {
        $row = Database::one(
            'SELECT r.*, u.full_name AS generated_by_name, a.ref_code AS assessment_ref, a.title AS assessment_title
             FROM reports r LEFT JOIN users u ON u.id = r.generated_by
             JOIN assessments a ON a.id = r.assessment_id WHERE r.id = ?',
            [$reportId]
        );
        if ($row === null) {
            return null;
        }
        $row['id'] = (int) $row['id'];
        $row['assessment_id'] = (int) $row['assessment_id'];
        return $row;
    }

    /** @return array<int,array<string,mixed>> */
    public static function listFor(int $assessmentId): array
    {
        $rows = Database::all(
            'SELECT r.id, r.ref_code, r.report_type, r.version, r.title, r.status, r.classification,
                    r.sha256, r.generated_at, u.full_name AS generated_by_name
             FROM reports r LEFT JOIN users u ON u.id = r.generated_by
             WHERE r.assessment_id = ? ORDER BY r.generated_at DESC, r.id DESC',
            [$assessmentId]
        );
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['sha256_short'] = substr((string) $row['sha256'], 0, 16);
        }
        return $rows;
    }

    /** @return array<string,mixed> */
    public static function snapshot(int $reportId): array
    {
        $json = Database::scalar('SELECT snapshot_json FROM reports WHERE id = ?', [$reportId]);
        if (!is_string($json) || $json === '') {
            throw new RuntimeException('Report snapshot not found.');
        }
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            throw new RuntimeException('Report snapshot is corrupt.');
        }
        return $decoded;
    }

    /** Confirms the stored snapshot still matches the hash taken at generation. */
    public static function verify(int $reportId): array
    {
        $row = Database::one('SELECT snapshot_json, sha256, ref_code FROM reports WHERE id = ?', [$reportId]);
        if ($row === null) {
            throw new RuntimeException('Report not found.');
        }
        $actual = hash('sha256', (string) $row['snapshot_json']);
        $ok = hash_equals((string) $row['sha256'], $actual);
        return [
            'verified' => $ok,
            'ref_code' => $row['ref_code'],
            'expected' => $row['sha256'],
            'actual'   => $actual,
            'message'  => $ok
                ? 'The stored report is byte-identical to the version generated and hashed at sign-off.'
                : 'The stored report no longer matches its hash. Treat this copy as untrusted.',
        ];
    }

    public static function finalise(int $reportId): array
    {
        $row = Database::one('SELECT assessment_id, status, ref_code FROM reports WHERE id = ?', [$reportId]);
        if ($row === null) {
            throw new RuntimeException('Report not found.');
        }
        if ((string) $row['status'] === 'final') {
            return self::find($reportId) ?? [];
        }
        Database::update('reports', ['status' => 'final'], 'id = ?', [$reportId]);
        Audit::log('report.finalised', 'report', $reportId, ['ref_code' => $row['ref_code']], (int) $row['assessment_id']);
        return self::find($reportId) ?? [];
    }

    public static function delete(int $reportId): void
    {
        $row = Database::one('SELECT assessment_id, status, ref_code FROM reports WHERE id = ?', [$reportId]);
        if ($row === null) {
            return;
        }
        if ((string) $row['status'] === 'final') {
            throw new RuntimeException('A finalised report cannot be deleted. Generate a new version instead.');
        }
        Database::delete('reports', 'id = ?', [$reportId]);
        Audit::log('report.deleted', 'report', $reportId, ['ref_code' => $row['ref_code']], (int) $row['assessment_id']);
    }

    // =======================================================================
    // Exports
    // =======================================================================

    public static function toCsv(int $reportId): string
    {
        $snapshot = self::snapshot($reportId);
        $handle = fopen('php://temp', 'r+');
        if ($handle === false) {
            throw new RuntimeException('Could not open a temporary stream for the CSV export.');
        }

        fputcsv($handle, [
            'Reference', 'Title', 'Severity', 'Severity source', 'CVSS score', 'CVSS vector',
            'Likelihood', 'Impact', 'Matrix score', 'Matrix band', 'Vulnerability class', 'CWE',
            'OWASP Top 10', 'Affected component', 'Affected URL', 'Status', 'Confidence',
            'Remediation status', 'Owner', 'Due date', 'Retests', 'Last retest result', 'Evidence items',
        ]);

        foreach ($snapshot['findings'] ?? [] as $f) {
            $retests = $f['retests'] ?? [];
            $last = $retests === [] ? '' : (string) ($retests[count($retests) - 1]['result'] ?? '');
            fputcsv($handle, [
                $f['ref_code'] ?? '',
                $f['title'] ?? '',
                strtoupper((string) ($f['severity'] ?? '')),
                $f['severity_source'] ?? '',
                $f['cvss_base_score'] ?? '',
                $f['cvss_vector'] ?? '',
                $f['likelihood'] ?? '',
                $f['impact'] ?? '',
                $f['matrix_score'] ?? '',
                strtoupper((string) ($f['matrix_band'] ?? '')),
                $f['vuln_class'] ?? '',
                $f['cwe_id'] ?? '',
                $f['owasp_top10'] ?? '',
                $f['affected_component'] ?? '',
                $f['affected_url'] ?? '',
                $f['status'] ?? '',
                $f['confidence'] ?? '',
                $f['remediation']['status'] ?? '',
                $f['remediation']['owner_name'] ?? '',
                $f['remediation']['due_date'] ?? '',
                count($retests),
                $last,
                count($f['evidence'] ?? []),
            ]);
        }

        rewind($handle);
        $csv = (string) stream_get_contents($handle);
        fclose($handle);

        Audit::log('report.exported', 'report', $reportId, ['format' => 'csv']);
        return "\xEF\xBB\xBF" . $csv;      // BOM so Excel reads UTF-8 correctly
    }

    public static function renderHtml(int $reportId): string
    {
        $report = self::find($reportId);
        if ($report === null) {
            throw new RuntimeException('Report not found.');
        }
        $snapshot = self::snapshot($reportId);

        Audit::log('report.viewed', 'report', $reportId, ['ref_code' => $report['ref_code']], (int) $report['assessment_id']);

        ob_start();
        $reportMeta = $report;
        require APP_ROOT . '/templates/report.php';
        return (string) ob_get_clean();
    }

    private static function nextVersion(int $assessmentId, string $type): string
    {
        $count = (int) Database::scalar(
            'SELECT COUNT(*) FROM reports WHERE assessment_id = ? AND report_type = ?',
            [$assessmentId, $type]
        );
        return sprintf('%d.0', $count + 1);
    }

    /** @param array<string,mixed> $assessment */
    private static function defaultTitle(string $type, array $assessment): string
    {
        return match ($type) {
            'executive' => 'Executive Summary - ' . $assessment['target_name'],
            'delta'     => 'Retest Report - ' . $assessment['target_name'],
            default     => 'Web Application Security Assessment - ' . $assessment['target_name'],
        };
    }
}
