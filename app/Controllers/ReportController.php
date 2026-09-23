<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Audit;
use App\Core\Auth;
use App\Core\Http;
use App\Services\ReportService;

final class ReportController
{
    public function index(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(ReportService::listFor((int) $params['id']));
    }

    public function generate(array $params): never
    {
        Auth::must('report.generate');
        $report = ReportService::generate(
            (int) $params['id'],
            Http::enum('report_type', ReportService::TYPES, 'full'),
            ['title' => Http::str('title', '', 220)]
        );
        Http::ok($report, ['message' => 'Report ' . ($report['ref_code'] ?? '') . ' generated and hashed.']);
    }

    public function show(array $params): never
    {
        Auth::must('assessment.view');
        $report = ReportService::find((int) $params['reportId']);
        if ($report === null) {
            Http::fail('Report not found.', 404);
        }
        unset($report['snapshot_json']);      // the payload is large; fetch it explicitly
        Http::ok($report);
    }

    /** Full HTML report - opened in a new tab and printed to PDF from there. */
    public function html(array $params): never
    {
        Auth::must('assessment.view');
        $html = ReportService::renderHtml((int) $params['reportId']);
        header('Content-Type: text/html; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: private, no-store');
        echo $html;
        exit;
    }

    public function json(array $params): never
    {
        Auth::must('assessment.view');
        $reportId = (int) $params['reportId'];
        $report = ReportService::find($reportId);
        if ($report === null) {
            Http::fail('Report not found.', 404);
        }
        $snapshot = ReportService::snapshot($reportId);
        Audit::log('report.exported', 'report', $reportId, ['format' => 'json'], (int) $report['assessment_id']);

        $filename = preg_replace('/[^A-Za-z0-9._-]/', '_', (string) $report['ref_code']) . '.json';
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('X-Content-Type-Options: nosniff');
        echo json_encode([
            'report'   => array_diff_key($report, ['snapshot_json' => null]),
            'snapshot' => $snapshot,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    public function csv(array $params): never
    {
        Auth::must('assessment.view');
        $reportId = (int) $params['reportId'];
        $report = ReportService::find($reportId);
        if ($report === null) {
            Http::fail('Report not found.', 404);
        }
        $csv = ReportService::toCsv($reportId);
        $filename = preg_replace('/[^A-Za-z0-9._-]/', '_', (string) $report['ref_code']) . '-findings.csv';

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('X-Content-Type-Options: nosniff');
        echo $csv;
        exit;
    }

    public function verify(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(ReportService::verify((int) $params['reportId']));
    }

    public function finalise(array $params): never
    {
        Auth::must('report.finalise');
        Http::ok(
            ReportService::finalise((int) $params['reportId']),
            ['message' => 'Report finalised. It can no longer be deleted; generate a new version for changes.']
        );
    }

    public function destroy(array $params): never
    {
        Auth::must('report.finalise');
        ReportService::delete((int) $params['reportId']);
        Http::ok(['deleted' => true], ['message' => 'Draft report deleted.']);
    }
}
