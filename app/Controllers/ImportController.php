<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Auth;
use App\Core\Config;
use App\Core\Database;
use App\Core\Http;
use App\Services\BurpImporter;

final class ImportController
{
    public function uploadBurp(array $params): never
    {
        Auth::must('import.burp');
        $assessmentId = (int) $params['id'];

        if (empty($_FILES['file']) || ($_FILES['file']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            Http::fail('Attach the Burp Suite XML export as the "file" field.', 422);
        }
        $tmp = (string) $_FILES['file']['tmp_name'];
        if (!is_uploaded_file($tmp)) {
            Http::fail('Upload rejected.', 422);
        }

        $maxBytes = max(1, Config::settingInt('evidence_max_mb', 16)) * 4 * 1024 * 1024;
        if ((int) $_FILES['file']['size'] > $maxBytes) {
            Http::fail('The export exceeds the configured upload limit.', 422);
        }

        $xml = (string) file_get_contents($tmp);
        $result = BurpImporter::import($assessmentId, $xml, (string) ($_FILES['file']['name'] ?? 'burp-export.xml'));

        Http::ok($result, [
            'message' => $result['issue_count'] . ' issue(s) staged for review. Nothing was promoted to a finding yet.',
        ]);
    }

    public function index(array $params): never
    {
        Auth::must('assessment.view');
        $rows = Database::all(
            'SELECT i.*, u.full_name AS imported_by_name,
                    (SELECT COUNT(*) FROM burp_issues b WHERE b.import_id = i.id AND b.action = ?) AS promoted
             FROM burp_imports i LEFT JOIN users u ON u.id = i.imported_by
             WHERE i.assessment_id = ? ORDER BY i.created_at DESC',
            ['imported', (int) $params['id']]
        );
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['issue_count'] = (int) $row['issue_count'];
            $row['promoted'] = (int) $row['promoted'];
            $row['file_sha256_short'] = substr((string) $row['file_sha256'], 0, 16);
        }
        Http::ok($rows);
    }

    public function issues(array $params): never
    {
        Auth::must('assessment.view');
        $sql = 'SELECT b.id, b.name, b.host, b.path, b.location, b.burp_severity, b.burp_confidence,
                       b.ai_category, b.ai_confidence, b.action, b.mapped_finding_id, b.mapped_catalog_id,
                       c.code AS catalog_code,
                       CASE WHEN b.request_text IS NULL OR b.request_text = ? THEN 0 ELSE 1 END AS has_request,
                       CASE WHEN b.response_text IS NULL OR b.response_text = ? THEN 0 ELSE 1 END AS has_response,
                       f.ref_code AS finding_ref
                FROM burp_issues b
                LEFT JOIN test_catalog c ON c.id = b.mapped_catalog_id
                LEFT JOIN findings f ON f.id = b.mapped_finding_id
                WHERE b.import_id = ?';
        $params2 = ['', '', (int) $params['importId']];

        $action = Http::str('action', '', 20);
        if ($action !== '') {
            $sql .= ' AND b.action = ?';
            $params2[] = $action;
        }
        $sql .= ' ORDER BY CASE LOWER(b.burp_severity)
                             WHEN \'high\' THEN 4 WHEN \'medium\' THEN 3 WHEN \'low\' THEN 2 ELSE 1 END DESC, b.id ASC';

        $rows = Database::all($sql, $params2);
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['ai_confidence'] = $row['ai_confidence'] !== null ? (float) $row['ai_confidence'] : null;
            $row['has_request'] = (int) $row['has_request'] === 1;
            $row['has_response'] = (int) $row['has_response'] === 1;
        }
        Http::ok($rows);
    }

    public function issue(array $params): never
    {
        Auth::must('assessment.view');
        $row = Database::one('SELECT * FROM burp_issues WHERE id = ?', [(int) $params['issueId']]);
        if ($row === null) {
            Http::fail('Burp issue not found.', 404);
        }
        $row['id'] = (int) $row['id'];
        // Bound the traffic returned to the browser.
        foreach (['request_text', 'response_text'] as $field) {
            if (!empty($row[$field])) {
                $row[$field] = mb_substr((string) $row[$field], 0, 60000);
            }
        }
        Http::ok($row);
    }

    public function promote(array $params): never
    {
        Auth::must('finding.create');
        $ids = array_map('intval', Http::arr('issue_ids'));
        if ($ids === []) {
            Http::fail('Select at least one issue to promote.', 422);
        }
        $result = BurpImporter::promote((int) $params['id'], $ids);
        Http::ok($result, [
            'message' => $result['created'] . ' finding(s) created from the selected Burp issues'
                . ($result['skipped'] > 0 ? ', ' . $result['skipped'] . ' skipped.' : '.'),
        ]);
    }
}
