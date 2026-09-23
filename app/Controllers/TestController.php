<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Audit;
use App\Core\Auth;
use App\Core\Database;
use App\Core\Http;
use App\Services\TestService;

final class TestController
{
    // -----------------------------------------------------------------------
    // Catalogue of predefined checks
    // -----------------------------------------------------------------------

    public function catalog(): never
    {
        Auth::must('assessment.view');
        $sql = 'SELECT * FROM test_catalog WHERE 1 = 1';
        $params = [];
        if (!Http::bool('include_archived', false)) {
            $sql .= ' AND is_active = 1';
        }
        $category = Http::str('category', '', 80);
        if ($category !== '') {
            $sql .= ' AND category = ?';
            $params[] = $category;
        }
        $search = Http::str('search', '', 120);
        if ($search !== '') {
            $sql .= ' AND (code LIKE ? OR title LIKE ? OR description LIKE ? OR dvwa_module LIKE ?)';
            $like = '%' . $search . '%';
            array_push($params, $like, $like, $like, $like);
        }
        $sql .= ' ORDER BY category ASC, code ASC';

        $rows = Database::all($sql, $params);
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['is_active'] = (int) $row['is_active'] === 1;
            $row['default_likelihood'] = (int) $row['default_likelihood'];
            $row['default_impact'] = (int) $row['default_impact'];
        }
        Http::ok(['items' => $rows, 'categories' => TestService::categories()]);
    }

    public function storeCatalog(): never
    {
        Auth::must('catalog.edit');
        $code = strtoupper(Http::str('code', '', 32));
        $title = Http::str('title', '', 200);
        if ($code === '' || $title === '') {
            Http::fail('A code and a title are required.', 422);
        }
        if ((int) Database::scalar('SELECT COUNT(*) FROM test_catalog WHERE code = ?', [$code]) > 0) {
            Http::fail('A check with the code ' . $code . ' already exists.', 422);
        }

        $id = Database::insert('test_catalog', [
            'code'                      => $code,
            'title'                     => $title,
            'category'                  => Http::str('category', 'Custom', 80),
            'owasp_top10'               => Http::str('owasp_top10', '', 80) ?: null,
            'cwe_id'                    => Http::str('cwe_id', '', 20) ?: null,
            'description'               => Http::str('description', '', 5000) ?: null,
            'test_objective'            => Http::str('test_objective', '', 5000) ?: null,
            'test_steps'                => Http::str('test_steps', '', 8000) ?: null,
            'tools_hint'                => Http::str('tools_hint', '', 255) ?: null,
            'expected_secure_behaviour' => Http::str('expected_secure_behaviour', '', 4000) ?: null,
            'default_likelihood'        => max(1, min(5, Http::int('default_likelihood', 3))),
            'default_impact'            => max(1, min(5, Http::int('default_impact', 3))),
            'default_cvss_vector'       => Http::str('default_cvss_vector', '', 120) ?: null,
            'dvwa_module'               => Http::str('dvwa_module', '', 60) ?: null,
            'is_active'                 => 1,
        ]);

        Audit::log('catalog.created', 'catalog', $id, ['code' => $code]);
        Http::ok(Database::one('SELECT * FROM test_catalog WHERE id = ?', [$id]), ['message' => 'Check ' . $code . ' added to the catalogue.']);
    }

    public function updateCatalog(array $params): never
    {
        Auth::must('catalog.edit');
        $id = (int) $params['id'];
        $body = Http::body();
        $data = [];
        foreach (['title' => 200, 'category' => 80, 'owasp_top10' => 80, 'cwe_id' => 20, 'description' => 5000,
                  'test_objective' => 5000, 'test_steps' => 8000, 'tools_hint' => 255,
                  'expected_secure_behaviour' => 4000, 'default_cvss_vector' => 120, 'dvwa_module' => 60] as $field => $limit) {
            if (array_key_exists($field, $body)) {
                $value = trim((string) $body[$field]);
                $data[$field] = $value !== '' ? mb_substr($value, 0, $limit) : null;
            }
        }
        foreach (['default_likelihood', 'default_impact'] as $field) {
            if (array_key_exists($field, $body)) {
                $data[$field] = max(1, min(5, (int) $body[$field]));
            }
        }
        if (array_key_exists('is_active', $body)) {
            $data['is_active'] = !empty($body['is_active']) ? 1 : 0;
        }
        if ($data === []) {
            Http::fail('Nothing to update.', 422);
        }
        Database::update('test_catalog', $data, 'id = ?', [$id]);
        Audit::log('catalog.updated', 'catalog', $id, ['fields' => array_keys($data)]);
        Http::ok(Database::one('SELECT * FROM test_catalog WHERE id = ?', [$id]), ['message' => 'Check updated.']);
    }

    public function archiveCatalog(array $params): never
    {
        Auth::must('catalog.edit');
        $id = (int) $params['id'];
        // Never hard-delete: existing assessments reference these rows.
        Database::update('test_catalog', ['is_active' => 0], 'id = ?', [$id]);
        Audit::log('catalog.archived', 'catalog', $id);
        Http::ok(['archived' => true], ['message' => 'Check archived. Existing assessments keep their history.']);
    }

    // -----------------------------------------------------------------------
    // Execution
    // -----------------------------------------------------------------------

    public function index(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(TestService::listFor((int) $params['id'], [
            'status'   => Http::str('status', '', 24),
            'category' => Http::str('category', '', 80),
            'search'   => Http::str('search', '', 120),
        ]));
    }

    public function coverage(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(TestService::coverage((int) $params['id']));
    }

    public function show(array $params): never
    {
        Auth::must('assessment.view');
        $test = TestService::find((int) $params['testId']);
        if ($test === null) {
            Http::fail('Check not found.', 404);
        }
        Http::ok($test);
    }

    public function recordResult(array $params): never
    {
        Auth::must('test.execute');
        Http::ok(
            TestService::recordResult((int) $params['testId'], Http::body()),
            ['message' => 'Result recorded.']
        );
    }

    public function review(array $params): never
    {
        Auth::must('test.review');
        Http::ok(
            TestService::review(
                (int) $params['testId'],
                Http::enum('review_status', ['approved', 'rework'], 'approved'),
                Http::str('note', '', 500)
            ),
            ['message' => 'Peer review recorded.']
        );
    }

    public function destroy(array $params): never
    {
        Auth::must('assessment.edit');
        TestService::remove((int) $params['testId']);
        Http::ok(['removed' => true], ['message' => 'Check removed from the plan.']);
    }
}
