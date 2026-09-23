<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Audit;
use App\Core\Auth;
use App\Core\Database;
use App\Core\Http;
use App\Services\AssessmentService;
use App\Services\DashboardService;
use RuntimeException;

final class AssessmentController
{
    public function index(): never
    {
        Auth::must('assessment.view');
        $status = Http::str('status', '', 30);
        Http::ok(AssessmentService::listAll($status !== '' ? $status : null, Http::str('search', '', 120)));
    }

    public function show(array $params): never
    {
        Auth::must('assessment.view');
        $assessment = AssessmentService::find((int) $params['id']);
        if ($assessment === null) {
            Http::fail('Assessment not found.', 404);
        }
        Http::ok($assessment);
    }

    public function store(): never
    {
        Auth::must('assessment.create');
        $body = Http::body();
        $assessment = AssessmentService::create($body);

        // Convenience: seed the plan with every active check unless asked not to.
        if (($body['seed_full_plan'] ?? true)) {
            AssessmentService::buildTestPlan((int) $assessment['id']);
            $assessment = AssessmentService::find((int) $assessment['id']);
        }
        Http::ok($assessment, ['message' => 'Assessment created.']);
    }

    public function update(array $params): never
    {
        Auth::must('assessment.edit');
        Http::ok(AssessmentService::update((int) $params['id'], Http::body()), ['message' => 'Assessment updated.']);
    }

    public function changeStatus(array $params): never
    {
        Auth::must('assessment.edit');
        $status = Http::str('status', '', 30);
        Http::ok(
            AssessmentService::changeStatus((int) $params['id'], $status),
            ['message' => 'Status set to ' . str_replace('_', ' ', $status) . '.']
        );
    }

    public function destroy(array $params): never
    {
        Auth::must('assessment.delete');
        $id = (int) $params['id'];
        $confirm = Http::str('confirm', '', 64);
        $refCode = (string) Database::scalar('SELECT ref_code FROM assessments WHERE id = ?', [$id]);
        if ($refCode === '') {
            Http::fail('Assessment not found.', 404);
        }
        // Deleting an assessment destroys its evidence chain, so require the
        // reference code to be typed back.
        if ($confirm !== $refCode) {
            Http::fail('Type the assessment reference (' . $refCode . ') to confirm deletion. This removes all of its findings, evidence and reports.', 422);
        }
        AssessmentService::delete($id);
        Http::ok(['deleted' => true], ['message' => $refCode . ' deleted.']);
    }

    public function addScope(array $params): never
    {
        Auth::must('assessment.edit');
        $assessmentId = (int) $params['id'];
        $value = Http::str('value', '', 255);
        if ($value === '') {
            Http::fail('A scope value is required.', 422);
        }
        $id = Database::insert('scope_items', [
            'assessment_id' => $assessmentId,
            'item_type'     => Http::enum('item_type', ['url', 'host', 'module', 'ip', 'credential_role'], 'url'),
            'value'         => $value,
            'in_scope'      => Http::bool('in_scope', true) ? 1 : 0,
            'notes'         => Http::str('notes', '', 255),
        ]);
        Audit::log('assessment.scope_added', 'assessment', $assessmentId, ['value' => $value], $assessmentId);
        Http::ok(['id' => $id] + (AssessmentService::find($assessmentId) ?? []));
    }

    public function removeScope(array $params): never
    {
        Auth::must('assessment.edit');
        $assessmentId = (int) $params['id'];
        Database::delete('scope_items', 'id = ? AND assessment_id = ?', [(int) $params['scopeId'], $assessmentId]);
        Audit::log('assessment.scope_removed', 'assessment', $assessmentId, ['scope_id' => (int) $params['scopeId']], $assessmentId);
        Http::ok(AssessmentService::find($assessmentId));
    }

    public function buildTestPlan(array $params): never
    {
        Auth::must('assessment.edit');
        $assessmentId = (int) $params['id'];
        if (AssessmentService::find($assessmentId) === null) {
            Http::fail('Assessment not found.', 404);
        }
        $ids = array_map('intval', Http::arr('catalog_ids'));
        $category = Http::str('category', '', 80);
        $result = AssessmentService::buildTestPlan($assessmentId, $ids, $category !== '' ? $category : null);

        Http::ok($result, [
            'message' => $result['added'] . ' check(s) added to the plan'
                . ($result['skipped'] > 0 ? ', ' . $result['skipped'] . ' already present.' : '.'),
        ]);
    }
}
