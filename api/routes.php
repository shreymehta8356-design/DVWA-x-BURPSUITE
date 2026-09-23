<?php
/**
 * API route table.
 *
 * Options per route:
 *   'auth'  => false   endpoint is reachable without a session (login only)
 *   'csrf'  => false   skip the CSRF guard (login only - no session to forge yet)
 *   'roles' => [...]   coarse role gate; capability checks live in controllers
 *
 * @var \App\Core\Router $router
 */

declare(strict_types=1);

use App\Controllers\AdminController;
use App\Controllers\AiController;
use App\Controllers\AssessmentController;
use App\Controllers\AuthController;
use App\Controllers\DashboardController;
use App\Controllers\EvidenceController;
use App\Controllers\FindingController;
use App\Controllers\ImportController;
use App\Controllers\RemediationController;
use App\Controllers\ReportController;
use App\Controllers\TestController;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
$router->post('/auth/login',    [AuthController::class, 'login'],  ['auth' => false, 'csrf' => false]);
$router->get('/auth/me',        [AuthController::class, 'me'],     ['auth' => false]);
$router->post('/auth/logout',   [AuthController::class, 'logout']);
$router->post('/auth/password', [AuthController::class, 'changePassword']);

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
$router->get('/dashboard',       [DashboardController::class, 'overview']);
$router->get('/dashboard/trend', [DashboardController::class, 'trend']);

// ---------------------------------------------------------------------------
// Assessments and scope
// ---------------------------------------------------------------------------
$router->get('/assessments',                    [AssessmentController::class, 'index']);
$router->post('/assessments',                   [AssessmentController::class, 'store']);
$router->get('/assessments/{id}',               [AssessmentController::class, 'show']);
$router->put('/assessments/{id}',               [AssessmentController::class, 'update']);
$router->post('/assessments/{id}/status',       [AssessmentController::class, 'changeStatus']);
$router->delete('/assessments/{id}',            [AssessmentController::class, 'destroy']);
$router->post('/assessments/{id}/scope',        [AssessmentController::class, 'addScope']);
$router->delete('/assessments/{id}/scope/{scopeId}', [AssessmentController::class, 'removeScope']);
$router->post('/assessments/{id}/test-plan',    [AssessmentController::class, 'buildTestPlan']);

// ---------------------------------------------------------------------------
// Security check catalogue and execution
// ---------------------------------------------------------------------------
$router->get('/catalog',                   [TestController::class, 'catalog']);
$router->post('/catalog',                  [TestController::class, 'storeCatalog']);
$router->put('/catalog/{id}',              [TestController::class, 'updateCatalog']);
$router->delete('/catalog/{id}',           [TestController::class, 'archiveCatalog']);

$router->get('/assessments/{id}/tests',    [TestController::class, 'index']);
$router->get('/assessments/{id}/coverage', [TestController::class, 'coverage']);
$router->get('/tests/{testId}',            [TestController::class, 'show']);
$router->post('/tests/{testId}/result',    [TestController::class, 'recordResult']);
$router->post('/tests/{testId}/review',    [TestController::class, 'review']);
$router->delete('/tests/{testId}',         [TestController::class, 'destroy']);

// ---------------------------------------------------------------------------
// Findings and risk
// ---------------------------------------------------------------------------
$router->get('/assessments/{id}/findings', [FindingController::class, 'index']);
$router->post('/assessments/{id}/findings',[FindingController::class, 'store']);
$router->get('/findings/{findingId}',      [FindingController::class, 'show']);
$router->put('/findings/{findingId}',      [FindingController::class, 'update']);
$router->post('/findings/{findingId}/status',    [FindingController::class, 'changeStatus']);
$router->post('/findings/{findingId}/duplicate', [FindingController::class, 'markDuplicate']);
$router->delete('/findings/{findingId}',   [FindingController::class, 'destroy']);
$router->post('/risk/evaluate',            [FindingController::class, 'evaluateRisk']);
$router->get('/risk/matrix',               [FindingController::class, 'matrix']);

// ---------------------------------------------------------------------------
// Remediation and retest
// ---------------------------------------------------------------------------
$router->get('/assessments/{id}/remediation', [RemediationController::class, 'tracker']);
$router->get('/findings/{findingId}/remediation',  [RemediationController::class, 'show']);
$router->put('/findings/{findingId}/remediation',  [RemediationController::class, 'update']);
$router->get('/findings/{findingId}/retests',      [RemediationController::class, 'retests']);
$router->post('/findings/{findingId}/retests',     [RemediationController::class, 'recordRetest']);

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------
$router->get('/assessments/{id}/evidence',  [EvidenceController::class, 'index']);
$router->post('/assessments/{id}/evidence', [EvidenceController::class, 'storeText']);
$router->post('/assessments/{id}/evidence/upload', [EvidenceController::class, 'upload']);
$router->get('/evidence/{evidenceId}',      [EvidenceController::class, 'show']);
$router->get('/evidence/{evidenceId}/file', [EvidenceController::class, 'download']);
$router->get('/evidence/{evidenceId}/verify', [EvidenceController::class, 'verify']);
$router->post('/evidence/{evidenceId}/attach', [EvidenceController::class, 'attach']);
$router->delete('/evidence/{evidenceId}',   [EvidenceController::class, 'destroy']);

// ---------------------------------------------------------------------------
// Burp Suite import
// ---------------------------------------------------------------------------
$router->post('/assessments/{id}/import/burp', [ImportController::class, 'uploadBurp']);
$router->get('/assessments/{id}/import',       [ImportController::class, 'index']);
$router->get('/imports/{importId}/issues',     [ImportController::class, 'issues']);
$router->get('/burp-issues/{issueId}',         [ImportController::class, 'issue']);
$router->post('/assessments/{id}/import/promote', [ImportController::class, 'promote']);

// ---------------------------------------------------------------------------
// AI assistance (offline models, optional local LLM)
// ---------------------------------------------------------------------------
$router->post('/ai/triage',        [AiController::class, 'triage']);
$router->post('/ai/duplicates',    [AiController::class, 'duplicates']);
$router->post('/ai/narrative',     [AiController::class, 'narrative']);
$router->post('/ai/remediation',   [AiController::class, 'remediation']);
$router->post('/ai/summary',       [AiController::class, 'summary']);
$router->post('/ai/redact-preview',[AiController::class, 'redactPreview']);
$router->post('/ai/feedback',      [AiController::class, 'feedback']);
$router->get('/ai/status',         [AiController::class, 'status']);

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
$router->get('/assessments/{id}/reports',  [ReportController::class, 'index']);
$router->post('/assessments/{id}/reports', [ReportController::class, 'generate']);
$router->get('/reports/{reportId}',        [ReportController::class, 'show']);
$router->get('/reports/{reportId}/html',   [ReportController::class, 'html']);
$router->get('/reports/{reportId}/json',   [ReportController::class, 'json']);
$router->get('/reports/{reportId}/csv',    [ReportController::class, 'csv']);
$router->get('/reports/{reportId}/verify', [ReportController::class, 'verify']);
$router->post('/reports/{reportId}/finalise', [ReportController::class, 'finalise']);
$router->delete('/reports/{reportId}',     [ReportController::class, 'destroy']);

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------
$router->get('/admin/users',            [AdminController::class, 'users'],        ['roles' => ['admin']]);
$router->post('/admin/users',           [AdminController::class, 'createUser'],   ['roles' => ['admin']]);
$router->put('/admin/users/{userId}',   [AdminController::class, 'updateUser'],   ['roles' => ['admin']]);
$router->delete('/admin/users/{userId}',[AdminController::class, 'disableUser'],  ['roles' => ['admin']]);

$router->get('/admin/settings',         [AdminController::class, 'settings'],     ['roles' => ['admin']]);
$router->put('/admin/settings',         [AdminController::class, 'updateSettings'], ['roles' => ['admin']]);
$router->put('/admin/risk-matrix',      [AdminController::class, 'updateMatrix'], ['roles' => ['admin']]);

$router->get('/admin/audit',            [AdminController::class, 'audit'],        ['roles' => ['lead', 'admin']]);
$router->get('/admin/audit/verify',     [AdminController::class, 'verifyAudit'],  ['roles' => ['lead', 'admin']]);

$router->get('/admin/ai/model',         [AdminController::class, 'aiModel'],      ['roles' => ['lead', 'admin']]);
$router->post('/admin/ai/retrain',      [AdminController::class, 'retrainModel'], ['roles' => ['admin']]);
$router->post('/admin/ai/evaluate',     [AdminController::class, 'evaluateModel'],['roles' => ['admin']]);
$router->get('/admin/ai/training',      [AdminController::class, 'trainingData'], ['roles' => ['admin']]);
$router->post('/admin/ai/training',     [AdminController::class, 'addTraining'],  ['roles' => ['admin']]);
$router->delete('/admin/ai/training/{rowId}', [AdminController::class, 'removeTraining'], ['roles' => ['admin']]);
$router->post('/admin/ai/llm-test',     [AdminController::class, 'testLlm'],      ['roles' => ['admin']]);

// ---------------------------------------------------------------------------
// Reference data used to populate select controls
// ---------------------------------------------------------------------------
$router->get('/meta', static function (): never {
    \App\Core\Http::ok([
        'severities'    => \App\Services\RiskEngine::SEVERITIES,
        'vuln_classes'  => \App\Services\FindingService::VULN_CLASSES,
        'finding_status'=> \App\Services\FindingService::STATUSES,
        'confidence'    => \App\Services\FindingService::CONFIDENCE,
        'test_results'  => \App\Services\TestService::RESULTS,
        'categories'    => \App\Services\TestService::categories(),
        'remediation_status' => \App\Services\RemediationService::STATUSES,
        'retest_results'=> \App\Services\RemediationService::RESULTS,
        'effort'        => \App\Services\RemediationService::EFFORT,
        'assessment_status' => \App\Services\AssessmentService::STATUSES,
        'environments'  => \App\Services\AssessmentService::ENVIRONMENTS,
        'evidence_types'=> \App\Services\EvidenceService::TYPES,
        'report_types'  => \App\Services\ReportService::TYPES,
        'roles'         => \App\Core\Auth::ROLES,
        'capabilities'  => \App\Core\Auth::capabilityMap(),
    ]);
});
