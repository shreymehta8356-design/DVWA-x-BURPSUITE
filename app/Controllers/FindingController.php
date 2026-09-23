<?php

declare(strict_types=1);

namespace App\Controllers;

use App\AI\AiService;
use App\Core\Auth;
use App\Core\Http;
use App\Services\FindingService;
use App\Services\RiskEngine;

final class FindingController
{
    public function index(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(FindingService::listFor((int) $params['id'], [
            'severity'   => Http::str('severity', '', 16),
            'status'     => Http::str('status', '', 24),
            'vuln_class' => Http::str('vuln_class', '', 80),
            'search'     => Http::str('search', '', 120),
        ]));
    }

    public function show(array $params): never
    {
        Auth::must('assessment.view');
        $finding = FindingService::find((int) $params['findingId']);
        if ($finding === null) {
            Http::fail('Finding not found.', 404);
        }
        Http::ok($finding);
    }

    public function store(array $params): never
    {
        Auth::must('finding.create');
        $assessmentId = (int) $params['id'];
        $body = Http::body();

        // Warn about a probable duplicate before the finding is written, unless
        // the analyst has already acknowledged it.
        if (!($body['ignore_duplicates'] ?? false)) {
            $duplicates = (new AiService())->findDuplicates(
                $assessmentId,
                (string) ($body['title'] ?? ''),
                (string) ($body['description'] ?? '')
            );
            if ($duplicates['duplicate_suspected']) {
                Http::json([
                    'ok'         => false,
                    'error'      => 'This looks like a finding that is already recorded in this assessment.',
                    'code'       => 'duplicate_suspected',
                    'duplicates' => $duplicates,
                ], 409);
            }
        }

        Http::ok(FindingService::create($assessmentId, $body), ['message' => 'Finding created.']);
    }

    public function update(array $params): never
    {
        Auth::must('finding.edit');
        Http::ok(FindingService::update((int) $params['findingId'], Http::body()), ['message' => 'Finding updated.']);
    }

    public function changeStatus(array $params): never
    {
        Auth::must('finding.edit');
        Http::ok(
            FindingService::changeStatus(
                (int) $params['findingId'],
                Http::str('status', '', 24),
                Http::str('note', '', 2000)
            ),
            ['message' => 'Finding status updated.']
        );
    }

    public function markDuplicate(array $params): never
    {
        Auth::must('finding.edit');
        Http::ok(
            FindingService::markDuplicate(
                (int) $params['findingId'],
                Http::int('duplicate_of'),
                Http::float('similarity', 0.0)
            ),
            ['message' => 'Finding marked as a duplicate.']
        );
    }

    public function destroy(array $params): never
    {
        Auth::must('finding.delete');
        FindingService::delete((int) $params['findingId']);
        Http::ok(['deleted' => true], ['message' => 'Finding deleted.']);
    }

    /**
     * Live risk preview for the finding editor: the analyst moves the
     * likelihood and impact sliders or edits the CVSS vector and immediately
     * sees the resulting severity together with the reasoning that produced it.
     */
    public function evaluateRisk(): never
    {
        Auth::must('assessment.view');
        $vector = Http::str('cvss_vector', '', 120);
        $override = Http::str('severity_override', '', 16);

        $result = RiskEngine::evaluate(
            Http::int('likelihood', 3),
            Http::int('impact', 3),
            $vector !== '' ? $vector : null,
            ($override !== '' && Auth::can('finding.severity')) ? $override : null
        );

        // Surface a vector parse error so the analyst can correct it.
        if ($vector !== '' && $result['cvss'] === null) {
            $parsed = RiskEngine::cvss($vector);
            $result['cvss_error'] = $parsed['error'] ?? 'The CVSS vector could not be parsed.';
        }
        Http::ok($result);
    }

    public function matrix(): never
    {
        Auth::must('assessment.view');
        Http::ok([
            'matrix'   => RiskEngine::matrixTable(),
            'severities' => RiskEngine::SEVERITIES,
            'labels'   => [
                'likelihood' => [1 => 'Rare', 2 => 'Unlikely', 3 => 'Possible', 4 => 'Likely', 5 => 'Almost certain'],
                'impact'     => [1 => 'Insignificant', 2 => 'Minor', 3 => 'Moderate', 4 => 'Major', 5 => 'Severe'],
            ],
        ]);
    }
}
