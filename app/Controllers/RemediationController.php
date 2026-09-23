<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Auth;
use App\Core\Http;
use App\Services\RemediationService;

final class RemediationController
{
    public function tracker(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(RemediationService::trackerFor((int) $params['id']));
    }

    public function show(array $params): never
    {
        Auth::must('assessment.view');
        $remediation = RemediationService::findFor((int) $params['findingId']);
        if ($remediation === null) {
            Http::fail('No remediation record exists for that finding.', 404);
        }
        Http::ok($remediation);
    }

    public function update(array $params): never
    {
        Auth::must('remediation.edit');
        Http::ok(
            RemediationService::update((int) $params['findingId'], Http::body()),
            ['message' => 'Remediation updated.']
        );
    }

    public function retests(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(RemediationService::retestsFor((int) $params['findingId']));
    }

    public function recordRetest(array $params): never
    {
        Auth::must('retest.record');
        Http::ok(
            RemediationService::recordRetest((int) $params['findingId'], Http::body()),
            ['message' => 'Retest recorded.']
        );
    }
}
