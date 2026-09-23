<?php

declare(strict_types=1);

namespace App\Controllers;

use App\AI\AiService;
use App\AI\LlmClient;
use App\AI\Redactor;
use App\Core\Auth;
use App\Core\Config;
use App\Core\Database;
use App\Core\Http;
use App\Services\AssessmentService;
use App\Services\FindingService;

final class AiController
{
    public function triage(): never
    {
        Auth::must('ai.use');
        $assessmentId = Http::int('assessment_id', 0);
        $testId = Http::int('test_id', 0);
        Http::ok((new AiService())->triage(
            Http::str('observation', '', 20000),
            $assessmentId > 0 ? $assessmentId : null,
            $testId > 0 ? 'test' : 'finding',
            $testId > 0 ? $testId : null
        ));
    }

    public function duplicates(): never
    {
        Auth::must('ai.use');
        $assessmentId = Http::int('assessment_id', 0);
        if ($assessmentId <= 0) {
            Http::fail('An assessment_id is required.', 422);
        }
        $exclude = Http::int('exclude_finding_id', 0);
        Http::ok((new AiService())->findDuplicates(
            $assessmentId,
            Http::str('title', '', 500),
            Http::str('description', '', 20000),
            $exclude > 0 ? $exclude : null
        ));
    }

    public function narrative(): never
    {
        Auth::must('ai.use');
        $findingId = Http::int('finding_id', 0);
        $finding = $findingId > 0 ? FindingService::find($findingId) : null;

        $input = $finding ?? [
            'title'              => Http::str('title', '', 500),
            'vuln_class'         => Http::str('vuln_class', '', 80),
            'affected_component' => Http::str('affected_component', '', 200),
            'affected_url'       => Http::str('affected_url', '', 255),
            'severity'           => Http::str('severity', 'medium', 16),
            'description'        => Http::str('description', '', 20000),
            'observation'        => Http::str('observation', '', 20000),
        ];

        $result = (new AiService())->draftFindingNarrative(
            $input,
            $finding['assessment_id'] ?? (Http::int('assessment_id', 0) ?: null)
        );
        Http::ok($this->splitNarrative($result));
    }

    public function remediation(): never
    {
        Auth::must('ai.use');
        $findingId = Http::int('finding_id', 0);
        $finding = $findingId > 0 ? FindingService::find($findingId) : null;

        $input = $finding ?? [
            'title'              => Http::str('title', '', 500),
            'vuln_class'         => Http::str('vuln_class', '', 80),
            'affected_component' => Http::str('affected_component', '', 200),
            'description'        => Http::str('description', '', 20000),
        ];

        Http::ok((new AiService())->draftRemediation($input, $finding['assessment_id'] ?? null));
    }

    public function summary(): never
    {
        Auth::must('ai.use');
        $assessmentId = Http::int('assessment_id', 0);
        $assessment = AssessmentService::find($assessmentId);
        if ($assessment === null) {
            Http::fail('Assessment not found.', 404);
        }
        $findings = FindingService::listFor($assessmentId);
        Http::ok((new AiService())->executiveSummary(
            $assessment,
            $assessment['stats'] ?? [],
            $findings,
            $assessmentId
        ));
    }

    /** Shows the analyst what auto-redaction would remove, before it is applied. */
    public function redactPreview(): never
    {
        Auth::must('ai.use');
        $text = Http::str('text', '', 200000);
        $result = Redactor::redact($text);
        Http::ok([
            'redactions' => $result['redactions'],
            'breakdown'  => $result['breakdown'],
            'summary'    => $result['summary'],
            'preview'    => mb_substr($result['text'], 0, 8000),
            'enabled'    => Config::settingBool('auto_redact_evidence', true),
        ]);
    }

    /**
     * Records whether the analyst accepted or rejected a suggestion, and feeds
     * accepted classifications back into the training corpus.
     */
    public function feedback(): never
    {
        Auth::must('ai.use');
        $runId = Http::int('ai_run_id', 0);
        $accepted = Http::bool('accepted', false);
        $service = new AiService();

        if ($runId > 0) {
            $service->recordAcceptance($runId, $accepted);
        }

        $learned = false;
        if ($accepted) {
            $observation = Http::str('observation', '', 20000);
            $label = Http::str('label', '', 80);
            if ($observation !== '' && $label !== '') {
                $learned = $service->learnFromFinding($observation, $label);
            }
        }

        Http::ok([
            'recorded' => true,
            'learned'  => $learned,
            'message'  => $learned
                ? 'Recorded. The confirmed example was added to the training corpus - retrain from Admin > AI Models to apply it.'
                : 'Recorded.',
        ]);
    }

    public function status(): never
    {
        Auth::requireLogin();
        $service = new AiService();
        $classifier = $service->classifier();
        $llm = new LlmClient();

        Http::ok([
            'enabled' => $service->enabled(),
            'offline_engines' => [
                [
                    'name' => 'Naive Bayes triage',
                    'engine' => 'naive_bayes',
                    'purpose' => 'Predicts the vulnerability class from a free-text analyst observation.',
                    'status' => $classifier->isTrained() ? 'ready' : 'untrained',
                    'detail' => $classifier->stats(),
                ],
                [
                    'name' => 'TF-IDF similarity',
                    'engine' => 'tfidf',
                    'purpose' => 'Detects duplicate findings and matches observations to predefined checks.',
                    'status' => 'ready',
                    'detail' => ['threshold' => Config::settingFloat('ai_dedup_threshold', 0.62)],
                ],
                [
                    'name' => 'CVSS v3.1 engine',
                    'engine' => 'cvss',
                    'purpose' => 'Computes base scores from the published specification.',
                    'status' => 'ready',
                    'detail' => ['strategy' => Config::setting('severity_strategy', 'higher_of')],
                ],
                [
                    'name' => 'Evidence redactor',
                    'engine' => 'regex',
                    'purpose' => 'Removes credentials, tokens and personal data from captured evidence.',
                    'status' => Config::settingBool('auto_redact_evidence', true) ? 'ready' : 'disabled',
                    'detail' => ['auto' => Config::settingBool('auto_redact_evidence', true)],
                ],
            ],
            'llm' => [
                'enabled'  => $llm->isEnabled(),
                'provider' => $llm->provider(),
                'endpoint' => $llm->endpoint(),
                'model'    => $llm->model(),
                'note'     => 'Optional. When it is off or unreachable, narrative drafting falls back to deterministic templates and every result is labelled accordingly.',
            ],
            'usage' => [
                'total_runs' => (int) Database::scalar('SELECT COUNT(*) FROM ai_runs'),
                'accepted'   => (int) Database::scalar('SELECT COUNT(*) FROM ai_runs WHERE accepted = 1'),
                'rejected'   => (int) Database::scalar('SELECT COUNT(*) FROM ai_runs WHERE accepted = 0'),
            ],
        ]);
    }

    /**
     * The drafting prompt asks for DESCRIPTION: / IMPACT: sections; split them
     * so the interface can drop each into the right field.
     *
     * @param  array<string,mixed> $result
     * @return array<string,mixed>
     */
    private function splitNarrative(array $result): array
    {
        $text = (string) $result['text'];
        $description = $text;
        $impact = '';

        if (preg_match('/DESCRIPTION\s*:\s*(.*?)(?:\n\s*IMPACT\s*:\s*(.*))?$/is', $text, $m)) {
            $description = trim($m[1] ?? $text);
            $impact = trim($m[2] ?? '');
        }

        $result['description'] = $description;
        $result['impact_narrative'] = $impact;
        return $result;
    }
}
