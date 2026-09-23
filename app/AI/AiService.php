<?php

declare(strict_types=1);

namespace App\AI;

use App\Core\Auth;
use App\Core\Config;
use App\Core\Database;
use App\Services\RiskEngine;

/**
 * Orchestrates every AI capability in the platform and records each
 * invocation in ai_runs, so a reviewer can always answer "which parts of this
 * report did a model touch, with what confidence, and did a human accept it".
 *
 * Engines
 *   naive_bayes  vulnerability class triage from an analyst observation
 *   tfidf        duplicate finding detection and catalogue matching
 *   cvss         deterministic severity computation (RiskEngine)
 *   regex        secret and PII redaction of evidence
 *   llm          OPTIONAL local model for narrative drafting; when it is off
 *                or unreachable, the deterministic template path runs instead
 *                and the result is labelled as such
 *
 * Nothing here decides anything on its own. Every output is a suggestion the
 * analyst accepts, edits or rejects, and the accept/reject decision is stored.
 */
final class AiService
{
    private ?NaiveBayesClassifier $classifier = null;
    private ?LlmClient $llm = null;

    public function enabled(): bool
    {
        return Config::settingBool('ai_enabled', (bool) Config::get('ai.enabled', true));
    }

    public function classifier(): NaiveBayesClassifier
    {
        return $this->classifier ??= NaiveBayesClassifier::loadOrTrain();
    }

    public function llm(): LlmClient
    {
        return $this->llm ??= new LlmClient();
    }

    // =======================================================================
    // 1. Triage - classify a free-text observation
    // =======================================================================

    /**
     * @return array<string,mixed>
     */
    public function triage(string $observation, ?int $assessmentId = null, string $entityType = 'test', ?int $entityId = null): array
    {
        $started = microtime(true);

        if (!$this->enabled()) {
            return ['available' => false, 'reason' => 'AI assistance is switched off in Admin > AI Settings.'];
        }
        if (mb_strlen(trim($observation)) < 12) {
            return ['available' => false, 'reason' => 'Write a few more words of observation before requesting triage.'];
        }

        $prediction = $this->classifier()->predict($observation, 3);
        $minConfidence = Config::settingFloat('ai_triage_min_confidence', 0.35);

        $label = $prediction['label'];
        $confident = $label !== null && $prediction['confidence'] >= $minConfidence;

        // Nearest predefined check, so the analyst can jump straight to it.
        $catalogMatches = $this->matchCatalogue($observation, 3);

        $suggestion = null;
        if ($confident && $label !== null) {
            $vector = RiskEngine::suggestVector($label);
            $cvss = RiskEngine::cvss($vector);
            [$likelihood, $impact] = $this->suggestMatrixInputs($label, $catalogMatches);

            $suggestion = [
                'vuln_class'   => $label,
                'cwe_id'       => RiskEngine::cweFor($label),
                'owasp_top10'  => RiskEngine::owaspFor($label),
                'cvss_vector'  => $cvss['vector'],
                'cvss_score'   => $cvss['base_score'],
                'cvss_band'    => $cvss['band'],
                'likelihood'   => $likelihood,
                'impact'       => $impact,
                'title'        => $this->suggestTitle($label, $observation),
            ];
        }

        $result = [
            'available'    => true,
            'engine'       => 'naive_bayes',
            'model'        => 'MultinomialNB (offline)',
            'label'        => $label,
            'confidence'   => $prediction['confidence'],
            'margin'       => $prediction['margin'],
            'confident'    => $confident,
            'threshold'    => $minConfidence,
            'ranking'      => $prediction['scores'],
            'evidence'     => $prediction['evidence'],
            'corpus'       => ['documents' => $prediction['documents'], 'vocabulary' => $prediction['vocabulary']],
            'catalogue'    => $catalogMatches,
            'suggestion'   => $suggestion,
            'disclaimer'   => 'Statistical suggestion from an offline model. Confirm against your evidence before accepting.',
        ];

        $this->record('triage', 'naive_bayes', 'MultinomialNB', $observation, $result, $prediction['confidence'], $started, $assessmentId, $entityType, $entityId);

        return $result;
    }

    /**
     * @param  array<int,array<string,mixed>> $catalogMatches
     * @return array{0:int,1:int}
     */
    private function suggestMatrixInputs(string $label, array $catalogMatches): array
    {
        // Prefer the catalogue defaults for the best matching check: they were
        // set by a human when the check was written.
        foreach ($catalogMatches as $match) {
            if (($match['score'] ?? 0) >= 0.25 && isset($match['default_likelihood'], $match['default_impact'])) {
                return [(int) $match['default_likelihood'], (int) $match['default_impact']];
            }
        }
        return match ($label) {
            'SQL Injection', 'Command Injection', 'Insecure File Upload'    => [4, 5],
            'Path Traversal / File Inclusion', 'Broken Access Control'      => [4, 5],
            'Cross-Site Scripting', 'Cross-Site Request Forgery'            => [4, 4],
            'Broken Authentication', 'Session Management'                   => [4, 4],
            'Cryptographic Failure', 'Server-Side Request Forgery'          => [3, 5],
            'Business Logic Flaw'                                           => [3, 4],
            'Security Misconfiguration'                                     => [4, 3],
            'Information Disclosure', 'Open Redirect'                       => [3, 3],
            default                                                         => [3, 3],
        };
    }

    private function suggestTitle(string $label, string $observation): string
    {
        $parameter = null;
        if (preg_match('/\b(?:the\s+)?([a-z_][a-z0-9_]{1,30})\s+(?:parameter|param|field|input|header)\b/i', $observation, $m)) {
            $parameter = $m[1];
        }
        return $parameter !== null
            ? $label . ' in the "' . $parameter . '" parameter'
            : $label . ' identified during testing';
    }

    // =======================================================================
    // 2. Catalogue matching (TF-IDF)
    // =======================================================================

    /** @return array<int,array<string,mixed>> */
    public function matchCatalogue(string $text, int $topN = 3): array
    {
        $index = new TfIdfIndex();
        $rows = Database::all(
            'SELECT id, code, title, category, description, test_objective, default_likelihood, default_impact, dvwa_module
             FROM test_catalog WHERE is_active = 1'
        );
        foreach ($rows as $row) {
            $index->add(
                (int) $row['id'],
                trim(($row['title'] ?? '') . ' ' . ($row['description'] ?? '') . ' ' . ($row['test_objective'] ?? '')),
                $row
            );
        }

        $matches = [];
        foreach ($index->similar($text, $topN, 0.05) as $hit) {
            $meta = (array) $hit['meta'];
            $matches[] = [
                'catalog_id'         => (int) $hit['id'],
                'code'               => $meta['code'] ?? '',
                'title'              => $meta['title'] ?? '',
                'category'           => $meta['category'] ?? '',
                'dvwa_module'        => $meta['dvwa_module'] ?? null,
                'default_likelihood' => (int) ($meta['default_likelihood'] ?? 3),
                'default_impact'     => (int) ($meta['default_impact'] ?? 3),
                'score'              => $hit['score'],
                'shared_terms'       => $hit['shared_terms'],
            ];
        }
        return $matches;
    }

    // =======================================================================
    // 3. Duplicate detection (TF-IDF cosine similarity)
    // =======================================================================

    /**
     * @return array{
     *   threshold:float, duplicate_suspected:bool,
     *   matches:array<int,array<string,mixed>>
     * }
     */
    public function findDuplicates(int $assessmentId, string $title, string $description = '', ?int $excludeFindingId = null): array
    {
        $started = microtime(true);
        $threshold = Config::settingFloat('ai_dedup_threshold', 0.62);
        $needle = trim($title . ' ' . $description);

        $params = [$assessmentId];
        $sql = 'SELECT id, ref_code, title, description, vuln_class, severity, status, affected_url
                FROM findings WHERE assessment_id = ?';
        if ($excludeFindingId !== null) {
            $sql .= ' AND id <> ?';
            $params[] = $excludeFindingId;
        }

        // Two views of each finding. A restated duplicate ("SQL injection in
        // the id parameter" vs "SQLi via the id field") almost always shares
        // its title, while its description may be much longer and drag the
        // combined cosine down. Scoring both and taking the stronger signal
        // catches the restatement without inventing similarity that is not
        // there - a genuinely different finding scores low on both views.
        $bodyIndex = new TfIdfIndex();
        $titleIndex = new TfIdfIndex();
        foreach (Database::all($sql, $params) as $row) {
            $id = (int) $row['id'];
            $bodyIndex->add($id, trim(($row['title'] ?? '') . ' ' . ($row['description'] ?? '')), $row);
            $titleIndex->add($id, trim((string) ($row['title'] ?? '')), $row);
        }

        if ($bodyIndex->size() === 0 || $needle === '') {
            return ['threshold' => $threshold, 'duplicate_suspected' => false, 'matches' => []];
        }

        $titleScores = [];
        if (trim($title) !== '') {
            foreach ($titleIndex->similar($title, 10, 0.0) as $hit) {
                $titleScores[(int) $hit['id']] = (float) $hit['score'];
            }
        }

        $matches = [];
        $suspected = false;
        foreach ($bodyIndex->similar($needle, 5, 0.10) as $hit) {
            $meta = (array) $hit['meta'];
            $id = (int) $hit['id'];
            $bodyScore = (float) $hit['score'];
            $titleScore = $titleScores[$id] ?? 0.0;
            $score = round(max($bodyScore, $titleScore), 4);

            $isDuplicate = $score >= $threshold;
            $suspected = $suspected || $isDuplicate;
            $matches[] = [
                'finding_id'   => $id,
                'ref_code'     => $meta['ref_code'] ?? '',
                'title'        => $meta['title'] ?? '',
                'vuln_class'   => $meta['vuln_class'] ?? '',
                'severity'     => $meta['severity'] ?? '',
                'status'       => $meta['status'] ?? '',
                'affected_url' => $meta['affected_url'] ?? '',
                'similarity'   => $score,
                'title_similarity' => round($titleScore, 4),
                'body_similarity'  => round($bodyScore, 4),
                'is_duplicate' => $isDuplicate,
                'shared_terms' => $hit['shared_terms'],
            ];
        }
        usort($matches, static fn ($a, $b) => $b['similarity'] <=> $a['similarity']);

        $result = ['threshold' => $threshold, 'duplicate_suspected' => $suspected, 'matches' => $matches];
        $this->record('dedup', 'tfidf', 'TF-IDF cosine', $needle, $result, $matches[0]['similarity'] ?? 0.0, $started, $assessmentId, 'finding', $excludeFindingId);

        return $result;
    }

    // =======================================================================
    // 4. Narrative drafting
    // =======================================================================

    /**
     * @param  array<string,mixed> $finding
     * @return array{text:string,engine:string,model:string,fallback:bool,latency_ms:int}
     */
    public function draftFindingNarrative(array $finding, ?int $assessmentId = null): array
    {
        $started = microtime(true);
        $vulnClass = (string) ($finding['vuln_class'] ?? 'Security Weakness');

        $system = 'You are a senior application security consultant writing a section of a formal penetration test '
            . 'report. Write in plain professional English, third person, no marketing language, no bullet lists of '
            . 'generic advice. Never invent evidence that was not supplied. Be concise: 120-180 words.';

        $user = "Write the technical description and business impact for this finding.\n\n"
            . 'Title: ' . ($finding['title'] ?? '') . "\n"
            . 'Vulnerability class: ' . $vulnClass . "\n"
            . 'Affected component: ' . ($finding['affected_component'] ?? 'not stated') . "\n"
            . 'Affected URL: ' . ($finding['affected_url'] ?? 'not stated') . "\n"
            . 'Severity: ' . ($finding['severity'] ?? 'medium') . "\n"
            . 'Analyst observation and evidence: ' . ($finding['observation'] ?? $finding['description'] ?? 'not stated') . "\n\n"
            . "Return two labelled paragraphs:\nDESCRIPTION: ...\nIMPACT: ...";

        $text = $this->llm()->complete($system, $user, 500);
        $fallback = $text === null;
        if ($fallback) {
            $text = $this->templateFindingNarrative($finding);
        }

        $result = [
            'text'       => $text,
            'engine'     => $fallback ? 'template' : 'llm',
            'model'      => $fallback ? 'deterministic template' : $this->llm()->model(),
            'fallback'   => $fallback,
            'latency_ms' => (int) round((microtime(true) - $started) * 1000),
        ];

        $this->record('narrative', $result['engine'], $result['model'], $user, $result, null, $started, $assessmentId, 'finding', isset($finding['id']) ? (int) $finding['id'] : null);
        return $result;
    }

    /** @param array<string,mixed> $finding */
    private function templateFindingNarrative(array $finding): string
    {
        $kb = self::knowledgeBase()[$finding['vuln_class'] ?? ''] ?? null;
        $component = (string) ($finding['affected_component'] ?? 'the affected component');
        $url = (string) ($finding['affected_url'] ?? '');
        $observation = trim((string) ($finding['observation'] ?? $finding['description'] ?? ''));

        $description = $kb['description']
            ?? 'Testing identified a security weakness in the application that does not meet the expected secure behaviour defined for this check.';
        $impact = $kb['impact']
            ?? 'An attacker able to reach this functionality could undermine the confidentiality or integrity of application data.';

        return "DESCRIPTION: " . $description . ' The condition was confirmed against ' . $component
            . ($url !== '' ? ' at ' . $url : '') . '. '
            . ($observation !== '' ? 'The analyst recorded: ' . $observation : '')
            . "\n\nIMPACT: " . $impact;
    }

    /**
     * @param  array<string,mixed> $finding
     * @return array{recommendation:string,secure_code:string,references:string,engine:string,model:string,fallback:bool}
     */
    public function draftRemediation(array $finding, ?int $assessmentId = null): array
    {
        $started = microtime(true);
        $vulnClass = (string) ($finding['vuln_class'] ?? '');
        $kb = self::knowledgeBase()[$vulnClass] ?? null;

        $system = 'You are a senior application security engineer. Give specific, actionable remediation guidance for '
            . 'a PHP and MySQL web application. Do not give generic advice such as "validate all input". Reference the '
            . 'concrete API or configuration change required. Maximum 140 words.';

        $user = "Write remediation guidance for this finding.\n\n"
            . 'Title: ' . ($finding['title'] ?? '') . "\n"
            . 'Vulnerability class: ' . $vulnClass . "\n"
            . 'Affected component: ' . ($finding['affected_component'] ?? 'not stated') . "\n"
            . 'Observation: ' . ($finding['description'] ?? $finding['observation'] ?? 'not stated');

        $llmText = $this->llm()->complete($system, $user, 400);
        $fallback = $llmText === null;

        $result = [
            'recommendation' => $fallback ? ($kb['remediation'] ?? self::genericRemediation()) : $llmText,
            'secure_code'    => $kb['secure_code'] ?? '',
            'references'     => $kb['references'] ?? "OWASP Web Security Testing Guide v4.2\nOWASP Cheat Sheet Series",
            'engine'         => $fallback ? 'template' : 'llm',
            'model'          => $fallback ? 'curated knowledge base' : $this->llm()->model(),
            'fallback'       => $fallback,
        ];

        $this->record('remediation', $result['engine'], $result['model'], $user, $result, null, $started, $assessmentId, 'finding', isset($finding['id']) ? (int) $finding['id'] : null);
        return $result;
    }

    /**
     * @param  array<string,mixed> $stats
     * @return array{text:string,engine:string,model:string,fallback:bool}
     */
    public function executiveSummary(array $assessment, array $stats, array $topFindings, ?int $assessmentId = null): array
    {
        $started = microtime(true);

        $findingLines = '';
        foreach (array_slice($topFindings, 0, 8) as $f) {
            $findingLines .= sprintf("- [%s] %s (%s)\n", strtoupper((string) $f['severity']), (string) $f['title'], (string) ($f['vuln_class'] ?? ''));
        }

        $system = 'You are writing the executive summary of a web application penetration test report for a '
            . 'non-technical management audience. State the risk posture plainly, avoid jargon, do not recommend '
            . 'products, and do not exaggerate. 150-220 words, three short paragraphs, no headings, no bullet points.';

        $user = "Assessment: " . ($assessment['title'] ?? '') . "\n"
            . 'Target: ' . ($assessment['target_name'] ?? '') . ' (' . ($assessment['environment'] ?? 'local lab') . ")\n"
            . 'Methodology: ' . ($assessment['methodology'] ?? 'OWASP WSTG v4.2') . "\n"
            . 'Checks executed: ' . ($stats['tests_executed'] ?? 0) . ' of ' . ($stats['tests_total'] ?? 0) . "\n"
            . 'Findings by severity: critical ' . ($stats['critical'] ?? 0) . ', high ' . ($stats['high'] ?? 0)
            . ', medium ' . ($stats['medium'] ?? 0) . ', low ' . ($stats['low'] ?? 0) . ', informational ' . ($stats['info'] ?? 0) . "\n"
            . 'Resolved and retested: ' . ($stats['resolved'] ?? 0) . "\n\n"
            . "Most significant findings:\n" . $findingLines;

        $text = $this->llm()->complete($system, $user, 600);
        $fallback = $text === null;
        if ($fallback) {
            $text = $this->templateExecutiveSummary($assessment, $stats, $topFindings);
        }

        $result = ['text' => $text, 'engine' => $fallback ? 'template' : 'llm', 'model' => $fallback ? 'deterministic template' : $this->llm()->model(), 'fallback' => $fallback];
        $this->record('summary', $result['engine'], $result['model'], $user, ['length' => mb_strlen($text)], null, $started, $assessmentId, 'assessment', $assessmentId);
        return $result;
    }

    /**
     * Deterministic executive summary. This is what appears when no LLM is
     * installed, and it is written to be report-quality on its own.
     */
    private function templateExecutiveSummary(array $assessment, array $stats, array $topFindings): string
    {
        $critical = (int) ($stats['critical'] ?? 0);
        $high     = (int) ($stats['high'] ?? 0);
        $medium   = (int) ($stats['medium'] ?? 0);
        $low      = (int) ($stats['low'] ?? 0);
        $info     = (int) ($stats['info'] ?? 0);
        $total    = $critical + $high + $medium + $low + $info;
        $executed = (int) ($stats['tests_executed'] ?? 0);
        $planned  = (int) ($stats['tests_total'] ?? 0);
        $resolved = (int) ($stats['resolved'] ?? 0);

        $posture = match (true) {
            $critical > 0 => 'weak',
            $high > 0     => 'below the expected standard',
            $medium > 0   => 'broadly acceptable with defects to address',
            $total > 0    => 'satisfactory',
            default       => 'satisfactory, with no exploitable weaknesses identified',
        };

        $p1 = sprintf(
            'A security assessment of %s was performed in the %s environment following %s. %d of %d predefined security checks were executed, and the evidence for every result is retained in the platform. The overall security posture of the target at the time of testing is assessed as %s.',
            (string) ($assessment['target_name'] ?? 'the target application'),
            str_replace('_', ' ', (string) ($assessment['environment'] ?? 'local lab')),
            (string) ($assessment['methodology'] ?? 'the OWASP Web Security Testing Guide v4.2'),
            $executed,
            $planned,
            $posture
        );

        $severityPhrase = $total === 0
            ? 'No findings were raised.'
            : sprintf(
                'The assessment raised %d finding%s: %d critical, %d high, %d medium, %d low and %d informational.',
                $total,
                $total === 1 ? '' : 's',
                $critical,
                $high,
                $medium,
                $low,
                $info
            );

        $headline = '';
        if ($topFindings !== []) {
            $names = array_map(static fn ($f) => (string) $f['title'], array_slice($topFindings, 0, 3));
            $headline = ' The issues carrying the greatest risk are ' . self::joinList($names) . '.';
        }

        $p2 = $severityPhrase . $headline
            . ' Severity for each finding was derived from the published likelihood and impact matrix and, where a vector was recorded, the CVSS v3.1 base score; the derivation is printed alongside every finding so it can be independently checked.';

        $p3 = $resolved > 0
            ? sprintf('%d finding%s %s already been remediated and independently retested. The remaining items are tracked with owners and due dates against the severity-based remediation targets defined in this report.', $resolved, $resolved === 1 ? '' : 's', $resolved === 1 ? 'has' : 'have')
            : 'Remediation has not yet been verified. Each finding carries a recommended fix, an owner and a due date derived from its severity, and should be retested through this platform once the fix is deployed.';

        return $p1 . "\n\n" . $p2 . "\n\n" . $p3;
    }

    /** @param array<int,string> $items */
    private static function joinList(array $items): string
    {
        if (count($items) === 1) {
            return $items[0];
        }
        $last = array_pop($items);
        return implode(', ', $items) . ' and ' . $last;
    }

    // =======================================================================
    // 5. Evidence redaction
    // =======================================================================

    /** @return array{text:string,redactions:int,summary:string,breakdown:array<string,int>} */
    public function redact(string $text, ?int $assessmentId = null, ?int $evidenceId = null): array
    {
        $started = microtime(true);
        $result = Redactor::redact($text);
        if ($result['redactions'] > 0) {
            $this->record('redaction', 'regex', 'pattern set v1', mb_substr($text, 0, 300), ['breakdown' => $result['breakdown']], null, $started, $assessmentId, 'evidence', $evidenceId);
        }
        return $result;
    }

    // =======================================================================
    // 6. Feedback loop - analyst decisions become training data
    // =======================================================================

    public function recordAcceptance(int $aiRunId, bool $accepted): void
    {
        Database::update('ai_runs', ['accepted' => $accepted ? 1 : 0], 'id = ?', [$aiRunId]);
    }

    /**
     * Adds a confirmed finding to the training corpus. Called when an analyst
     * confirms a finding's class, so the classifier improves with use.
     */
    public function learnFromFinding(string $observation, string $label, ?int $userId = null): bool
    {
        $observation = trim($observation);
        if (mb_strlen($observation) < 20 || $label === '') {
            return false;
        }
        $exists = Database::scalar(
            'SELECT COUNT(*) FROM ai_training_data WHERE label = ? AND text = ?',
            [$label, $observation]
        );
        if ((int) $exists > 0) {
            return false;
        }
        Database::insert('ai_training_data', [
            'text'       => mb_substr($observation, 0, 4000),
            'label'      => $label,
            'source'     => 'analyst',
            'created_by' => $userId ?? Auth::id(),
        ]);
        return true;
    }

    // =======================================================================
    // Governance
    // =======================================================================

    private function record(
        string $task,
        string $engine,
        string $model,
        string $input,
        mixed $output,
        ?float $confidence,
        float $startedAt,
        ?int $assessmentId,
        ?string $entityType,
        ?int $entityId
    ): void {
        try {
            Database::insert('ai_runs', [
                'assessment_id' => $assessmentId,
                'entity_type'   => $entityType,
                'entity_id'     => $entityId,
                'task'          => $task,
                'engine'        => $engine,
                'model_name'    => mb_substr($model, 0, 80),
                'input_hash'    => hash('sha256', $input),
                'input_excerpt' => mb_substr(preg_replace('/\s+/', ' ', $input) ?? '', 0, 500),
                'output'        => is_string($output) ? $output : json_encode($output, JSON_UNESCAPED_SLASHES),
                'confidence'    => $confidence,
                'latency_ms'    => (int) round((microtime(true) - $startedAt) * 1000),
                'actor_id'      => Auth::id(),
            ]);
        } catch (\Throwable $e) {
            error_log('[ai] could not record run: ' . $e->getMessage());
        }
    }

    // =======================================================================
    // Curated remediation knowledge base (the deterministic fallback)
    // =======================================================================

    /** @return array<string,array{description:string,impact:string,remediation:string,secure_code:string,references:string}> */
    public static function knowledgeBase(): array
    {
        return [
            'SQL Injection' => [
                'description' => 'User supplied input is incorporated into a SQL statement without parameterisation, so an attacker can alter the structure of the query rather than only its data.',
                'impact' => 'An attacker can read, modify or delete arbitrary database records, extract credential hashes, and in many configurations read local files or execute commands on the database host. This is normally a full compromise of application data.',
                'remediation' => "Replace string concatenation with prepared statements and bound parameters. In PHP use PDO with ATTR_EMULATE_PREPARES set to false, or mysqli prepared statements. Where an identifier such as a column or sort direction must vary, map the user value through a fixed allow list rather than interpolating it. Apply least privilege to the database account so it cannot read other schemas or write files. Do not rely on escaping functions or input filtering as the primary control.",
                'secure_code' => "// Vulnerable\n\$sql = \"SELECT first_name FROM users WHERE user_id = '\$id'\";\n\$result = mysqli_query(\$conn, \$sql);\n\n// Fixed - parameterised, structure is fixed before data is bound\n\$stmt = \$pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?');\n\$stmt->execute([\$id]);\n\$rows = \$stmt->fetchAll(PDO::FETCH_ASSOC);\n\n// Allow list for a dynamic identifier\n\$sortable = ['user_id' => 'user_id', 'name' => 'last_name'];\n\$column = \$sortable[\$_GET['sort'] ?? 'user_id'] ?? 'user_id';\n\$stmt = \$pdo->prepare(\"SELECT * FROM users ORDER BY \$column ASC\");",
                'references' => "OWASP WSTG-INPV-05\nOWASP SQL Injection Prevention Cheat Sheet\nCWE-89",
            ],
            'Cross-Site Scripting' => [
                'description' => 'Untrusted input is returned in a response without encoding appropriate to the output context, allowing script supplied by an attacker to execute in the browser of another user under the origin of the application.',
                'impact' => 'An attacker can execute script in a victim session: stealing session tokens where cookies are readable, performing authenticated actions as the victim, capturing keystrokes on the page and rewriting displayed content. Stored variants affect every user who views the content.',
                'remediation' => "Encode on output, in the context where the value is written. Use htmlspecialchars with ENT_QUOTES and UTF-8 for HTML body and attribute contexts, JSON encoding for values placed into JavaScript, and URL encoding inside href or src. Do not write untrusted data into innerHTML, document.write, or an event handler attribute - use textContent instead. Add a Content-Security-Policy that forbids inline script, and set HttpOnly on session cookies so a successful payload cannot read them.",
                'secure_code' => "// Vulnerable\necho '<p>Hello ' . \$_GET['name'] . '</p>';\n\n// Fixed - contextual output encoding\necho '<p>Hello ' . htmlspecialchars(\$_GET['name'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';\n\n// Client side: use textContent, never innerHTML, for untrusted values\nconst el = document.getElementById('greeting');\nel.textContent = untrustedValue;\n\n// Response header\nheader(\"Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\");",
                'references' => "OWASP WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01\nOWASP Cross Site Scripting Prevention Cheat Sheet\nCWE-79",
            ],
            'Command Injection' => [
                'description' => 'User supplied input reaches an operating system shell, so shell metacharacters submitted by an attacker are interpreted as command syntax rather than data.',
                'impact' => 'An attacker can run arbitrary commands with the privileges of the web server account, which normally means reading application source and configuration including database credentials, writing a web shell, and pivoting to other hosts reachable from the server.',
                'remediation' => "Remove the shell from the path entirely where possible: use a native library or PHP function instead of invoking a binary. Where a binary must be executed, pass arguments as an array through proc_open rather than a single string, and never interpolate user input into the command. If a value must appear in a command, validate it against a strict pattern (for example an IPv4 address) before use and apply escapeshellarg as a secondary control, not the primary one. Run the web server as an unprivileged account.",
                'secure_code' => "// Vulnerable\n\$target = \$_REQUEST['ip'];\n\$output = shell_exec('ping -c 4 ' . \$target);\n\n// Fixed - validate strictly, then avoid the shell\n\$target = \$_POST['ip'] ?? '';\nif (!filter_var(\$target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {\n    throw new InvalidArgumentException('An IPv4 address is required.');\n}\n\$process = proc_open(\n    ['ping', '-c', '4', \$target],   // argument array: no shell parsing\n    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],\n    \$pipes\n);",
                'references' => "OWASP WSTG-INPV-12\nOWASP OS Command Injection Defense Cheat Sheet\nCWE-78",
            ],
            'Path Traversal / File Inclusion' => [
                'description' => 'A file path or include target is built from user input, so traversal sequences or absolute paths supplied by an attacker cause the application to read or execute a file that was never intended to be reachable.',
                'impact' => 'An attacker can read application source, configuration files and credentials. Where the value reaches an include statement, or where remote URLs are permitted, this escalates to arbitrary code execution on the server.',
                'remediation' => "Do not build paths from user input. Map the supplied value through a fixed allow list of permitted files and include only the mapped constant. Where a path must be constructed, resolve it with realpath and confirm the result is still inside the intended base directory before opening it. Disable allow_url_include and allow_url_fopen in php.ini. Reject values containing path separators, null bytes or traversal sequences rather than attempting to strip them.",
                'secure_code' => "// Vulnerable\ninclude(\$_GET['page']);\n\n// Fixed - allow list, no user data in the path\n\$pages = [\n    'about'   => __DIR__ . '/views/about.php',\n    'contact' => __DIR__ . '/views/contact.php',\n];\n\$key = \$_GET['page'] ?? 'about';\nif (!isset(\$pages[\$key])) {\n    http_response_code(404);\n    exit('Not found');\n}\ninclude \$pages[\$key];\n\n// When a path must be built, confine it\n\$base = realpath(__DIR__ . '/uploads');\n\$path = realpath(\$base . '/' . basename(\$_GET['file'] ?? ''));\nif (\$path === false || !str_starts_with(\$path, \$base . DIRECTORY_SEPARATOR)) {\n    exit('Denied');\n}",
                'references' => "OWASP WSTG-ATHZ-01, WSTG-INPV-11\nOWASP File Inclusion guidance\nCWE-22, CWE-98",
            ],
            'Cross-Site Request Forgery' => [
                'description' => 'A state changing request is authorised by the session cookie alone, so a page under attacker control can cause the victim browser to submit the request with the victim credentials attached.',
                'impact' => 'An attacker can perform any state changing action available to the victim without ever seeing the response: changing a password or email address, transferring a record, or creating an administrative account when the victim holds that role.',
                'remediation' => "Issue a per-session anti-CSRF token, place it in every state changing form and validate it server side with a constant time comparison, rejecting the request when it is absent or does not match. Set SameSite=Lax or Strict on the session cookie as defence in depth. Require the current password for sensitive changes such as password or email updates. Never perform state changes on a GET request.",
                'secure_code' => "// Issue\nif (empty(\$_SESSION['csrf'])) {\n    \$_SESSION['csrf'] = bin2hex(random_bytes(32));\n}\necho '<input type=\"hidden\" name=\"_csrf\" value=\"'\n   . htmlspecialchars(\$_SESSION['csrf'], ENT_QUOTES, 'UTF-8') . '\">';\n\n// Validate on every POST, PUT, PATCH and DELETE\nif (!hash_equals(\$_SESSION['csrf'] ?? '', \$_POST['_csrf'] ?? '')) {\n    http_response_code(419);\n    exit('CSRF token invalid');\n}\n\n// Cookie hardening\nsession_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => true]);",
                'references' => "OWASP WSTG-SESS-05\nOWASP Cross-Site Request Forgery Prevention Cheat Sheet\nCWE-352",
            ],
            'Insecure File Upload' => [
                'description' => 'The upload handler accepts a file without validating its true type, and stores it in a location the web server will execute, so an attacker can upload a script and then request it.',
                'impact' => 'An attacker gains arbitrary code execution on the web server, which normally leads to full compromise of the application, its database credentials and any data the server account can reach.',
                'remediation' => "Validate the file by inspecting its content, not the client supplied name or Content-Type: use finfo to read the real MIME type and check it against an allow list, and for images confirm getimagesize succeeds. Generate a new random file name and a controlled extension - never reuse the uploaded name. Store uploads outside the web root and serve them through a script that sets Content-Disposition and a non-executable Content-Type. If uploads must live under the web root, disable script execution in that directory at the server level. Enforce a maximum size.",
                'secure_code' => "\$finfo = new finfo(FILEINFO_MIME_TYPE);\n\$mime  = \$finfo->file(\$_FILES['f']['tmp_name']);\n\$allowed = ['image/png' => 'png', 'image/jpeg' => 'jpg'];\nif (!isset(\$allowed[\$mime]) || getimagesize(\$_FILES['f']['tmp_name']) === false) {\n    exit('Unsupported file type');\n}\n\$name = bin2hex(random_bytes(16)) . '.' . \$allowed[\$mime];\nmove_uploaded_file(\$_FILES['f']['tmp_name'], STORAGE_OUTSIDE_WEBROOT . '/' . \$name);\n\n# Apache, in the upload directory\n# php_flag engine off\n# <FilesMatch \"\\.(php|phar|phtml)\\$\"> Require all denied </FilesMatch>",
                'references' => "OWASP WSTG-BUSL-09\nOWASP File Upload Cheat Sheet\nCWE-434",
            ],
            'Broken Authentication' => [
                'description' => 'The authentication mechanism does not adequately resist guessing, or accepts credentials that were never changed from their defaults, so an attacker can obtain a valid session without knowing a secret.',
                'impact' => 'An attacker gains access to a legitimate account and everything that account can reach. Where an administrative account is obtained, this is a complete compromise of the application.',
                'remediation' => "Enforce a minimum password length of at least 12 characters and screen candidates against a breached password list. Apply progressive delays and account lockout after a small number of consecutive failures, and rate limit by source address as well as by account. Return an identical response for an unknown username and a wrong password so accounts cannot be enumerated. Store passwords with bcrypt, scrypt or Argon2id, never a fast hash. Change or disable every default account before deployment, and offer multi-factor authentication for privileged roles.",
                'secure_code' => "// Storage\n\$hash = password_hash(\$password, PASSWORD_BCRYPT, ['cost' => 12]);\n\n// Verification with a uniform failure response\n\$user = \$repo->findByUsername(\$username);\n\$valid = \$user !== null && password_verify(\$password, \$user['password_hash']);\nif (!\$valid) {\n    \$repo->recordFailure(\$username, \$ip);   // drives lockout and throttling\n    usleep(random_int(150000, 400000));\n    return ['error' => 'Invalid username or password.'];  // identical either way\n}\nsession_regenerate_id(true);",
                'references' => "OWASP WSTG-ATHN-02, WSTG-ATHN-03, WSTG-ATHN-07\nOWASP Authentication Cheat Sheet\nCWE-287, CWE-307",
            ],
            'Session Management' => [
                'description' => 'Session identifiers are predictable, are not protected by the appropriate cookie attributes, or are not invalidated when they should be, so an attacker can obtain or guess a valid session.',
                'impact' => 'An attacker who predicts, steals or fixes a session identifier acts as that user for the life of the session, with no need for credentials and typically with no trace in authentication logs.',
                'remediation' => "Generate session identifiers with a cryptographically secure source and adequate entropy - use the platform session manager rather than a custom scheme. Set HttpOnly, Secure and SameSite on the session cookie. Regenerate the identifier on authentication and on any privilege change to prevent fixation. Destroy the session server side on logout, not only the cookie, and enforce both an idle and an absolute timeout. Never place the session identifier in a URL.",
                'secure_code' => "session_set_cookie_params([\n    'lifetime' => 0,\n    'httponly' => true,\n    'secure'   => true,\n    'samesite' => 'Strict',\n]);\nini_set('session.use_strict_mode', '1');\nini_set('session.use_only_cookies', '1');\nsession_start();\n\n// On successful authentication\nsession_regenerate_id(true);\n\$_SESSION['uid'] = \$user['id'];\n\$_SESSION['started_at'] = time();\n\n// On logout\n\$_SESSION = [];\nsession_destroy();",
                'references' => "OWASP WSTG-SESS-01, WSTG-SESS-02, WSTG-SESS-03\nOWASP Session Management Cheat Sheet\nCWE-384, CWE-613",
            ],
            'Broken Access Control' => [
                'description' => 'An authorisation decision is made from data the client controls, or is not made at all on the server, so a user can reach a function or a record that belongs to someone else.',
                'impact' => 'A low privileged user reads or modifies other users data, or reaches administrative functionality. This is frequently the highest impact class of finding because it is trivially repeatable and leaves no anomaly in application logs.',
                'remediation' => "Deny by default and enforce every authorisation decision on the server, in one place, from the authenticated session - never from a role or identifier supplied in the request, a hidden field or a cookie. For every object access, confirm the authenticated user owns or is entitled to that specific record before returning it. Prefer opaque or per-user identifiers over sequential ones so enumeration is not free. Cover authorisation with automated tests for each role.",
                'secure_code' => "// Vulnerable - trusts the identifier in the request\n\$order = \$repo->find(\$_GET['order_id']);\n\n// Fixed - the query is scoped to the session owner\n\$stmt = \$pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');\n\$stmt->execute([(int) \$_GET['order_id'], \$_SESSION['uid']]);\n\$order = \$stmt->fetch();\nif (\$order === false) {\n    http_response_code(403);\n    exit('Forbidden');\n}\n\n// Role comes from the server side session, never the request\nif (!in_array(\$_SESSION['role'], ['lead', 'admin'], true)) {\n    http_response_code(403);\n    exit('Forbidden');\n}",
                'references' => "OWASP WSTG-ATHZ-02, WSTG-ATHZ-03, WSTG-ATHZ-04\nOWASP Authorization Cheat Sheet\nCWE-284, CWE-639",
            ],
            'Open Redirect' => [
                'description' => 'A redirect destination is taken from user input without validation, so the application will forward a visitor to any site an attacker chooses.',
                'impact' => 'An attacker sends a link on the legitimate domain that lands the victim on a phishing page, borrowing the trust and the reputation of the real site. It is also used to bypass link filters and to leak tokens through the referrer.',
                'remediation' => "Prefer redirect targets that are not user controlled at all - use a server side mapping key instead of a URL. Where a URL must be accepted, parse it and accept only relative paths, or match the host against an allow list of permitted destinations; reject scheme-relative values beginning with two slashes and anything containing a backslash or an encoded separator. Do not attempt to fix an invalid destination, reject it.",
                'secure_code' => "\$target = \$_GET['url'] ?? '/';\n\n// Accept only a same-site relative path\nif (!preg_match('~^/[A-Za-z0-9_\\-/.]*\$~', \$target) || str_starts_with(\$target, '//')) {\n    \$target = '/dashboard';\n}\nheader('Location: ' . \$target, true, 302);\nexit;\n\n// Or map through a fixed table\n\$destinations = ['home' => '/', 'profile' => '/profile'];\n\$target = \$destinations[\$_GET['to'] ?? 'home'] ?? '/';",
                'references' => "OWASP WSTG-CLNT-04\nOWASP Unvalidated Redirects and Forwards Cheat Sheet\nCWE-601",
            ],
            'Security Misconfiguration' => [
                'description' => 'The platform or application is deployed with insecure defaults, unnecessary features enabled, or missing hardening headers, weakening the protections a browser would otherwise apply.',
                'impact' => 'Individually these are usually low severity, but together they lower the cost of every other attack: framing enables clickjacking, a missing CSP removes the last line of defence against script injection, and verbose banners tell an attacker exactly which exploit to try.',
                'remediation' => "Add the security response headers on every response: a restrictive Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY or CSP frame-ancestors 'none', Referrer-Policy: strict-origin-when-cross-origin, and HSTS on HTTPS services. Disable directory listing and the TRACE method. Suppress version banners. Remove sample applications, backup files and administrative interfaces from the deployed instance, and confirm display_errors is off in production.",
                'secure_code' => "// PHP, on every response\nheader(\"Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'\");\nheader('X-Content-Type-Options: nosniff');\nheader('Referrer-Policy: strict-origin-when-cross-origin');\nheader('Strict-Transport-Security: max-age=31536000; includeSubDomains');\n\n# Apache httpd.conf\n# ServerTokens Prod\n# ServerSignature Off\n# TraceEnable Off\n# Options -Indexes",
                'references' => "OWASP WSTG-CONF-02, WSTG-CONF-06, WSTG-CONF-12\nOWASP Secure Headers Project\nCWE-16, CWE-693",
            ],
            'Information Disclosure' => [
                'description' => 'The application returns internal detail - stack traces, absolute paths, SQL statements, framework versions or developer comments - to an unauthenticated client.',
                'impact' => 'The disclosed detail does not compromise the application by itself, but it removes the reconnaissance cost for an attacker: it names the technology to target, reveals the internal structure, and frequently exposes the exact query an injection payload must fit.',
                'remediation' => "Set display_errors to off and log_errors to on in production so detail reaches the log rather than the browser, and register a global exception handler that returns a generic message with a correlation identifier. Remove developer comments and debug endpoints from deployed code. Suppress Server and X-Powered-By banners. Review responses for internal hostnames and paths before release.",
                'secure_code' => "// php.ini\n// display_errors = Off\n// log_errors = On\n// error_log = /path/outside/webroot/php-error.log\n// expose_php = Off\n\nset_exception_handler(function (Throwable \$e) {\n    \$id = bin2hex(random_bytes(8));\n    error_log(\"[\$id] \" . \$e->getMessage() . ' @ ' . \$e->getFile() . ':' . \$e->getLine());\n    http_response_code(500);\n    echo 'An unexpected error occurred. Reference: ' . \$id;\n});",
                'references' => "OWASP WSTG-ERRH-01, WSTG-ERRH-02, WSTG-INFO-05\nCWE-200, CWE-209",
            ],
            'Cryptographic Failure' => [
                'description' => 'Sensitive data is transmitted or stored without adequate cryptographic protection, or is protected with an algorithm that no longer resists attack.',
                'impact' => 'Credentials and personal data are exposed to anyone positioned on the network path or able to read the datastore. Unsalted fast hashes such as MD5 are recovered from commodity hardware in minutes, so a database disclosure becomes a credential disclosure.',
                'remediation' => "Serve the whole application over TLS 1.2 or later and enable HSTS; never transmit a credential or a token over plain HTTP. Hash passwords with bcrypt, scrypt or Argon2id through password_hash, never MD5 or SHA-1, and re-hash on login when the cost parameters change. Encrypt sensitive data at rest with an authenticated mode such as AES-256-GCM, generate keys from a CSPRNG, and keep them outside the web root and out of version control. Never store a session token in localStorage.",
                'secure_code' => "// Password storage\n\$hash = password_hash(\$plain, PASSWORD_ARGON2ID);\nif (password_verify(\$plain, \$hash) && password_needs_rehash(\$hash, PASSWORD_ARGON2ID)) {\n    \$repo->updateHash(\$id, password_hash(\$plain, PASSWORD_ARGON2ID));\n}\n\n// Authenticated encryption at rest\n\$iv  = random_bytes(12);\n\$ct  = openssl_encrypt(\$plaintext, 'aes-256-gcm', \$key, OPENSSL_RAW_DATA, \$iv, \$tag);\n\$blob = base64_encode(\$iv . \$tag . \$ct);",
                'references' => "OWASP WSTG-CRYP-03, WSTG-CRYP-04, WSTG-ATHN-01\nOWASP Password Storage Cheat Sheet\nCWE-319, CWE-327",
            ],
            'Business Logic Flaw' => [
                'description' => 'The application enforces its business rules in a way that can be subverted by using the application in an unintended order or with unintended values, without breaking any technical control.',
                'impact' => 'An attacker achieves an outcome the business never intended - repeating a single use operation, skipping a required step, or submitting values outside the permitted range - while every individual request looks legitimate in the logs.',
                'remediation' => "Enforce the workflow state on the server: record which step a transaction has reached and reject any request that does not follow from that state. Validate value ranges and sign server side rather than in the browser. Make single use operations idempotent with a server generated nonce that is consumed on first use. Apply rate limiting to sensitive functions and test each rule with the step deliberately performed out of order.",
                'secure_code' => "// Server side state machine, not a hidden form field\n\$allowed = ['cart' => ['address'], 'address' => ['payment'], 'payment' => ['confirm']];\n\$current = \$_SESSION['checkout_step'] ?? 'cart';\nif (!in_array(\$requestedStep, \$allowed[\$current] ?? [], true)) {\n    http_response_code(409);\n    exit('Step out of sequence');\n}\n\n// Single use token consumed on first use\n\$stmt = \$pdo->prepare('UPDATE operations SET used_at = NOW() WHERE nonce = ? AND used_at IS NULL');\n\$stmt->execute([\$nonce]);\nif (\$stmt->rowCount() === 0) {\n    exit('This operation has already been completed.');\n}",
                'references' => "OWASP WSTG-BUSL-01, WSTG-BUSL-05\nOWASP Business Logic Testing guidance\nCWE-840, CWE-837",
            ],
            'Server-Side Request Forgery' => [
                'description' => 'The server fetches a URL supplied by the user without restricting the destination, so it can be induced to make requests to internal systems on the attacker behalf.',
                'impact' => 'An attacker reaches services that are not exposed to the network, including cloud metadata endpoints, internal administrative interfaces and databases bound to loopback, using the server as a proxy that carries its own network trust.',
                'remediation' => "Do not accept a full URL from the user where a fixed identifier will do. Where a URL is required, parse it and enforce an allow list of scheme, host and port; resolve the hostname and reject addresses in private, loopback, link-local and reserved ranges, then connect to the resolved address to prevent a DNS rebind between check and use. Disable redirect following. Isolate the fetching component at the network level so it cannot reach internal ranges at all.",
                'secure_code' => "\$url = \$_POST['url'] ?? '';\n\$parts = parse_url(\$url);\nif (!\$parts || !in_array(\$parts['scheme'] ?? '', ['http', 'https'], true)) {\n    exit('Unsupported URL');\n}\n\$ip = gethostbyname(\$parts['host']);\nif (!filter_var(\$ip, FILTER_VALIDATE_IP,\n    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {\n    exit('Destination not permitted');\n}\n\$ch = curl_init(\$url);\ncurl_setopt_array(\$ch, [CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 5]);",
                'references' => "OWASP WSTG-INPV-19\nOWASP Server-Side Request Forgery Prevention Cheat Sheet\nCWE-918",
            ],
        ];
    }

    private static function genericRemediation(): string
    {
        return 'Correct the underlying weakness at the point where untrusted data is handled: validate the input '
            . 'against an allow list on the server, use a safe API for the sink involved rather than string '
            . 'construction, and enforce the authorisation decision server side. Re-test through this platform once '
            . 'the change is deployed and attach the retest evidence to the finding.';
    }
}
