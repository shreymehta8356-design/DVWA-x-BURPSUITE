<?php

declare(strict_types=1);

namespace App\Controllers;

use App\AI\LlmClient;
use App\AI\NaiveBayesClassifier;
use App\Core\Audit;
use App\Core\Auth;
use App\Core\Config;
use App\Core\Database;
use App\Core\Http;
use App\Services\RiskEngine;

final class AdminController
{
    // =======================================================================
    // Users
    // =======================================================================

    public function users(): never
    {
        $rows = Database::all(
            'SELECT id, username, full_name, email, role, is_active, must_change_password,
                    last_login_at, last_login_ip, locked_until, created_at
             FROM users ORDER BY role DESC, username ASC'
        );
        Http::ok(array_map([Auth::class, 'publicUser'], $rows));
    }

    public function createUser(): never
    {
        $username = strtolower(Http::str('username', '', 64));
        $fullName = Http::str('full_name', '', 120);
        $password = (string) (Http::body()['password'] ?? '');
        $role     = Http::enum('role', Auth::ROLES, 'analyst');

        if (!preg_match('/^[a-z0-9._-]{3,64}$/', $username)) {
            Http::fail('Username must be 3-64 characters using letters, digits, dot, underscore or hyphen.', 422);
        }
        if ($fullName === '') {
            Http::fail('A full name is required so the audit trail names a real person.', 422);
        }
        if ((int) Database::scalar('SELECT COUNT(*) FROM users WHERE username = ?', [$username]) > 0) {
            Http::fail('That username is already taken.', 422);
        }
        $problem = Auth::passwordPolicy($password, $username);
        if ($problem !== null) {
            Http::fail($problem, 422);
        }

        $id = Database::insert('users', [
            'username'             => $username,
            'full_name'            => $fullName,
            'email'                => Http::str('email', '', 160) ?: null,
            'password_hash'        => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
            'role'                 => $role,
            'is_active'            => 1,
            'must_change_password' => Http::bool('must_change_password', true) ? 1 : 0,
        ]);

        Audit::log('admin.user_created', 'user', $id, ['username' => $username, 'role' => $role]);
        Http::ok(Auth::publicUser(Database::one('SELECT * FROM users WHERE id = ?', [$id]) ?? []), ['message' => 'Account created.']);
    }

    public function updateUser(array $params): never
    {
        $userId = (int) $params['userId'];
        $user = Database::one('SELECT * FROM users WHERE id = ?', [$userId]);
        if ($user === null) {
            Http::fail('Account not found.', 404);
        }
        $body = Http::body();
        $data = [];

        if (isset($body['full_name']) && trim((string) $body['full_name']) !== '') {
            $data['full_name'] = mb_substr(trim((string) $body['full_name']), 0, 120);
        }
        if (array_key_exists('email', $body)) {
            $data['email'] = trim((string) $body['email']) ?: null;
        }
        if (isset($body['role']) && in_array($body['role'], Auth::ROLES, true)) {
            if ($userId === Auth::id() && $body['role'] !== 'admin') {
                Http::fail('You cannot remove your own administrator role. Ask another administrator to do it.', 422);
            }
            $data['role'] = (string) $body['role'];
        }
        if (array_key_exists('is_active', $body)) {
            if ($userId === Auth::id() && empty($body['is_active'])) {
                Http::fail('You cannot disable your own account.', 422);
            }
            $data['is_active'] = !empty($body['is_active']) ? 1 : 0;
        }
        if (!empty($body['reset_password'])) {
            $newPassword = (string) ($body['new_password'] ?? '');
            $problem = Auth::passwordPolicy($newPassword, (string) $user['username']);
            if ($problem !== null) {
                Http::fail($problem, 422);
            }
            $data['password_hash'] = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
            $data['must_change_password'] = 1;
            $data['failed_attempts'] = 0;
            $data['locked_until'] = null;
        }
        if (!empty($body['unlock'])) {
            $data['locked_until'] = null;
            $data['failed_attempts'] = 0;
        }

        if ($data === []) {
            Http::fail('Nothing to update.', 422);
        }
        $data['updated_at'] = date('Y-m-d H:i:s');
        Database::update('users', $data, 'id = ?', [$userId]);

        Audit::log('admin.user_updated', 'user', $userId, [
            'username' => $user['username'],
            'fields'   => array_values(array_diff(array_keys($data), ['password_hash'])),
        ]);
        Http::ok(Auth::publicUser(Database::one('SELECT * FROM users WHERE id = ?', [$userId]) ?? []), ['message' => 'Account updated.']);
    }

    public function disableUser(array $params): never
    {
        $userId = (int) $params['userId'];
        if ($userId === Auth::id()) {
            Http::fail('You cannot disable your own account.', 422);
        }
        // Accounts are never deleted: the audit trail references them.
        Database::update('users', ['is_active' => 0, 'updated_at' => date('Y-m-d H:i:s')], 'id = ?', [$userId]);
        Audit::log('admin.user_disabled', 'user', $userId);
        Http::ok(['disabled' => true], ['message' => 'Account disabled. It is retained so the audit trail stays complete.']);
    }

    // =======================================================================
    // Settings and risk model
    // =======================================================================

    public function settings(): never
    {
        $rows = Database::all('SELECT skey, svalue, value_type, description, updated_at FROM settings ORDER BY skey');
        foreach ($rows as &$row) {
            if ($row['skey'] === 'ai_llm_api_key' && (string) $row['svalue'] !== '') {
                $row['svalue'] = '********';        // never echo a stored key
            }
        }
        Http::ok([
            'settings'    => $rows,
            'risk_matrix' => RiskEngine::matrixTable(),
            'sla'         => Database::all('SELECT severity, sla_days, rank, description FROM severity_sla ORDER BY rank DESC'),
        ]);
    }

    public function updateSettings(): never
    {
        $updates = Http::body()['settings'] ?? [];
        if (!is_array($updates) || $updates === []) {
            Http::fail('Send a settings object.', 422);
        }

        $known = array_map(static fn ($r) => (string) $r['skey'], Database::all('SELECT skey FROM settings'));
        $applied = [];

        foreach ($updates as $key => $value) {
            $key = (string) $key;
            if (!in_array($key, $known, true)) {
                continue;                                    // ignore unknown keys
            }
            if ($key === 'ai_llm_api_key' && $value === '********') {
                continue;                                    // unchanged masked value
            }
            $value = is_bool($value) ? ($value ? '1' : '0') : (string) $value;

            // Validate the values that would break the platform if wrong.
            if ($key === 'severity_strategy' && !in_array($value, ['matrix', 'cvss', 'higher_of'], true)) {
                Http::fail('severity_strategy must be matrix, cvss or higher_of.', 422);
            }
            if ($key === 'ai_llm_provider' && !in_array($value, ['ollama', 'openai_compatible', 'disabled'], true)) {
                Http::fail('ai_llm_provider must be ollama, openai_compatible or disabled.', 422);
            }
            if ($key === 'ai_llm_endpoint' && $value !== '' && !filter_var($value, FILTER_VALIDATE_URL)) {
                Http::fail('ai_llm_endpoint must be a valid URL, for example http://127.0.0.1:11434.', 422);
            }
            if (in_array($key, ['ai_dedup_threshold', 'ai_triage_min_confidence'], true)) {
                $numeric = (float) $value;
                if ($numeric < 0.05 || $numeric > 0.99) {
                    Http::fail(str_replace('_', ' ', $key) . ' must be between 0.05 and 0.99.', 422);
                }
            }
            if (in_array($key, ['login_max_attempts', 'session_idle_minutes', 'evidence_max_mb', 'login_lockout_minutes', 'ai_llm_timeout'], true)
                && (int) $value < 1) {
                Http::fail(str_replace('_', ' ', $key) . ' must be at least 1.', 422);
            }

            Config::putSetting($key, mb_substr($value, 0, 2000), Auth::id());
            $applied[] = $key;
        }

        Audit::log('admin.settings_updated', 'settings', null, ['keys' => $applied]);
        Http::ok(['updated' => $applied], ['message' => count($applied) . ' setting(s) saved.']);
    }

    public function updateMatrix(): never
    {
        $cells = Http::body()['cells'] ?? [];
        if (!is_array($cells) || $cells === []) {
            Http::fail('Send a cells array of {likelihood, impact, band, colour}.', 422);
        }
        $updated = 0;
        foreach ($cells as $cell) {
            if (!is_array($cell)) {
                continue;
            }
            $likelihood = max(1, min(5, (int) ($cell['likelihood'] ?? 0)));
            $impact     = max(1, min(5, (int) ($cell['impact'] ?? 0)));
            $band       = (string) ($cell['band'] ?? '');
            if (!in_array($band, RiskEngine::SEVERITIES, true)) {
                continue;
            }
            $colour = (string) ($cell['colour'] ?? RiskEngine::colourFor($band));
            if (!preg_match('/^#[0-9a-fA-F]{6}$/', $colour)) {
                $colour = RiskEngine::colourFor($band);
            }
            Database::update('risk_matrix', [
                'band'   => $band,
                'colour' => $colour,
                'score'  => $likelihood * $impact,
            ], 'likelihood = ? AND impact = ?', [$likelihood, $impact]);
            $updated++;
        }
        Audit::log('admin.risk_matrix_updated', 'risk_matrix', null, ['cells' => $updated]);
        Http::ok(RiskEngine::matrixTable(), ['message' => $updated . ' matrix cell(s) updated. Existing findings keep the rating recorded at the time.']);
    }

    // =======================================================================
    // Audit trail
    // =======================================================================

    public function audit(): never
    {
        $limit  = max(1, min(500, Http::int('limit', 100)));
        $offset = max(0, Http::int('offset', 0));

        $sql = 'SELECT a.id, a.actor_username, a.actor_ip, a.action, a.entity_type, a.entity_id,
                       a.assessment_id, a.detail, a.created_at, SUBSTR(a.row_hash, 1, 12) AS hash_short,
                       s.ref_code AS assessment_ref
                FROM audit_log a LEFT JOIN assessments s ON s.id = a.assessment_id WHERE 1 = 1';
        $params = [];

        $assessmentId = Http::int('assessment_id', 0);
        if ($assessmentId > 0) {
            $sql .= ' AND a.assessment_id = ?';
            $params[] = $assessmentId;
        }
        $action = Http::str('action', '', 60);
        if ($action !== '') {
            $sql .= ' AND a.action LIKE ?';
            $params[] = $action . '%';
        }
        $actor = Http::str('actor', '', 64);
        if ($actor !== '') {
            $sql .= ' AND a.actor_username = ?';
            $params[] = $actor;
        }
        $sql .= ' ORDER BY a.id DESC LIMIT ' . $limit . ' OFFSET ' . $offset;

        Http::ok([
            'entries' => Database::all($sql, $params),
            'total'   => (int) Database::scalar('SELECT COUNT(*) FROM audit_log'),
            'limit'   => $limit,
            'offset'  => $offset,
        ]);
    }

    public function verifyAudit(): never
    {
        $result = Audit::verifyChain();
        Http::ok($result + [
            'explanation' => 'Each audit entry stores a SHA-256 over its own content plus the previous entry hash. '
                . 'Verification re-walks that chain, so any edited, deleted or reordered entry is detected.',
        ]);
    }

    // =======================================================================
    // AI models
    // =======================================================================

    public function aiModel(): never
    {
        $classifier = NaiveBayesClassifier::loadOrTrain();
        $llm = new LlmClient();
        Http::ok([
            'classifier' => $classifier->stats(),
            'corpus'     => [
                'seed'     => (int) Database::scalar("SELECT COUNT(*) FROM ai_training_data WHERE source = 'seed' AND is_active = 1"),
                'analyst'  => (int) Database::scalar("SELECT COUNT(*) FROM ai_training_data WHERE source = 'analyst' AND is_active = 1"),
                'total'    => (int) Database::scalar('SELECT COUNT(*) FROM ai_training_data WHERE is_active = 1'),
                'catalogue_examples' => count(NaiveBayesClassifier::catalogLabelMap()),
            ],
            'llm'   => $llm->health(),
            'runs'  => Database::all(
                'SELECT task, engine, model_name, COUNT(*) AS runs, AVG(confidence) AS avg_confidence
                 FROM ai_runs GROUP BY task, engine, model_name ORDER BY runs DESC'
            ),
        ]);
    }

    public function retrainModel(): never
    {
        $started = microtime(true);
        $model = NaiveBayesClassifier::retrain();
        $elapsed = (int) round((microtime(true) - $started) * 1000);

        Audit::log('admin.ai_retrained', 'ai_model', null, $model->stats());
        Http::ok([
            'stats'      => $model->stats(),
            'elapsed_ms' => $elapsed,
        ], ['message' => 'Classifier retrained on ' . $model->stats()['documents'] . ' documents in ' . $elapsed . ' ms.']);
    }

    public function evaluateModel(): never
    {
        $folds = max(2, min(10, Http::int('folds', 5)));
        $samples = NaiveBayesClassifier::collectCorpus();
        if (count($samples) < $folds * 2) {
            Http::fail('Not enough training examples for ' . $folds . '-fold cross validation.', 422);
        }
        $result = NaiveBayesClassifier::crossValidate($samples, $folds);
        Audit::log('admin.ai_evaluated', 'ai_model', null, ['accuracy' => $result['accuracy'], 'macro_f1' => $result['macro_f1']]);
        Http::ok($result + [
            'note' => 'Stratified k-fold cross validation over the current corpus. Accuracy is measured on data the '
                . 'model did not see during that fold, so it reflects generalisation rather than memorisation.',
        ]);
    }

    public function trainingData(): never
    {
        $sql = 'SELECT id, text, label, source, is_active, created_at FROM ai_training_data WHERE 1 = 1';
        $params = [];
        $label = Http::str('label', '', 80);
        if ($label !== '') {
            $sql .= ' AND label = ?';
            $params[] = $label;
        }
        $source = Http::str('source', '', 20);
        if ($source !== '') {
            $sql .= ' AND source = ?';
            $params[] = $source;
        }
        $sql .= ' ORDER BY id DESC LIMIT ' . max(1, min(500, Http::int('limit', 200)));

        Http::ok([
            'rows'   => Database::all($sql, $params),
            'labels' => array_map(
                static fn ($r) => ['label' => (string) $r['label'], 'count' => (int) $r['n']],
                Database::all('SELECT label, COUNT(*) AS n FROM ai_training_data WHERE is_active = 1 GROUP BY label ORDER BY n DESC')
            ),
        ]);
    }

    public function addTraining(): never
    {
        $text = Http::str('text', '', 4000);
        $label = Http::str('label', '', 80);
        if (mb_strlen($text) < 20 || $label === '') {
            Http::fail('Provide an example of at least 20 characters and a label.', 422);
        }
        $id = Database::insert('ai_training_data', [
            'text'       => $text,
            'label'      => $label,
            'source'     => 'analyst',
            'created_by' => Auth::id(),
        ]);
        Audit::log('admin.ai_training_added', 'ai_training', $id, ['label' => $label]);
        Http::ok(['id' => $id], ['message' => 'Example added. Retrain the classifier to apply it.']);
    }

    public function removeTraining(array $params): never
    {
        $id = (int) $params['rowId'];
        Database::update('ai_training_data', ['is_active' => 0], 'id = ?', [$id]);
        Audit::log('admin.ai_training_removed', 'ai_training', $id);
        Http::ok(['removed' => true], ['message' => 'Example deactivated. Retrain to apply.']);
    }

    public function testLlm(): never
    {
        $llm = new LlmClient([
            'provider' => Http::str('provider', '', 40) ?: null,
            'endpoint' => Http::str('endpoint', '', 255) ?: null,
            'model'    => Http::str('model', '', 80) ?: null,
        ]);
        $health = $llm->health();

        if ($health['available'] && Http::bool('run_prompt', false)) {
            $reply = $llm->complete(
                'You are a security report assistant. Answer in one short sentence.',
                'Confirm you are running locally and ready to help draft findings.',
                80
            );
            $health['sample'] = $reply ?? ('No reply: ' . ($llm->lastError() ?? 'unknown error'));
            $health['latency_ms'] = $llm->lastLatencyMs();
        }

        Audit::log('admin.llm_tested', 'ai_model', null, ['available' => $health['available'], 'endpoint' => $health['endpoint']]);
        Http::ok($health);
    }
}
