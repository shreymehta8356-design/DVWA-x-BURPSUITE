<?php

declare(strict_types=1);

namespace App\AI;

use App\Core\Config;

/**
 * Optional local language model client.
 *
 * The platform is designed to work with this switched OFF: every AI feature
 * has a deterministic offline path (Naive Bayes triage, TF-IDF duplicate
 * detection, CVSS scoring, template narratives). When an analyst wants better
 * prose, they install Ollama on the same machine, pull a small model and turn
 * the assistant on in Admin > AI Settings. Requests go to 127.0.0.1 and never
 * leave the host.
 *
 * The openai_compatible provider exists for labs that run a local
 * OpenAI-shaped server (llama.cpp server, LM Studio, vLLM). Pointing it at an
 * internet endpoint would break the offline guarantee, which the settings
 * screen warns about.
 */
final class LlmClient
{
    private string $provider;
    private string $endpoint;
    private string $model;
    private string $apiKey;
    private int $timeout;
    private float $temperature;
    private ?string $lastError = null;
    private int $lastLatencyMs = 0;

    public function __construct(?array $overrides = null)
    {
        $cfg = (array) Config::get('ai.llm', []);

        // Database settings win over the file, so an admin can switch the
        // assistant on without editing config.php.
        $this->provider    = (string) (Config::setting('ai_llm_provider') ?: ($cfg['provider'] ?? 'ollama'));
        $this->endpoint    = rtrim((string) (Config::setting('ai_llm_endpoint') ?: ($cfg['endpoint'] ?? 'http://127.0.0.1:11434')), '/');
        $this->model       = (string) (Config::setting('ai_llm_model') ?: ($cfg['model'] ?? 'llama3.2'));
        $this->apiKey      = (string) (Config::setting('ai_llm_api_key') ?: ($cfg['api_key'] ?? ''));
        $this->timeout     = max(5, (int) (Config::setting('ai_llm_timeout') ?: ($cfg['timeout'] ?? 60)));
        $this->temperature = (float) ($cfg['temperature'] ?? 0.2);

        if ($overrides !== null) {
            $this->provider = (string) ($overrides['provider'] ?? $this->provider);
            $this->endpoint = rtrim((string) ($overrides['endpoint'] ?? $this->endpoint), '/');
            $this->model    = (string) ($overrides['model'] ?? $this->model);
            $this->apiKey   = (string) ($overrides['api_key'] ?? $this->apiKey);
            $this->timeout  = (int) ($overrides['timeout'] ?? $this->timeout);
        }
    }

    public function isEnabled(): bool
    {
        if (!Config::settingBool('ai_enabled', true)) {
            return false;
        }
        if (!Config::settingBool('ai_llm_enabled', (bool) Config::get('ai.llm.enabled', false))) {
            return false;
        }
        return $this->provider !== 'disabled' && function_exists('curl_init');
    }

    public function provider(): string { return $this->provider; }
    public function model(): string    { return $this->model; }
    public function endpoint(): string { return $this->endpoint; }
    public function lastError(): ?string { return $this->lastError; }
    public function lastLatencyMs(): int { return $this->lastLatencyMs; }

    /**
     * Health probe used by Admin > AI Settings.
     *
     * @return array{available:bool,provider:string,endpoint:string,model:string,models:array<int,string>,message:string}
     */
    public function health(): array
    {
        $base = [
            'available' => false,
            'provider'  => $this->provider,
            'endpoint'  => $this->endpoint,
            'model'     => $this->model,
            'models'    => [],
            'message'   => '',
        ];

        if (!function_exists('curl_init')) {
            $base['message'] = 'PHP cURL extension is not enabled. Enable extension=curl in php.ini.';
            return $base;
        }
        if ($this->provider === 'disabled') {
            $base['message'] = 'The narrative assistant is disabled. Offline models are still active.';
            return $base;
        }

        $url = $this->provider === 'ollama'
            ? $this->endpoint . '/api/tags'
            : $this->endpoint . '/v1/models';

        $response = $this->httpGet($url, 8);
        if ($response === null) {
            $base['message'] = 'Cannot reach ' . $this->endpoint . '. ' . ($this->lastError ?? '')
                . ' Start Ollama (ollama serve) or turn the assistant off.';
            return $base;
        }

        $decoded = json_decode($response, true);
        $names = [];
        if (is_array($decoded)) {
            foreach ($decoded['models'] ?? $decoded['data'] ?? [] as $entry) {
                if (is_array($entry)) {
                    $names[] = (string) ($entry['name'] ?? $entry['id'] ?? '');
                }
            }
        }
        $names = array_values(array_filter($names));

        $base['available'] = true;
        $base['models']    = $names;
        $hasModel = $names === [] || array_filter($names, fn ($n) => str_starts_with($n, $this->model)) !== [];
        $base['message'] = $hasModel
            ? 'Connected. Model "' . $this->model . '" is available locally.'
            : 'Connected, but "' . $this->model . '" is not pulled. Run: ollama pull ' . $this->model;

        return $base;
    }

    /**
     * Single-shot completion. Returns null on any failure so callers fall back
     * to the deterministic template path.
     */
    public function complete(string $system, string $user, int $maxTokens = 700): ?string
    {
        $this->lastError = null;
        if (!$this->isEnabled()) {
            $this->lastError = 'LLM assistant is disabled.';
            return null;
        }

        $started = microtime(true);

        if ($this->provider === 'ollama') {
            $payload = [
                'model'   => $this->model,
                'prompt'  => $user,
                'system'  => $system,
                'stream'  => false,
                'options' => [
                    'temperature' => $this->temperature,
                    'num_predict' => $maxTokens,
                ],
            ];
            $raw = $this->httpPost($this->endpoint . '/api/generate', $payload);
            $text = $raw !== null ? (string) (json_decode($raw, true)['response'] ?? '') : '';
        } else {
            $payload = [
                'model'       => $this->model,
                'messages'    => [
                    ['role' => 'system', 'content' => $system],
                    ['role' => 'user',   'content' => $user],
                ],
                'temperature' => $this->temperature,
                'max_tokens'  => $maxTokens,
                'stream'      => false,
            ];
            $raw = $this->httpPost($this->endpoint . '/v1/chat/completions', $payload);
            $decoded = $raw !== null ? json_decode($raw, true) : null;
            $text = is_array($decoded) ? (string) ($decoded['choices'][0]['message']['content'] ?? '') : '';
        }

        $this->lastLatencyMs = (int) round((microtime(true) - $started) * 1000);

        $text = trim($text);
        if ($text === '') {
            $this->lastError ??= 'The model returned an empty response.';
            return null;
        }
        return $text;
    }

    // -----------------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------------

    private function httpGet(string $url, int $timeout): ?string
    {
        $ch = curl_init($url);
        if ($ch === false) {
            $this->lastError = 'Unable to initialise cURL.';
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(5, $timeout),
            CURLOPT_HTTPHEADER     => $this->headers(),
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($body === false || $status >= 400) {
            $this->lastError = curl_error($ch) ?: ('HTTP ' . $status);
            curl_close($ch);
            return null;
        }
        curl_close($ch);
        return (string) $body;
    }

    /** @param array<string,mixed> $payload */
    private function httpPost(string $url, array $payload): ?string
    {
        $ch = curl_init($url);
        if ($ch === false) {
            $this->lastError = 'Unable to initialise cURL.';
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_HTTPHEADER     => $this->headers(),
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($body === false || $status >= 400) {
            $this->lastError = curl_error($ch) ?: ('HTTP ' . $status . ': ' . substr((string) $body, 0, 200));
            curl_close($ch);
            return null;
        }
        curl_close($ch);
        return (string) $body;
    }

    /** @return array<int,string> */
    private function headers(): array
    {
        $headers = ['Content-Type: application/json', 'Accept: application/json'];
        if ($this->apiKey !== '' && $this->provider === 'openai_compatible') {
            $headers[] = 'Authorization: Bearer ' . $this->apiKey;
        }
        return $headers;
    }
}
