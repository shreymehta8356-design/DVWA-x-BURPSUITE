<?php
/**
 * DVWA x BURPSUITE - platform configuration
 *
 * Copy this file to config/config.php and edit the values for your machine.
 * config.php is the only file you should need to change after installation.
 */

return [

    // ---------------------------------------------------------------------
    // Database  (XAMPP default MySQL/MariaDB credentials shown)
    // ---------------------------------------------------------------------
    'db' => [
        'driver'   => 'mysql',            // 'mysql' for XAMPP. 'sqlite' is used
                                          // only by tools/selftest.php.
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'name'     => 'dvwa_burp_platform',
        'user'     => 'root',
        'pass'     => '',                 // set this if you gave MySQL a password
        'charset'  => 'utf8mb4',
        'sqlite_path' => null,            // used only when driver = sqlite
    ],

    // ---------------------------------------------------------------------
    // Application
    // ---------------------------------------------------------------------
    'app' => [
        'name'          => 'DVWA x BURPSUITE',
        'tagline'       => 'Offline Web Application Security Assessment Platform',
        // Base URL path the platform is served from, no trailing slash.
        // http://localhost/dvwa-burp-platform  ->  '/dvwa-burp-platform'
        'base_path'     => '/dvwa-burp-platform',
        'timezone'      => 'Asia/Kolkata',
        'debug'         => false,         // true prints PHP errors - keep false
        'storage_path'  => __DIR__ . '/../storage',
    ],

    // ---------------------------------------------------------------------
    // Session hardening
    // ---------------------------------------------------------------------
    'session' => [
        'name'            => 'DVWABURPSID',
        'idle_minutes'    => 30,
        'absolute_hours'  => 12,
        'cookie_secure'   => false,       // set true when serving over HTTPS
        'cookie_samesite' => 'Strict',
    ],

    // ---------------------------------------------------------------------
    // Evidence handling
    // ---------------------------------------------------------------------
    'evidence' => [
        'max_bytes'          => 16 * 1024 * 1024,
        'allowed_mime'       => [
            'image/png', 'image/jpeg', 'image/gif', 'image/webp',
            'text/plain', 'application/json', 'application/xml', 'text/xml',
            'application/pdf', 'text/html', 'application/octet-stream',
        ],
        'allowed_extensions' => [
            'png','jpg','jpeg','gif','webp','txt','log','json','xml','har','pdf','html','req','resp','md','csv',
        ],
    ],

    // ---------------------------------------------------------------------
    // AI  (everything below runs on this machine - nothing is sent outside)
    //
    //  offline engines - always available, zero dependencies:
    //    naive_bayes : vulnerability class triage from analyst observations
    //    tfidf       : duplicate finding detection
    //    cvss        : CVSS v3.1 base score computation
    //    regex       : secret and PII redaction in evidence
    //
    //  optional narrative assistant - local LLM through Ollama:
    //    install Ollama, run `ollama pull llama3.2`, then set llm.enabled = true
    //    in Admin > AI Settings. If the endpoint is unreachable the platform
    //    silently falls back to deterministic templates.
    // ---------------------------------------------------------------------
    'ai' => [
        'enabled'        => true,
        'model_path'     => __DIR__ . '/../storage/models/nb_model.json',
        'llm' => [
            'enabled'  => false,
            'provider' => 'ollama',                    // ollama | openai_compatible | disabled
            'endpoint' => 'http://127.0.0.1:11434',
            'model'    => 'llama3.2',
            'api_key'  => '',
            'timeout'  => 60,
            'temperature' => 0.2,
        ],
    ],
];
