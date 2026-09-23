<?php

declare(strict_types=1);

namespace App\Services;

use App\AI\AiService;
use App\Core\Audit;
use App\Core\Auth;
use App\Core\Database;
use RuntimeException;

/**
 * Burp Suite issue import.
 *
 * Reads the XML produced by Burp Suite "Report issues" (both Professional and
 * the Community-style manual issue export), maps each issue to a predefined
 * check in the catalogue, classifies it with the offline model, and stages it
 * for analyst review. Nothing is promoted to a finding automatically - the
 * analyst chooses which issues to accept, which keeps the human in the loop
 * and keeps the report defensible.
 *
 * XML security: the parser is the piece of this platform most exposed to
 * hostile input, so entity substitution and network access are both refused
 * and a DOCTYPE containing an ENTITY declaration is rejected outright.
 */
final class BurpImporter
{
    private const MAX_BYTES = 64 * 1024 * 1024;

    /**
     * Burp issue name (lowercased, matched by substring) => vulnerability class.
     * Ordered: the first match wins, so specific names precede generic ones.
     *
     * @var array<string,string>
     */
    private const NAME_MAP = [
        'sql injection'                    => 'SQL Injection',
        'blind sql'                        => 'SQL Injection',
        'cross-site scripting (stored)'    => 'Cross-Site Scripting',
        'cross-site scripting (reflected)' => 'Cross-Site Scripting',
        'cross-site scripting (dom'        => 'Cross-Site Scripting',
        'cross-site scripting'             => 'Cross-Site Scripting',
        'os command injection'             => 'Command Injection',
        'command injection'                => 'Command Injection',
        'file path traversal'              => 'Path Traversal / File Inclusion',
        'path traversal'                   => 'Path Traversal / File Inclusion',
        'file path manipulation'           => 'Path Traversal / File Inclusion',
        'php code injection'               => 'Path Traversal / File Inclusion',
        'remote file inclusion'            => 'Path Traversal / File Inclusion',
        'cross-site request forgery'       => 'Cross-Site Request Forgery',
        'csrf'                             => 'Cross-Site Request Forgery',
        'file upload'                      => 'Insecure File Upload',
        'unrestricted file upload'         => 'Insecure File Upload',
        'server-side request forgery'      => 'Server-Side Request Forgery',
        'ssrf'                             => 'Server-Side Request Forgery',
        'external service interaction'     => 'Server-Side Request Forgery',
        'open redirection'                 => 'Open Redirect',
        'open redirect'                    => 'Open Redirect',
        'session token'                    => 'Session Management',
        'cookie without httponly'          => 'Session Management',
        'cookie without the httponly'      => 'Session Management',
        'cookie without secure'            => 'Session Management',
        'ssl cookie without secure'        => 'Session Management',
        'session fixation'                 => 'Session Management',
        'password field'                   => 'Broken Authentication',
        'password submitted'               => 'Cryptographic Failure',
        'unencrypted communications'       => 'Cryptographic Failure',
        'cleartext submission of password' => 'Cryptographic Failure',
        'tls certificate'                  => 'Cryptographic Failure',
        'ssl certificate'                  => 'Cryptographic Failure',
        'directory listing'                => 'Security Misconfiguration',
        'frameable response'               => 'Security Misconfiguration',
        'clickjacking'                     => 'Security Misconfiguration',
        'content security policy'          => 'Security Misconfiguration',
        'content type incorrectly stated'  => 'Security Misconfiguration',
        'content sniffing'                 => 'Security Misconfiguration',
        'strict transport security'        => 'Security Misconfiguration',
        'http trace'                       => 'Security Misconfiguration',
        'cross-domain'                     => 'Security Misconfiguration',
        'robots.txt'                       => 'Information Disclosure',
        'information disclosure'           => 'Information Disclosure',
        'error message'                    => 'Information Disclosure',
        'stack trace'                      => 'Information Disclosure',
        'private ip'                       => 'Information Disclosure',
        'email addresses disclosed'        => 'Information Disclosure',
        'software version'                 => 'Information Disclosure',
        'backup file'                      => 'Information Disclosure',
        'source code disclosure'           => 'Information Disclosure',
        'directory traversal'              => 'Path Traversal / File Inclusion',
        'privilege escalation'             => 'Broken Access Control',
        'access control'                   => 'Broken Access Control',
        'insecure direct object'           => 'Broken Access Control',
    ];

    /** Vulnerability class => catalogue code used when creating the finding. */
    private const CLASS_TO_CODE = [
        'SQL Injection'                   => 'WSTG-INPV-05',
        'Cross-Site Scripting'            => 'WSTG-INPV-01',
        'Command Injection'               => 'WSTG-INPV-12',
        'Path Traversal / File Inclusion' => 'WSTG-ATHZ-01',
        'Cross-Site Request Forgery'      => 'WSTG-SESS-05',
        'Insecure File Upload'            => 'WSTG-BUSL-09',
        'Server-Side Request Forgery'     => 'WSTG-INPV-19',
        'Open Redirect'                   => 'WSTG-CLNT-04',
        'Session Management'              => 'WSTG-SESS-02',
        'Broken Authentication'           => 'WSTG-ATHN-03',
        'Broken Access Control'           => 'WSTG-ATHZ-02',
        'Cryptographic Failure'           => 'WSTG-CRYP-03',
        'Security Misconfiguration'       => 'WSTG-CONF-12',
        'Information Disclosure'          => 'WSTG-INFO-05',
        'Business Logic Flaw'             => 'WSTG-BUSL-01',
    ];

    // =======================================================================
    // Import
    // =======================================================================

    /**
     * @return array{import_id:int,issue_count:int,burp_version:string,export_time:string,issues:array<int,array<string,mixed>>}
     */
    public static function import(int $assessmentId, string $xml, string $filename): array
    {
        if (strlen($xml) === 0) {
            throw new RuntimeException('The uploaded file is empty.');
        }
        if (strlen($xml) > self::MAX_BYTES) {
            throw new RuntimeException('The Burp export is larger than 64 MB. Filter the issues in Burp and export again.');
        }

        $fileHash = hash('sha256', $xml);
        $existing = Database::one(
            'SELECT id FROM burp_imports WHERE assessment_id = ? AND file_sha256 = ?',
            [$assessmentId, $fileHash]
        );
        if ($existing !== null) {
            throw new RuntimeException('This exact export has already been imported into this assessment (import #' . $existing['id'] . ').');
        }

        $root = self::parseSafely($xml);

        $importId = Database::insert('burp_imports', [
            'assessment_id' => $assessmentId,
            'filename'      => mb_substr($filename, 0, 200),
            'file_sha256'   => $fileHash,
            'issue_count'   => 0,
            'burp_version'  => mb_substr((string) ($root['burpVersion'] ?? ''), 0, 40),
            'export_time'   => mb_substr((string) ($root['exportTime'] ?? ''), 0, 60),
            'imported_by'   => Auth::id(),
        ]);

        $ai = new AiService();
        $catalogueByCode = self::catalogueByCode();
        $issues = [];
        $count = 0;

        foreach ($root->issue as $node) {
            $issue = self::readIssue($node);
            if ($issue['name'] === '') {
                continue;
            }
            $count++;

            $vulnClass = self::classify($issue['name']);
            $confidence = $vulnClass !== null ? 1.0 : 0.0;

            // Fall back to the offline classifier when the name is unfamiliar.
            if ($vulnClass === null) {
                $text = $issue['name'] . ' ' . strip_tags($issue['issue_detail']) . ' ' . strip_tags($issue['issue_background']);
                $prediction = $ai->classifier()->predict($text, 1);
                if ($prediction['label'] !== null && $prediction['confidence'] >= 0.30) {
                    $vulnClass = $prediction['label'];
                    $confidence = (float) $prediction['confidence'];
                }
            }

            $code = $vulnClass !== null ? (self::CLASS_TO_CODE[$vulnClass] ?? null) : null;
            $catalogId = $code !== null ? ($catalogueByCode[$code] ?? null) : null;

            $issueId = Database::insert('burp_issues', [
                'import_id'              => $importId,
                'assessment_id'          => $assessmentId,
                'serial_number'          => mb_substr($issue['serial'], 0, 64),
                'issue_type'             => mb_substr($issue['type'], 0, 40),
                'name'                   => mb_substr($issue['name'], 0, 220),
                'host'                   => mb_substr($issue['host'], 0, 200),
                'path'                   => mb_substr($issue['path'], 0, 255),
                'location'               => mb_substr($issue['location'], 0, 255),
                'burp_severity'          => mb_substr($issue['severity'], 0, 24),
                'burp_confidence'        => mb_substr($issue['confidence'], 0, 24),
                'issue_background'       => $issue['issue_background'],
                'issue_detail'           => $issue['issue_detail'],
                'remediation_background' => $issue['remediation_background'],
                'request_text'           => $issue['request'],
                'response_text'          => $issue['response'],
                'mapped_catalog_id'      => $catalogId,
                'ai_category'            => $vulnClass,
                'ai_confidence'          => $confidence,
                'action'                 => 'pending',
            ]);

            $issues[] = [
                'id'            => $issueId,
                'name'          => $issue['name'],
                'host'          => $issue['host'],
                'path'          => $issue['path'],
                'location'      => $issue['location'],
                'burp_severity' => $issue['severity'],
                'ai_category'   => $vulnClass,
                'ai_confidence' => round($confidence, 3),
                'catalog_code'  => $code,
                'has_request'   => $issue['request'] !== '',
                'has_response'  => $issue['response'] !== '',
            ];
        }

        Database::update('burp_imports', ['issue_count' => $count], 'id = ?', [$importId]);
        Audit::log('burp.imported', 'burp_import', $importId, [
            'filename' => $filename, 'issues' => $count, 'sha256' => $fileHash,
        ], $assessmentId);

        return [
            'import_id'    => $importId,
            'issue_count'  => $count,
            'burp_version' => (string) ($root['burpVersion'] ?? ''),
            'export_time'  => (string) ($root['exportTime'] ?? ''),
            'issues'       => $issues,
        ];
    }

    /**
     * Promotes selected Burp issues into platform findings, attaching the
     * captured request and response as evidence.
     *
     * @param  array<int,int> $issueIds
     * @return array{created:int,skipped:int,findings:array<int,array<string,mixed>>}
     */
    public static function promote(int $assessmentId, array $issueIds): array
    {
        $created = 0;
        $skipped = 0;
        $findings = [];

        foreach ($issueIds as $issueId) {
            $issue = Database::one(
                'SELECT * FROM burp_issues WHERE id = ? AND assessment_id = ?',
                [(int) $issueId, $assessmentId]
            );
            if ($issue === null || $issue['action'] === 'imported') {
                $skipped++;
                continue;
            }

            $vulnClass = (string) ($issue['ai_category'] ?? 'Security Misconfiguration');
            [$likelihood, $impact] = self::severityToMatrix((string) $issue['burp_severity'], (string) $issue['burp_confidence']);

            $vector = RiskEngine::suggestVector($vulnClass);
            $risk = RiskEngine::evaluate($likelihood, $impact, $vector);

            $description = trim(
                self::htmlToText((string) $issue['issue_detail']) . "\n\n"
                . self::htmlToText((string) $issue['issue_background'])
            );

            $finding = FindingService::create($assessmentId, [
                'title'              => 'Burp: ' . $issue['name'],
                'vuln_class'         => $vulnClass,
                'cwe_id'             => RiskEngine::cweFor($vulnClass),
                'owasp_top10'        => RiskEngine::owaspFor($vulnClass),
                'affected_component' => (string) $issue['location'],
                'affected_url'       => rtrim((string) $issue['host'], '/') . (string) $issue['path'],
                'description'        => $description !== '' ? $description : (string) $issue['name'],
                'reproduction_steps' => "Imported from a Burp Suite issue export. The captured request and response are attached as evidence.\n"
                    . 'Burp severity: ' . $issue['burp_severity'] . ' / confidence: ' . $issue['burp_confidence'],
                'likelihood'         => $likelihood,
                'impact'             => $impact,
                'cvss_vector'        => $vector,
                'confidence'         => match (strtolower((string) $issue['burp_confidence'])) {
                    'certain' => 'confirmed', 'firm' => 'probable', default => 'tentative',
                },
                'status'             => 'open',
            ]);

            // Attach the traffic that proves it.
            foreach ([['http_request', 'Burp request', (string) $issue['request_text']],
                      ['http_response', 'Burp response', (string) $issue['response_text']]] as [$type, $label, $content]) {
                if (trim($content) === '') {
                    continue;
                }
                EvidenceService::captureText($assessmentId, [
                    'evidence_type' => $type,
                    'title'         => $label . ' - ' . mb_substr((string) $issue['name'], 0, 120),
                    'description'   => 'Captured by Burp Suite and imported with the issue export.',
                    'content_text'  => $content,
                    'finding_id'    => $finding['id'],
                ]);
            }

            Database::update('burp_issues', [
                'action'            => 'imported',
                'mapped_finding_id' => $finding['id'],
            ], 'id = ?', [(int) $issueId]);

            $created++;
            $findings[] = [
                'id'       => $finding['id'],
                'ref_code' => $finding['ref_code'],
                'title'    => $finding['title'],
                'severity' => $risk['severity'],
            ];
        }

        Audit::log('burp.promoted', 'assessment', $assessmentId, ['created' => $created, 'skipped' => $skipped], $assessmentId);
        return ['created' => $created, 'skipped' => $skipped, 'findings' => $findings];
    }

    // =======================================================================
    // Parsing
    // =======================================================================

    private static function parseSafely(string $xml): \SimpleXMLElement
    {
        // Reject entity declarations outright - the cheapest defence against
        // XXE and billion-laughs, and no legitimate Burp export needs them.
        if (preg_match('/<!ENTITY/i', $xml)) {
            throw new RuntimeException('The XML declares entities and was refused. Re-export from Burp without modification.');
        }

        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();

        $root = simplexml_load_string(
            $xml,
            \SimpleXMLElement::class,
            LIBXML_NONET | LIBXML_NOCDATA | LIBXML_NOERROR | LIBXML_NOWARNING
        );

        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($root === false) {
            $first = $errors[0]->message ?? 'unknown parse error';
            throw new RuntimeException('Could not parse the XML: ' . trim($first));
        }
        if ($root->getName() !== 'issues') {
            throw new RuntimeException('This does not look like a Burp Suite issue export (root element is <' . $root->getName() . '>, expected <issues>).');
        }
        return $root;
    }

    /** @return array<string,string> */
    private static function readIssue(\SimpleXMLElement $node): array
    {
        return [
            'serial'                 => trim((string) $node->serialNumber),
            'type'                   => trim((string) $node->type),
            'name'                   => trim((string) $node->name),
            'host'                   => trim((string) $node->host),
            'path'                   => trim((string) $node->path),
            'location'               => trim((string) $node->location),
            'severity'               => trim((string) $node->severity),
            'confidence'             => trim((string) $node->confidence),
            'issue_background'       => trim((string) $node->issueBackground),
            'issue_detail'           => trim((string) $node->issueDetail),
            'remediation_background' => trim((string) $node->remediationBackground),
            'request'                => self::readTraffic($node, 'request'),
            'response'               => self::readTraffic($node, 'response'),
        ];
    }

    private static function readTraffic(\SimpleXMLElement $node, string $which): string
    {
        if (!isset($node->requestresponse)) {
            return '';
        }
        $element = $node->requestresponse->{$which} ?? null;
        if ($element === null) {
            return '';
        }
        $raw = (string) $element;
        if (strtolower((string) ($element['base64'] ?? '')) === 'true') {
            $decoded = base64_decode($raw, true);
            $raw = $decoded === false ? '' : $decoded;
        }
        // Keep captures bounded; a full binary response body is not evidence.
        if (strlen($raw) > 200000) {
            $raw = substr($raw, 0, 200000) . "\n\n[truncated at 200 KB by the import]";
        }
        return self::toUtf8($raw);
    }

    private static function classify(string $name): ?string
    {
        $lower = mb_strtolower($name);
        foreach (self::NAME_MAP as $needle => $class) {
            if (str_contains($lower, $needle)) {
                return $class;
            }
        }
        return null;
    }

    /**
     * Maps Burp severity and confidence onto the platform likelihood/impact
     * inputs. Confidence drives likelihood because a "Certain" Burp issue is
     * one it has already proven; severity drives impact.
     *
     * @return array{0:int,1:int}
     */
    private static function severityToMatrix(string $severity, string $confidence): array
    {
        $impact = match (strtolower($severity)) {
            'high'          => 5,
            'medium'        => 4,
            'low'           => 3,
            'information'   => 2,
            default         => 3,
        };
        $likelihood = match (strtolower($confidence)) {
            'certain'   => 5,
            'firm'      => 4,
            'tentative' => 3,
            default     => 3,
        };
        // Informational issues should not become high risk on confidence alone.
        if ($impact <= 2) {
            $likelihood = min($likelihood, 3);
        }
        return [$likelihood, $impact];
    }

    /** @return array<string,int> code => catalog id */
    private static function catalogueByCode(): array
    {
        $map = [];
        foreach (Database::all('SELECT id, code FROM test_catalog') as $row) {
            $map[(string) $row['code']] = (int) $row['id'];
        }
        return $map;
    }

    private static function htmlToText(string $html): string
    {
        $text = preg_replace('~<\s*br\s*/?>~i', "\n", $html) ?? $html;
        $text = preg_replace('~</\s*(p|li|div|h[1-6])\s*>~i', "\n", $text) ?? $text;
        $text = strip_tags($text);
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = preg_replace("/\n{3,}/", "\n\n", $text) ?? $text;
        return trim($text);
    }

    private static function toUtf8(string $raw): string
    {
        if (mb_check_encoding($raw, 'UTF-8')) {
            return $raw;
        }
        $converted = @mb_convert_encoding($raw, 'UTF-8', 'ISO-8859-1');
        return is_string($converted) ? $converted : preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '.', $raw) ?? '';
    }
}
