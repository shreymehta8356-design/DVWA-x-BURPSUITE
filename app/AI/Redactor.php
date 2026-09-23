<?php

declare(strict_types=1);

namespace App\AI;

/**
 * Pattern-based secret and PII redaction for captured evidence.
 *
 * Raw Burp requests and responses routinely carry live session cookies,
 * Authorization headers, API keys and personal data. Those belong in the
 * evidence store no more than they belong in the final report, so text
 * evidence is passed through here on capture. The original SHA-256 is taken
 * before redaction so integrity is still provable, and every substitution is
 * counted and shown to the analyst rather than applied silently.
 *
 * Redaction is deliberately conservative: it preserves the payload and the
 * vulnerable parameter, because that is the part the finding depends on.
 */
final class Redactor
{
    /** @var array<string,string> label => regex */
    private const PATTERNS = [
        'Authorization header' => '/^(Authorization:\s*)(\S.*)$/mi',
        'Cookie header'        => '/^(Cookie:\s*)(.+)$/mi',
        'Set-Cookie value'     => '/^(Set-Cookie:\s*[^=]+=)([^;\r\n]+)/mi',
        'Proxy credentials'    => '/^(Proxy-Authorization:\s*)(\S.*)$/mi',
        'Bearer token'         => '/\b(Bearer\s+)([A-Za-z0-9\-._~+\/]{16,})/i',
        'JWT'                  => '/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/',
        'Password parameter'   => '/\b(password|passwd|pwd|pass|secret|api[_-]?key|apikey|token|access_token|refresh_token)\s*=\s*([^&\s"\'<>]{1,200})/i',
        'JSON password field'  => '/("(?:password|passwd|secret|api_key|apiKey|token|access_token)"\s*:\s*")([^"]{1,200})(")/i',
        'AWS access key'       => '/\b(AKIA|ASIA)[0-9A-Z]{16}\b/',
        'Private key block'    => '/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/',
        'Email address'        => '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/',
        'Payment card number'  => '/\b(?:\d[ -]*?){13,19}\b/',
        'Session identifier'   => '/\b(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|SESSID|sid)=([A-Za-z0-9%._-]{8,})/i',
    ];

    /** Ignore these hosts/values so the redactor does not blank the whole capture. */
    private const SAFE_EMAILS = ['@localhost', '@example.com', '@example.org', '@dvwa.local'];

    /**
     * @return array{text:string, redactions:int, summary:string, breakdown:array<string,int>}
     */
    public static function redact(string $text, bool $redactEmails = true): array
    {
        if (trim($text) === '') {
            return ['text' => $text, 'redactions' => 0, 'summary' => '', 'breakdown' => []];
        }

        $breakdown = [];
        $total = 0;

        foreach (self::PATTERNS as $label => $pattern) {
            if ($label === 'Email address' && !$redactEmails) {
                continue;
            }

            $count = 0;
            $replaced = preg_replace_callback(
                $pattern,
                static function (array $m) use ($label, &$count): string {
                    // Card-number heuristic: only redact when Luhn passes, so
                    // long IDs and timestamps in evidence survive intact.
                    if ($label === 'Payment card number') {
                        $digits = preg_replace('/\D/', '', $m[0]) ?? '';
                        if (strlen($digits) < 13 || !self::luhn($digits)) {
                            return $m[0];
                        }
                        $count++;
                        return '[REDACTED:CARD]';
                    }

                    if ($label === 'Email address') {
                        foreach (self::SAFE_EMAILS as $safe) {
                            if (str_ends_with(strtolower($m[0]), $safe)) {
                                return $m[0];
                            }
                        }
                        $count++;
                        return '[REDACTED:EMAIL]';
                    }

                    $count++;
                    // Preserve the prefix (header or parameter name) so the
                    // evidence still shows WHERE the secret travelled.
                    if (isset($m[3])) {
                        return $m[1] . '[REDACTED]' . $m[3];
                    }
                    if (isset($m[2])) {
                        return $m[1] . '[REDACTED]';
                    }
                    return '[REDACTED]';
                },
                $text
            );

            if ($replaced !== null && $count > 0) {
                $text = $replaced;
                $breakdown[$label] = $count;
                $total += $count;
            }
        }

        $summary = $total === 0
            ? ''
            : $total . ' item(s) redacted: ' . implode(', ', array_map(
                static fn ($k, $v) => "$k x$v",
                array_keys($breakdown),
                array_values($breakdown)
            ));

        return [
            'text'       => $text,
            'redactions' => $total,
            'summary'    => mb_substr($summary, 0, 500),
            'breakdown'  => $breakdown,
        ];
    }

    /** Preview only - reports what would be removed without changing the text. */
    public static function scan(string $text): array
    {
        $result = self::redact($text);
        return ['redactions' => $result['redactions'], 'breakdown' => $result['breakdown'], 'summary' => $result['summary']];
    }

    private static function luhn(string $digits): bool
    {
        $sum = 0;
        $alt = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $n = (int) $digits[$i];
            if ($alt) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $alt = !$alt;
        }
        return $sum % 10 === 0;
    }
}
