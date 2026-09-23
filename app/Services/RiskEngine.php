<?php

declare(strict_types=1);

namespace App\Services;

use App\Core\Config;
use App\Core\Database;
use InvalidArgumentException;

/**
 * Transparent risk calculation.
 *
 * Two independent, fully explainable inputs:
 *
 *   1. Qualitative 5x5 matrix. Likelihood x Impact is looked up in the
 *      risk_matrix table, which an administrator can edit and which the report
 *      prints in full. Nothing is hidden in code.
 *
 *   2. CVSS v3.1 base score, implemented exactly as specified in the
 *      first.org specification, including the integer-arithmetic Roundup
 *      function that trips up most hand-rolled implementations.
 *
 * The severity_strategy setting decides which one wins: 'matrix', 'cvss', or
 * 'higher_of' (default - the more conservative of the two). Every calculation
 * returns a rationale string that is stored on the finding and reproduced in
 * the report, so a reader can re-derive the severity by hand.
 */
final class RiskEngine
{
    public const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

    private const AV = ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.20];
    private const AC = ['L' => 0.77, 'H' => 0.44];
    private const PR_UNCHANGED = ['N' => 0.85, 'L' => 0.62, 'H' => 0.27];
    private const PR_CHANGED   = ['N' => 0.85, 'L' => 0.68, 'H' => 0.50];
    private const UI = ['N' => 0.85, 'R' => 0.62];
    private const CIA = ['H' => 0.56, 'L' => 0.22, 'N' => 0.00];

    private const METRIC_NAMES = [
        'AV' => 'Attack Vector', 'AC' => 'Attack Complexity', 'PR' => 'Privileges Required',
        'UI' => 'User Interaction', 'S' => 'Scope', 'C' => 'Confidentiality',
        'I' => 'Integrity', 'A' => 'Availability',
    ];

    private const METRIC_VALUES = [
        'AV' => ['N' => 'Network', 'A' => 'Adjacent', 'L' => 'Local', 'P' => 'Physical'],
        'AC' => ['L' => 'Low', 'H' => 'High'],
        'PR' => ['N' => 'None', 'L' => 'Low', 'H' => 'High'],
        'UI' => ['N' => 'None', 'R' => 'Required'],
        'S'  => ['U' => 'Unchanged', 'C' => 'Changed'],
        'C'  => ['H' => 'High', 'L' => 'Low', 'N' => 'None'],
        'I'  => ['H' => 'High', 'L' => 'Low', 'N' => 'None'],
        'A'  => ['H' => 'High', 'L' => 'Low', 'N' => 'None'],
    ];

    // =======================================================================
    // CVSS v3.1
    // =======================================================================

    /**
     * @return array{
     *   vector:string, base_score:float, band:string, impact_subscore:float,
     *   exploitability_subscore:float, metrics:array<string,string>,
     *   metrics_readable:array<string,string>, valid:bool, error:string|null
     * }
     */
    public static function cvss(string $vector): array
    {
        $failure = [
            'vector' => $vector, 'base_score' => 0.0, 'band' => 'info',
            'impact_subscore' => 0.0, 'exploitability_subscore' => 0.0,
            'metrics' => [], 'metrics_readable' => [], 'valid' => false, 'error' => null,
        ];

        try {
            $metrics = self::parseVector($vector);
        } catch (InvalidArgumentException $e) {
            $failure['error'] = $e->getMessage();
            return $failure;
        }

        $scopeChanged = $metrics['S'] === 'C';

        $c = self::CIA[$metrics['C']];
        $i = self::CIA[$metrics['I']];
        $a = self::CIA[$metrics['A']];

        // ISS = 1 - [ (1 - C) x (1 - I) x (1 - A) ]
        $iss = 1 - ((1 - $c) * (1 - $i) * (1 - $a));

        $impact = $scopeChanged
            ? 7.52 * ($iss - 0.029) - 3.25 * (($iss - 0.02) ** 15)
            : 6.42 * $iss;

        $prTable = $scopeChanged ? self::PR_CHANGED : self::PR_UNCHANGED;
        $exploitability = 8.22
            * self::AV[$metrics['AV']]
            * self::AC[$metrics['AC']]
            * $prTable[$metrics['PR']]
            * self::UI[$metrics['UI']];

        if ($impact <= 0) {
            $base = 0.0;
        } elseif ($scopeChanged) {
            $base = self::roundUp(min(1.08 * ($impact + $exploitability), 10.0));
        } else {
            $base = self::roundUp(min($impact + $exploitability, 10.0));
        }

        $readable = [];
        foreach ($metrics as $key => $value) {
            $readable[self::METRIC_NAMES[$key]] = self::METRIC_VALUES[$key][$value];
        }

        return [
            'vector'                  => self::canonicalVector($metrics),
            'base_score'              => $base,
            'band'                    => self::bandForCvss($base),
            'impact_subscore'         => round($impact, 2),
            'exploitability_subscore' => round($exploitability, 2),
            'metrics'                 => $metrics,
            'metrics_readable'        => $readable,
            'valid'                   => true,
            'error'                   => null,
        ];
    }

    /**
     * CVSS v3.1 Roundup, specified with integer arithmetic precisely because
     * floating point round() gives the wrong answer at the boundaries.
     */
    public static function roundUp(float $input): float
    {
        $intInput = (int) round($input * 100000);
        if ($intInput % 10000 === 0) {
            return $intInput / 100000;
        }
        return (floor($intInput / 10000) + 1) / 10.0;
    }

    /** @return array<string,string> */
    private static function parseVector(string $vector): array
    {
        $vector = trim($vector);
        if ($vector === '') {
            throw new InvalidArgumentException('Empty CVSS vector.');
        }
        $parts = explode('/', $vector);
        $first = array_shift($parts);
        if (!in_array(strtoupper((string) $first), ['CVSS:3.1', 'CVSS:3.0'], true)) {
            throw new InvalidArgumentException('Vector must start with CVSS:3.1/ or CVSS:3.0/.');
        }

        $metrics = [];
        foreach ($parts as $part) {
            if (!str_contains($part, ':')) {
                continue;
            }
            [$key, $value] = explode(':', $part, 2);
            $key = strtoupper(trim($key));
            $value = strtoupper(trim($value));
            if (!isset(self::METRIC_VALUES[$key])) {
                continue;                                  // temporal/environmental metrics ignored
            }
            if (!isset(self::METRIC_VALUES[$key][$value])) {
                throw new InvalidArgumentException("Invalid value '$value' for metric $key.");
            }
            $metrics[$key] = $value;
        }

        foreach (array_keys(self::METRIC_NAMES) as $required) {
            if (!isset($metrics[$required])) {
                throw new InvalidArgumentException("Missing required base metric $required.");
            }
        }
        return $metrics;
    }

    /** @param array<string,string> $metrics */
    private static function canonicalVector(array $metrics): string
    {
        $order = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
        $parts = ['CVSS:3.1'];
        foreach ($order as $key) {
            $parts[] = $key . ':' . $metrics[$key];
        }
        return implode('/', $parts);
    }

    public static function bandForCvss(float $score): string
    {
        if ($score >= 9.0) return 'critical';
        if ($score >= 7.0) return 'high';
        if ($score >= 4.0) return 'medium';
        if ($score > 0.0)  return 'low';
        return 'info';
    }

    // =======================================================================
    // Qualitative matrix
    // =======================================================================

    /**
     * @return array{likelihood:int,impact:int,score:int,band:string,colour:string,source:string}
     */
    public static function matrix(int $likelihood, int $impact): array
    {
        $likelihood = max(1, min(5, $likelihood));
        $impact     = max(1, min(5, $impact));

        $row = Database::one(
            'SELECT score, band, colour FROM risk_matrix WHERE likelihood = ? AND impact = ?',
            [$likelihood, $impact]
        );

        if ($row !== null) {
            return [
                'likelihood' => $likelihood,
                'impact'     => $impact,
                'score'      => (int) $row['score'],
                'band'       => (string) $row['band'],
                'colour'     => (string) $row['colour'],
                'source'     => 'risk_matrix table',
            ];
        }

        // Fallback if the table was cleared - documented, not magic.
        $score = $likelihood * $impact;
        $band = match (true) {
            $score >= 20 => 'critical',
            $score >= 12 => 'high',
            $score >= 6  => 'medium',
            $score >= 3  => 'low',
            default      => 'info',
        };
        return [
            'likelihood' => $likelihood, 'impact' => $impact, 'score' => $score,
            'band' => $band, 'colour' => self::colourFor($band), 'source' => 'fallback product rule',
        ];
    }

    /** @return array<int,array<string,mixed>> */
    public static function matrixTable(): array
    {
        $rows = Database::all('SELECT likelihood, impact, score, band, colour FROM risk_matrix ORDER BY likelihood, impact');
        if ($rows !== []) {
            return $rows;
        }
        $out = [];
        for ($l = 1; $l <= 5; $l++) {
            for ($i = 1; $i <= 5; $i++) {
                $cell = self::matrix($l, $i);
                $out[] = ['likelihood' => $l, 'impact' => $i, 'score' => $cell['score'], 'band' => $cell['band'], 'colour' => $cell['colour']];
            }
        }
        return $out;
    }

    // =======================================================================
    // Combined severity decision
    // =======================================================================

    /**
     * @return array{
     *   severity:string, source:string, rationale:string,
     *   matrix:array<string,mixed>, cvss:array<string,mixed>|null,
     *   sla_days:int, rank:int
     * }
     */
    public static function evaluate(int $likelihood, int $impact, ?string $cvssVector = null, ?string $override = null): array
    {
        $matrix = self::matrix($likelihood, $impact);
        $cvss = null;
        if ($cvssVector !== null && trim($cvssVector) !== '') {
            $computed = self::cvss($cvssVector);
            $cvss = $computed['valid'] ? $computed : null;
        }

        $strategy = (string) Config::setting('severity_strategy', 'higher_of');

        if ($override !== null && in_array($override, self::SEVERITIES, true)) {
            $severity = $override;
            $source = 'override';
            $rationale = sprintf(
                'Severity manually set to %s by the assessment lead. Matrix produced %s (L%d x I%d = %d)%s.',
                strtoupper($severity),
                strtoupper($matrix['band']),
                $likelihood,
                $impact,
                $matrix['score'],
                $cvss ? sprintf(' and CVSS v3.1 produced %s (%.1f)', strtoupper($cvss['band']), $cvss['base_score']) : ''
            );
        } elseif ($cvss === null || $strategy === 'matrix') {
            $severity = $matrix['band'];
            $source = 'matrix';
            $rationale = sprintf(
                'Likelihood %d x Impact %d = %d, which the published 5x5 risk matrix maps to %s.%s',
                $likelihood,
                $impact,
                $matrix['score'],
                strtoupper($severity),
                $cvss === null ? ' No CVSS vector was supplied.' : ' Strategy is set to matrix-only.'
            );
        } elseif ($strategy === 'cvss') {
            $severity = $cvss['band'];
            $source = 'cvss';
            $rationale = sprintf(
                'CVSS v3.1 base score %.1f (%s) from %s. Impact sub-score %.2f, exploitability sub-score %.2f.',
                $cvss['base_score'],
                strtoupper($severity),
                $cvss['vector'],
                $cvss['impact_subscore'],
                $cvss['exploitability_subscore']
            );
        } else {
            $matrixRank = self::rank($matrix['band']);
            $cvssRank   = self::rank($cvss['band']);
            if ($cvssRank >= $matrixRank) {
                $severity = $cvss['band'];
                $source = 'cvss';
            } else {
                $severity = $matrix['band'];
                $source = 'matrix';
            }
            $rationale = sprintf(
                'Matrix: L%d x I%d = %d -> %s. CVSS v3.1: %.1f -> %s (%s). Strategy "higher of" selects %s from the %s input.',
                $likelihood,
                $impact,
                $matrix['score'],
                strtoupper($matrix['band']),
                $cvss['base_score'],
                strtoupper($cvss['band']),
                $cvss['vector'],
                strtoupper($severity),
                $source
            );
        }

        return [
            'severity'  => $severity,
            'source'    => $source,
            'rationale' => $rationale,
            'matrix'    => $matrix,
            'cvss'      => $cvss,
            'sla_days'  => self::slaDays($severity),
            'rank'      => self::rank($severity),
        ];
    }

    public static function rank(string $severity): int
    {
        $index = array_search(strtolower($severity), self::SEVERITIES, true);
        return $index === false ? 0 : (int) $index + 1;
    }

    public static function slaDays(string $severity): int
    {
        $row = Database::one('SELECT sla_days FROM severity_sla WHERE severity = ?', [strtolower($severity)]);
        if ($row !== null) {
            return (int) $row['sla_days'];
        }
        return match (strtolower($severity)) {
            'critical' => 7, 'high' => 30, 'medium' => 60, 'low' => 90, default => 180,
        };
    }

    public static function colourFor(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical' => '#dc2626',
            'high'     => '#f97316',
            'medium'   => '#f59e0b',
            'low'      => '#3b82f6',
            default    => '#6b7280',
        };
    }

    /**
     * Suggests a starting CVSS vector for a vulnerability class. The analyst
     * always confirms it; this only saves typing.
     */
    public static function suggestVector(string $vulnClass): string
    {
        return match ($vulnClass) {
            'SQL Injection'                  => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
            'Command Injection'              => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
            'Insecure File Upload'           => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
            'Cross-Site Scripting'           => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            'Path Traversal / File Inclusion' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
            'Cross-Site Request Forgery'     => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
            'Broken Access Control'          => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
            'Broken Authentication'          => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'Session Management'             => 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'Server-Side Request Forgery'    => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
            'Open Redirect'                  => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N',
            'Cryptographic Failure'          => 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'Information Disclosure'         => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'Security Misconfiguration'      => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            'Business Logic Flaw'            => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
            default                          => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        };
    }

    /** CWE reference for a predicted vulnerability class. */
    public static function cweFor(string $vulnClass): string
    {
        return match ($vulnClass) {
            'SQL Injection'                   => 'CWE-89',
            'Cross-Site Scripting'            => 'CWE-79',
            'Command Injection'               => 'CWE-78',
            'Path Traversal / File Inclusion' => 'CWE-22',
            'Cross-Site Request Forgery'      => 'CWE-352',
            'Insecure File Upload'            => 'CWE-434',
            'Broken Authentication'           => 'CWE-287',
            'Session Management'              => 'CWE-384',
            'Broken Access Control'           => 'CWE-284',
            'Open Redirect'                   => 'CWE-601',
            'Security Misconfiguration'       => 'CWE-16',
            'Information Disclosure'          => 'CWE-200',
            'Cryptographic Failure'           => 'CWE-327',
            'Business Logic Flaw'             => 'CWE-840',
            'Server-Side Request Forgery'     => 'CWE-918',
            default                           => 'CWE-693',
        };
    }

    /** OWASP Top 10 2021 reference for a predicted vulnerability class. */
    public static function owaspFor(string $vulnClass): string
    {
        return match ($vulnClass) {
            'SQL Injection', 'Cross-Site Scripting', 'Command Injection' => 'A03:2021 Injection',
            'Path Traversal / File Inclusion', 'Broken Access Control',
            'Cross-Site Request Forgery', 'Open Redirect'                => 'A01:2021 Broken Access Control',
            'Broken Authentication', 'Session Management'                => 'A07:2021 Identification and Authentication Failures',
            'Cryptographic Failure'                                      => 'A02:2021 Cryptographic Failures',
            'Security Misconfiguration', 'Information Disclosure'        => 'A05:2021 Security Misconfiguration',
            'Insecure File Upload', 'Business Logic Flaw'                => 'A04:2021 Insecure Design',
            'Server-Side Request Forgery'                                => 'A10:2021 Server-Side Request Forgery',
            default                                                      => 'A05:2021 Security Misconfiguration',
        };
    }
}
