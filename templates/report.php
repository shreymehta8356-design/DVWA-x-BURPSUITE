<?php
/**
 * Audit-ready security assessment report.
 *
 * Rendered from the frozen snapshot stored against the report row, never from
 * live tables, so re-opening an old report reproduces exactly what was signed
 * off. Print to PDF from the browser (Ctrl+P) - the print stylesheet handles
 * page breaks, running headers and the classification footer.
 *
 * @var array<string,mixed> $snapshot
 * @var array<string,mixed> $reportMeta
 */

if (!function_exists('rpt_e')) {
    function rpt_e(mixed $value): string
    {
        return htmlspecialchars((string) ($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
    /** Escapes then converts newlines to paragraph breaks. */
    function rpt_p(mixed $value): string
    {
        $text = trim((string) ($value ?? ''));
        if ($text === '') {
            return '<p class="muted">Not recorded.</p>';
        }
        $blocks = preg_split("/\n{2,}/", $text) ?: [$text];
        $html = '';
        foreach ($blocks as $block) {
            $html .= '<p>' . nl2br(rpt_e(trim($block))) . '</p>';
        }
        return $html;
    }
    function rpt_sev(mixed $severity): string
    {
        return 'sev-' . preg_replace('/[^a-z]/', '', strtolower((string) $severity));
    }
    function rpt_date(mixed $value, string $format = 'd M Y'): string
    {
        $ts = strtotime((string) $value);
        return $ts ? date($format, $ts) : '-';
    }
    function rpt_label(mixed $value): string
    {
        return ucwords(str_replace('_', ' ', (string) $value));
    }
}

$a          = $snapshot['assessment'] ?? [];
$meta       = $snapshot['meta'] ?? [];
$stats      = $snapshot['statistics'] ?? [];
$findings   = $snapshot['findings'] ?? [];
$riskModel  = $snapshot['risk_model'] ?? [];
$isExecutive = ($meta['report_type'] ?? 'full') === 'executive';

$sevCounts = [
    'critical' => (int) ($stats['critical'] ?? 0),
    'high'     => (int) ($stats['high'] ?? 0),
    'medium'   => (int) ($stats['medium'] ?? 0),
    'low'      => (int) ($stats['low'] ?? 0),
    'info'     => (int) ($stats['info'] ?? 0),
];
$sevMax = max(1, max($sevCounts));
$totalFindings = array_sum($sevCounts);
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= rpt_e($reportMeta['ref_code'] ?? 'Security Assessment Report') ?></title>
<style>
    /* ------------------------------------------------------------------
       Self-contained stylesheet. No external fonts or assets: the report
       must render identically on a machine with no network connection.
       ------------------------------------------------------------------ */
    :root {
        --ink:#111827; --ink-2:#374151; --muted:#6b7280; --line:#e5e7eb; --line-2:#d1d5db;
        --bg:#ffffff; --bg-2:#f9fafb; --bg-3:#f3f4f6;
        --critical:#b91c1c; --high:#c2410c; --medium:#b45309; --low:#1d4ed8; --info:#4b5563;
        --accent:#0f766e;
    }
    * { box-sizing:border-box; }
    body {
        margin:0; background:var(--bg-3); color:var(--ink);
        font:13px/1.65 "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        -webkit-print-color-adjust:exact; print-color-adjust:exact;
    }
    .page {
        max-width:210mm; margin:0 auto; background:var(--bg); padding:22mm 18mm;
        box-shadow:0 1px 3px rgba(0,0,0,.12);
    }
    h1,h2,h3,h4 { color:var(--ink); font-weight:600; line-height:1.25; margin:0 0 .5em; }
    h1 { font-size:26px; letter-spacing:-.3px; }
    h2 { font-size:19px; margin-top:2.2em; padding-bottom:.35em; border-bottom:2px solid var(--accent); }
    h3 { font-size:15px; margin-top:1.6em; }
    h4 { font-size:13px; margin-top:1.2em; color:var(--ink-2); text-transform:uppercase; letter-spacing:.6px; }
    p  { margin:0 0 .8em; }
    a  { color:var(--accent); }
    .muted { color:var(--muted); }
    .small { font-size:11.5px; }
    code, pre, .mono { font-family:"Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace; font-size:11px; }
    pre {
        background:var(--bg-2); border:1px solid var(--line); border-left:3px solid var(--accent);
        padding:10px 12px; overflow-x:auto; white-space:pre-wrap; word-break:break-word;
        margin:.6em 0; border-radius:3px; max-height:340px;
    }

    /* ---- cover ---- */
    .cover { min-height:250mm; display:flex; flex-direction:column; justify-content:space-between; }
    .cover-top { border-top:6px solid var(--accent); padding-top:22px; }
    .brand { font-size:12px; letter-spacing:3px; text-transform:uppercase; color:var(--accent); font-weight:700; }
    .cover h1 { font-size:34px; margin:26px 0 10px; }
    .cover .subtitle { font-size:16px; color:var(--ink-2); }
    .classification {
        display:inline-block; margin-top:22px; padding:5px 14px; border:1.5px solid var(--critical);
        color:var(--critical); font-weight:700; font-size:11px; letter-spacing:2px; border-radius:3px;
    }
    .cover-meta { width:100%; border-collapse:collapse; margin-top:34px; font-size:12.5px; }
    .cover-meta td { padding:7px 0; border-bottom:1px solid var(--line); vertical-align:top; }
    .cover-meta td:first-child { width:180px; color:var(--muted); font-weight:600; }
    .cover-note {
        margin-top:26px; padding:12px 14px; background:var(--bg-2); border:1px solid var(--line);
        border-radius:4px; font-size:11.5px; color:var(--ink-2);
    }

    /* ---- tables ---- */
    table.data { width:100%; border-collapse:collapse; margin:.8em 0 1.2em; font-size:12px; }
    table.data th, table.data td { border:1px solid var(--line); padding:7px 9px; text-align:left; vertical-align:top; }
    table.data th { background:var(--bg-2); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:var(--ink-2); }
    table.data tr:nth-child(even) td { background:#fcfcfd; }
    table.data td.num { text-align:right; font-variant-numeric:tabular-nums; }

    /* ---- severity ---- */
    .badge {
        display:inline-block; padding:2px 8px; border-radius:3px; font-size:10px; font-weight:700;
        letter-spacing:.7px; text-transform:uppercase; color:#fff; white-space:nowrap;
    }
    .sev-critical{background:var(--critical)} .sev-high{background:var(--high)}
    .sev-medium{background:var(--medium)} .sev-low{background:var(--low)} .sev-info{background:var(--info)}
    .badge-outline { background:transparent; border:1px solid var(--line-2); color:var(--ink-2); }

    /* ---- summary chart (hand-drawn, no library) ---- */
    .sev-chart { margin:1em 0 1.4em; break-inside:avoid-page; page-break-inside:avoid; }
    .sev-row { display:flex; align-items:center; gap:10px; margin-bottom:6px; }
    .sev-row .name { width:92px; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.5px; }
    .sev-row .track { flex:1; height:18px; background:var(--bg-3); border-radius:2px; overflow:hidden; }
    .sev-row .fill { height:100%; }
    .sev-row .count { width:34px; text-align:right; font-weight:700; font-variant-numeric:tabular-nums; }

    .kpis { display:flex; flex-wrap:wrap; gap:10px; margin:1em 0 1.4em; }
    .kpi { flex:1 1 118px; border:1px solid var(--line); border-radius:4px; padding:10px 12px; background:var(--bg-2); }
    .kpi .v { font-size:22px; font-weight:700; line-height:1.1; }
    .kpi .l { font-size:10px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted); margin-top:3px; }

    /* ---- matrix ---- */
    table.matrix { border-collapse:collapse; margin:1em 0; font-size:11px; }
    table.matrix td, table.matrix th { border:1px solid var(--line-2); padding:6px 8px; text-align:center; min-width:74px; }
    table.matrix th { background:var(--bg-2); font-size:10px; text-transform:uppercase; letter-spacing:.4px; }
    table.matrix td.cell { color:#fff; font-weight:700; font-size:10px; letter-spacing:.4px; }

    /* ---- findings ---- */
    .finding { margin-top:2.2em; border:1px solid var(--line); border-radius:5px; overflow:hidden; break-inside:avoid-page; }
    .finding > header {
        display:flex; align-items:flex-start; justify-content:space-between; gap:14px;
        padding:11px 14px; background:var(--bg-2); border-bottom:1px solid var(--line);
    }
    .finding > header h3 { margin:0; font-size:14.5px; }
    .finding > header .ref { font-size:10.5px; color:var(--muted); letter-spacing:1px; font-weight:700; }
    .finding .body { padding:14px; }
    .finding .facts { width:100%; border-collapse:collapse; font-size:11.5px; margin-bottom:1em; }
    .finding .facts td { padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
    .finding .facts td:first-child { width:150px; color:var(--muted); font-weight:600; }
    .rationale {
        background:#f0fdfa; border:1px solid #99f6e4; border-left:3px solid var(--accent);
        padding:9px 12px; border-radius:3px; font-size:11.5px; margin:.7em 0;
    }
    .evidence-item { border:1px solid var(--line); border-radius:4px; margin:.7em 0; overflow:hidden; }
    .evidence-item > .eh {
        background:var(--bg-2); padding:6px 10px; font-size:11px; display:flex;
        justify-content:space-between; gap:10px; border-bottom:1px solid var(--line); flex-wrap:wrap;
    }
    .evidence-item .hash { font-family:"Cascadia Mono",Consolas,monospace; font-size:10px; color:var(--muted); word-break:break-all; }
    .evidence-item .eb { padding:8px 10px; }
    .custody { font-size:10.5px; color:var(--muted); margin-top:5px; }
    .custody span { margin-right:12px; }

    .callout { padding:11px 14px; border-radius:4px; border:1px solid; margin:1em 0; font-size:12px; }
    .callout.ok   { background:#f0fdf4; border-color:#bbf7d0; color:#14532d; }
    .callout.warn { background:#fffbeb; border-color:#fde68a; color:#78350f; }
    .callout.bad  { background:#fef2f2; border-color:#fecaca; color:#7f1d1d; }
    .callout.note { background:var(--bg-2); border-color:var(--line); color:var(--ink-2); }

    ol.toc { list-style:none; padding:0; counter-reset:toc; font-size:12.5px; }
    ol.toc li { counter-increment:toc; padding:5px 0; border-bottom:1px dotted var(--line); }
    ol.toc li::before { content:counter(toc) ". "; color:var(--muted); font-weight:600; }

    .sig-grid { display:flex; gap:24px; margin-top:2em; flex-wrap:wrap; }
    .sig { flex:1 1 200px; border-top:1px solid var(--ink-2); padding-top:6px; font-size:11px; color:var(--muted); }

    .page-break { break-before:page; page-break-before:always; }
    .no-print { }
    .toolbar {
        max-width:210mm; margin:14px auto 0; display:flex; gap:8px; justify-content:flex-end;
    }
    .toolbar button, .toolbar a {
        font:inherit; font-size:12px; padding:7px 14px; border:1px solid var(--line-2); border-radius:4px;
        background:#fff; color:var(--ink); cursor:pointer; text-decoration:none;
    }
    .toolbar button.primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }

    @media print {
        body { background:#fff; }
        .page { box-shadow:none; max-width:none; margin:0; padding:0; }
        .no-print, .toolbar { display:none !important; }
        h2 { break-after:avoid-page; }
        .finding, .evidence-item, table.data tr, .sev-chart, .kpis { break-inside:avoid-page; }
        pre { max-height:none; }
        @page {
            size:A4; margin:16mm 14mm 18mm;
            @bottom-center { content:"<?= rpt_e($meta['footer'] ?? 'CONFIDENTIAL') ?>"; font-size:9pt; color:#6b7280; }
        }
    }
</style>
</head>
<body>

<div class="toolbar no-print">
    <button class="primary" onclick="window.print()">Print / Save as PDF</button>
    <a href="#findings">Jump to findings</a>
</div>

<!-- ===================== COVER ===================== -->
<div class="page cover">
    <div class="cover-top">
        <div class="brand"><?= rpt_e($meta['organisation'] ?? 'Security Assessment Lab') ?></div>
        <h1><?= rpt_e($reportMeta['title'] ?? 'Web Application Security Assessment') ?></h1>
        <div class="subtitle"><?= rpt_e($a['target_name'] ?? '') ?> &mdash; <?= rpt_e($a['target_base_url'] ?? '') ?></div>
        <div class="classification"><?= rpt_e($a['classification'] ?? 'INTERNAL') ?></div>

        <table class="cover-meta">
            <tr><td>Report reference</td><td class="mono"><?= rpt_e($reportMeta['ref_code'] ?? '') ?></td></tr>
            <tr><td>Assessment reference</td><td class="mono"><?= rpt_e($a['ref_code'] ?? '') ?></td></tr>
            <tr><td>Report type</td><td><?= rpt_label($meta['report_type'] ?? 'full') ?> report, version <?= rpt_e($reportMeta['version'] ?? '1.0') ?> (<?= rpt_e($reportMeta['status'] ?? 'draft') ?>)</td></tr>
            <tr><td>Target environment</td><td><?= rpt_label($a['environment'] ?? 'local_lab') ?></td></tr>
            <tr><td>Methodology</td><td><?= rpt_e($a['methodology'] ?? 'OWASP WSTG v4.2') ?></td></tr>
            <tr><td>Testing window</td><td><?= rpt_date($a['start_date'] ?? null) ?> &ndash; <?= rpt_date($a['end_date'] ?? null) ?></td></tr>
            <tr><td>Lead analyst</td><td><?= rpt_e($a['lead_analyst'] ?? 'Not assigned') ?></td></tr>
            <tr><td>Generated</td><td><?= rpt_date($meta['generated_at'] ?? null, 'd M Y \a\t H:i') ?> by <?= rpt_e($meta['generated_by_name'] ?: ($meta['generated_by'] ?? 'system')) ?></td></tr>
            <tr><td>Snapshot SHA-256</td><td class="mono" style="word-break:break-all"><?= rpt_e($reportMeta['sha256'] ?? '') ?></td></tr>
        </table>

        <div class="cover-note">
            <strong>About this document.</strong> This report is generated from a frozen snapshot of the assessment
            record. Every finding below carries the evidence hashes, the risk derivation and the retest history that
            produced it, so each conclusion can be independently re-checked against the platform record. The SHA-256
            above covers the entire snapshot; if a single character of this report is altered, that hash no longer
            matches.
        </div>
    </div>

    <div class="small muted" style="border-top:1px solid var(--line); padding-top:10px;">
        <?= rpt_e($meta['footer'] ?? 'CONFIDENTIAL') ?> &middot;
        Produced with <?= rpt_e($meta['platform'] ?? 'DVWA x BURPSUITE') ?> &middot;
        Offline assessment platform &middot; Page 1
    </div>
</div>

<!-- ===================== CONTENTS + SUMMARY ===================== -->
<div class="page page-break">
    <h2 style="margin-top:0">1. Contents</h2>
    <ol class="toc">
        <li>Contents</li>
        <li>Executive summary</li>
        <li>Scope and rules of engagement</li>
        <li>Methodology</li>
        <li>Risk rating model</li>
        <li>Findings summary</li>
        <li>Detailed findings</li>
        <?php if (!$isExecutive): ?>
        <li>Security check log</li>
        <?php endif; ?>
        <li>Remediation tracker</li>
        <li>Assurance, AI usage and record integrity</li>
    </ol>

    <h2>2. Executive summary</h2>
    <?= rpt_p($snapshot['executive_summary']['text'] ?? '') ?>
    <?php if (($snapshot['executive_summary']['fallback'] ?? true) === false): ?>
        <p class="small muted">Narrative drafted with the locally hosted assistant
        (<?= rpt_e($snapshot['executive_summary']['model'] ?? '') ?>) and reviewed by the named analyst before inclusion.</p>
    <?php endif; ?>

    <div class="kpis">
        <div class="kpi"><div class="v"><?= (int) ($stats['tests_executed'] ?? 0) ?>/<?= (int) ($stats['tests_total'] ?? 0) ?></div><div class="l">Checks executed</div></div>
        <div class="kpi"><div class="v"><?= $totalFindings ?></div><div class="l">Findings raised</div></div>
        <div class="kpi"><div class="v" style="color:var(--critical)"><?= $sevCounts['critical'] + $sevCounts['high'] ?></div><div class="l">Critical &amp; high</div></div>
        <div class="kpi"><div class="v"><?= (int) ($stats['resolved'] ?? 0) ?></div><div class="l">Resolved &amp; retested</div></div>
        <div class="kpi"><div class="v"><?= (int) ($stats['evidence_count'] ?? 0) ?></div><div class="l">Evidence items</div></div>
        <div class="kpi"><div class="v"><?= (int) ($stats['risk_score'] ?? 0) ?></div><div class="l">Posture score /100</div></div>
    </div>

    <h3>Findings by severity</h3>
    <div class="sev-chart">
        <?php foreach ($sevCounts as $severity => $count):
            $width = $count > 0 ? max(3, (int) round($count / $sevMax * 100)) : 0; ?>
        <div class="sev-row">
            <div class="name"><?= rpt_e($severity) ?></div>
            <div class="track"><div class="fill <?= rpt_sev($severity) ?>" style="width:<?= $width ?>%"></div></div>
            <div class="count"><?= $count ?></div>
        </div>
        <?php endforeach; ?>
    </div>

    <h2>3. Scope and rules of engagement</h2>
    <h4>Objective</h4>
    <?= rpt_p($a['objective'] ?? '') ?>
    <h4>Scope</h4>
    <?php $scope = $a['scope'] ?? []; if ($scope === []): ?>
        <p class="muted">No explicit scope items were recorded; the target base URL defines the scope.</p>
    <?php else: ?>
    <table class="data">
        <thead><tr><th style="width:110px">Type</th><th>Value</th><th style="width:90px">In scope</th><th>Notes</th></tr></thead>
        <tbody>
        <?php foreach ($scope as $item): ?>
            <tr>
                <td><?= rpt_label($item['item_type'] ?? '') ?></td>
                <td class="mono"><?= rpt_e($item['value'] ?? '') ?></td>
                <td><?= ((int) ($item['in_scope'] ?? 0) === 1)
                        ? '<span class="badge" style="background:#15803d">In scope</span>'
                        : '<span class="badge badge-outline">Excluded</span>' ?></td>
                <td class="small"><?= rpt_e($item['notes'] ?? '') ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <h4>Rules of engagement</h4>
    <?= rpt_p($a['rules_of_engagement'] ?? '') ?>
    <?php if (trim((string) ($a['constraints'] ?? '')) !== ''): ?>
        <h4>Constraints and limitations</h4>
        <?= rpt_p($a['constraints']) ?>
    <?php endif; ?>

    <h2>4. Methodology</h2>
    <p>
        Testing followed <strong><?= rpt_e($a['methodology'] ?? 'the OWASP Web Security Testing Guide v4.2') ?></strong>.
        Each predefined check in the plan was executed manually against the target with an intercepting proxy, and the
        outcome recorded as PASS, FAIL, MANUAL REVIEW or NOT APPLICABLE together with the observation and the captured
        traffic that supports it. Failing checks were promoted to findings, rated using the model in section 5, given a
        remediation recommendation and an owner, and retested after the fix was reported.
    </p>
    <p>
        The workflow enforced by the platform is:
        <strong>Assessment &rarr; Security Check &rarr; Result &rarr; Evidence &rarr; Finding &rarr; Risk &rarr;
        Remediation &rarr; Retest &rarr; Report.</strong>
        No stage can be skipped: a finding cannot be marked resolved without a retest recording a fixed result, and a
        report cannot be finalised while checks remain unexecuted.
    </p>
    <?php if (!empty($snapshot['coverage'])): ?>
    <h3>Coverage by category</h3>
    <table class="data">
        <thead><tr><th>Category</th><th class="num">Checks</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Manual review</th><th class="num">N/A</th><th class="num">Executed</th></tr></thead>
        <tbody>
        <?php foreach ($snapshot['coverage'] as $row): ?>
            <tr>
                <td><?= rpt_e($row['category'] ?? '') ?></td>
                <td class="num"><?= (int) ($row['total'] ?? 0) ?></td>
                <td class="num"><?= (int) ($row['pass'] ?? 0) ?></td>
                <td class="num"><?= (int) ($row['fail'] ?? 0) ?></td>
                <td class="num"><?= (int) ($row['manual_review'] ?? 0) ?></td>
                <td class="num"><?= (int) ($row['not_applicable'] ?? 0) ?></td>
                <td class="num"><?= (int) ($row['progress'] ?? 0) ?>%</td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>

<!-- ===================== RISK MODEL ===================== -->
<div class="page page-break">
    <h2 style="margin-top:0">5. Risk rating model</h2>
    <p>
        Severity is derived from two independent inputs and the strategy in force for this assessment was
        <strong><?= rpt_label($riskModel['strategy'] ?? 'higher_of') ?></strong>.
        Both inputs are printed for every finding so any rating can be re-derived by hand.
    </p>

    <h3>5.1 Qualitative matrix</h3>
    <p class="small">Likelihood (rows) against impact (columns). The numeric score is the product, used for ordering; the band shown in the cell is the published rating.</p>
    <?php
    $matrix = [];
    foreach (($riskModel['matrix'] ?? []) as $cell) {
        $matrix[(int) $cell['likelihood']][(int) $cell['impact']] = $cell;
    }
    if ($matrix !== []): ?>
    <table class="matrix">
        <thead>
            <tr><th>Likelihood \ Impact</th><th>1 Insignificant</th><th>2 Minor</th><th>3 Moderate</th><th>4 Major</th><th>5 Severe</th></tr>
        </thead>
        <tbody>
        <?php for ($l = 5; $l >= 1; $l--): ?>
            <tr>
                <th><?= $l ?> <?= ['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost certain'][$l] ?></th>
                <?php for ($i = 1; $i <= 5; $i++):
                    $cell = $matrix[$l][$i] ?? null; ?>
                    <td class="cell" style="background:<?= rpt_e($cell['colour'] ?? '#6b7280') ?>">
                        <?= rpt_e(strtoupper((string) ($cell['band'] ?? '-'))) ?><br><span style="opacity:.85"><?= (int) ($cell['score'] ?? $l * $i) ?></span>
                    </td>
                <?php endfor; ?>
            </tr>
        <?php endfor; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <h3>5.2 CVSS v3.1</h3>
    <p class="small">
        Where a vector was recorded, the CVSS v3.1 base score was computed from the published specification
        (impact and exploitability sub-scores, with the specified round-up). The vector is printed with every
        finding, so the score can be reproduced in any CVSS calculator.
    </p>

    <h3>5.3 Remediation targets</h3>
    <table class="data">
        <thead><tr><th style="width:110px">Severity</th><th style="width:110px">Target</th><th>Definition</th></tr></thead>
        <tbody>
        <?php foreach (($riskModel['sla'] ?? []) as $row): ?>
            <tr>
                <td><span class="badge <?= rpt_sev($row['severity'] ?? '') ?>"><?= rpt_e($row['severity'] ?? '') ?></span></td>
                <td><?= (int) ($row['sla_days'] ?? 0) ?> days</td>
                <td class="small"><?= rpt_e($row['description'] ?? '') ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <h3>5.4 Posture score</h3>
    <p class="small">
        The single posture figure on the cover is <code>100 &minus; min(100, &Sigma; severity weight &times; count)</code>
        with weights
        <?php $w = $riskModel['score_weights'] ?? []; ?>
        critical <?= (int) ($w['critical'] ?? 40) ?>,
        high <?= (int) ($w['high'] ?? 20) ?>,
        medium <?= (int) ($w['medium'] ?? 8) ?>,
        low <?= (int) ($w['low'] ?? 3) ?>,
        informational <?= (int) ($w['info'] ?? 1) ?>.
        It is a communication aid, not a rating in its own right.
    </p>

    <h2>6. Findings summary</h2>
    <?php if ($findings === []): ?>
        <div class="callout ok"><strong>No findings were raised.</strong> Every executed check met its expected secure behaviour.</div>
    <?php else: ?>
    <table class="data">
        <thead>
            <tr>
                <th style="width:58px">Ref</th><th>Finding</th><th style="width:78px">Severity</th>
                <th style="width:52px">CVSS</th><th style="width:104px">Status</th>
                <th style="width:96px">Remediation</th><th style="width:78px">Due</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($findings as $f): ?>
            <tr>
                <td class="mono"><a href="#<?= rpt_e($f['ref_code'] ?? '') ?>"><?= rpt_e($f['ref_code'] ?? '') ?></a></td>
                <td>
                    <?= rpt_e($f['title'] ?? '') ?>
                    <div class="small muted"><?= rpt_e($f['vuln_class'] ?? '') ?><?= !empty($f['cwe_id']) ? ' &middot; ' . rpt_e($f['cwe_id']) : '' ?></div>
                </td>
                <td><span class="badge <?= rpt_sev($f['severity'] ?? '') ?>"><?= rpt_e($f['severity'] ?? '') ?></span></td>
                <td class="num"><?= $f['cvss_base_score'] !== null ? rpt_e(number_format((float) $f['cvss_base_score'], 1)) : '-' ?></td>
                <td class="small"><?= rpt_label($f['status'] ?? '') ?></td>
                <td class="small"><?= rpt_label($f['remediation']['status'] ?? 'not started') ?></td>
                <td class="small"><?= !empty($f['remediation']['due_date']) ? rpt_date($f['remediation']['due_date'], 'd M') : '-' ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>

<!-- ===================== DETAILED FINDINGS ===================== -->
<div class="page page-break" id="findings">
    <h2 style="margin-top:0">7. Detailed findings</h2>
    <?php if ($findings === []): ?>
        <p class="muted">No findings to detail.</p>
    <?php endif; ?>

    <?php foreach ($findings as $f): ?>
    <article class="finding" id="<?= rpt_e($f['ref_code'] ?? '') ?>">
        <header>
            <div>
                <div class="ref"><?= rpt_e($f['ref_code'] ?? '') ?></div>
                <h3><?= rpt_e($f['title'] ?? '') ?></h3>
            </div>
            <div style="text-align:right; white-space:nowrap">
                <span class="badge <?= rpt_sev($f['severity'] ?? '') ?>"><?= rpt_e($f['severity'] ?? '') ?></span>
                <?php if ($f['cvss_base_score'] !== null): ?>
                    <div class="small muted" style="margin-top:4px">CVSS <?= rpt_e(number_format((float) $f['cvss_base_score'], 1)) ?></div>
                <?php endif; ?>
            </div>
        </header>
        <div class="body">
            <table class="facts">
                <tr><td>Vulnerability class</td><td><?= rpt_e($f['vuln_class'] ?? 'Not classified') ?></td></tr>
                <tr><td>References</td><td><?= rpt_e($f['cwe_id'] ?? '-') ?> &middot; <?= rpt_e($f['owasp_top10'] ?? '-') ?><?= !empty($f['test_code']) ? ' &middot; ' . rpt_e($f['test_code']) : '' ?></td></tr>
                <tr><td>Affected component</td><td><?= rpt_e($f['affected_component'] ?? '-') ?></td></tr>
                <?php if (!empty($f['affected_url'])): ?>
                <tr><td>Affected URL</td><td class="mono" style="word-break:break-all"><?= rpt_e($f['affected_url']) ?></td></tr>
                <?php endif; ?>
                <tr><td>Likelihood / Impact</td><td><?= (int) ($f['likelihood'] ?? 0) ?> / <?= (int) ($f['impact'] ?? 0) ?> &rarr; matrix score <?= (int) ($f['matrix_score'] ?? 0) ?> (<?= rpt_e(strtoupper((string) ($f['matrix_band'] ?? '-'))) ?>)</td></tr>
                <?php if (!empty($f['cvss_vector'])): ?>
                <tr><td>CVSS v3.1 vector</td><td class="mono" style="word-break:break-all"><?= rpt_e($f['cvss_vector']) ?>
                    <?php if (!empty($f['cvss_detail'])): ?>
                        <div class="small muted" style="margin-top:3px">
                            Impact sub-score <?= rpt_e($f['cvss_detail']['impact_subscore'] ?? '-') ?>,
                            exploitability sub-score <?= rpt_e($f['cvss_detail']['exploitability_subscore'] ?? '-') ?>
                        </div>
                    <?php endif; ?>
                </td></tr>
                <?php endif; ?>
                <tr><td>Confidence</td><td><?= rpt_label($f['confidence'] ?? '') ?></td></tr>
                <tr><td>Status</td><td><?= rpt_label($f['status'] ?? '') ?></td></tr>
                <tr><td>Raised by</td><td><?= rpt_e($f['created_by'] ?? 'unknown') ?> on <?= rpt_date($f['created_at'] ?? null) ?></td></tr>
            </table>

            <div class="rationale">
                <strong>How this severity was derived.</strong><br>
                <?= nl2br(rpt_e($f['severity_rationale'] ?? 'Not recorded.')) ?>
            </div>

            <h4>Description</h4>
            <?= rpt_p($f['description'] ?? '') ?>

            <?php if (trim((string) ($f['impact_narrative'] ?? '')) !== ''): ?>
                <h4>Business impact</h4>
                <?= rpt_p($f['impact_narrative']) ?>
            <?php endif; ?>

            <?php if (trim((string) ($f['reproduction_steps'] ?? '')) !== ''): ?>
                <h4>Steps to reproduce</h4>
                <pre><?= rpt_e($f['reproduction_steps']) ?></pre>
            <?php endif; ?>

            <?php $evidence = $f['evidence'] ?? []; if ($evidence !== []): ?>
                <h4>Evidence (<?= count($evidence) ?>)</h4>
                <?php foreach ($evidence as $item): ?>
                <div class="evidence-item">
                    <div class="eh">
                        <div>
                            <strong><?= rpt_e($item['title'] ?? '') ?></strong>
                            <span class="badge badge-outline" style="margin-left:6px"><?= rpt_label($item['type'] ?? '') ?></span>
                            <?php if (!empty($item['is_redacted'])): ?>
                                <span class="badge" style="background:#7c3aed; margin-left:4px">Redacted</span>
                            <?php endif; ?>
                        </div>
                        <div class="small muted">
                            <?= rpt_date($item['captured_at'] ?? null, 'd M Y H:i') ?> &middot; <?= rpt_e($item['collected_by'] ?? '') ?>
                        </div>
                    </div>
                    <div class="eb">
                        <?php if (trim((string) ($item['description'] ?? '')) !== ''): ?>
                            <p class="small"><?= rpt_e($item['description']) ?></p>
                        <?php endif; ?>
                        <?php if (!empty($item['content'])): ?>
                            <pre><?= rpt_e($item['content']) ?></pre>
                        <?php elseif (!empty($item['is_image'])): ?>
                            <p class="small muted">Screenshot artefact held in the evidence store
                                (<?= rpt_e($item['mime_type'] ?? 'image') ?>). Retrieve it from the platform using the hash below.</p>
                        <?php endif; ?>
                        <?php if (!empty($item['redaction'])): ?>
                            <p class="small muted"><strong>Redaction applied:</strong> <?= rpt_e($item['redaction']) ?></p>
                        <?php endif; ?>
                        <div class="hash">SHA-256 (original capture): <?= rpt_e($item['sha256'] ?? '') ?></div>
                        <?php $custody = $item['custody'] ?? []; if ($custody !== []): ?>
                        <div class="custody">
                            <strong>Chain of custody:</strong>
                            <?php foreach ($custody as $entry): ?>
                                <span><?= rpt_label($entry['action'] ?? '') ?> &mdash; <?= rpt_e($entry['actor_name'] ?? '') ?>,
                                <?= rpt_date($entry['created_at'] ?? null, 'd M H:i') ?></span>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            <?php else: ?>
                <div class="callout warn small"><strong>No evidence is attached to this finding.</strong> Attach the captured request, response or screenshot before the report is finalised.</div>
            <?php endif; ?>

            <?php $rem = $f['remediation'] ?? null; if ($rem !== null): ?>
                <h4>Remediation</h4>
                <?= rpt_p($rem['recommendation'] ?? '') ?>
                <?php if (trim((string) ($rem['secure_code_example'] ?? '')) !== ''): ?>
                    <p class="small muted">Reference implementation:</p>
                    <pre><?= rpt_e($rem['secure_code_example']) ?></pre>
                <?php endif; ?>
                <table class="facts">
                    <tr><td>Status</td><td><?= rpt_label($rem['status'] ?? 'not started') ?></td></tr>
                    <tr><td>Owner</td><td><?= rpt_e($rem['owner_name'] ?? 'Unassigned') ?><?= !empty($rem['owner_team']) ? ' (' . rpt_e($rem['owner_team']) . ')' : '' ?></td></tr>
                    <tr><td>Target date</td><td><?= !empty($rem['due_date']) ? rpt_date($rem['due_date']) : 'Not set' ?><?= !empty($rem['sla_days']) ? ' (' . (int) $rem['sla_days'] . ' day target)' : '' ?></td></tr>
                    <tr><td>Estimated effort</td><td><?= rpt_label($rem['effort'] ?? 'medium') ?></td></tr>
                </table>
                <?php if (trim((string) ($rem['reference_links'] ?? '')) !== ''): ?>
                    <p class="small muted"><strong>References:</strong><br><?= nl2br(rpt_e($rem['reference_links'])) ?></p>
                <?php endif; ?>
            <?php endif; ?>

            <?php $retests = $f['retests'] ?? []; if ($retests !== []): ?>
                <h4>Retest history</h4>
                <table class="data">
                    <thead><tr><th style="width:52px">Round</th><th style="width:86px">Date</th><th style="width:110px">Result</th><th>Method and observation</th><th style="width:110px">Tester</th></tr></thead>
                    <tbody>
                    <?php foreach ($retests as $rt): ?>
                        <tr>
                            <td class="num"><?= (int) ($rt['round_no'] ?? 0) ?></td>
                            <td><?= rpt_date($rt['retest_date'] ?? null, 'd M Y') ?></td>
                            <td>
                                <?php $cls = ($rt['result'] ?? '') === 'fixed' ? 'sev-low' : (($rt['result'] ?? '') === 'partially_fixed' ? 'sev-medium' : 'sev-high'); ?>
                                <span class="badge <?= $cls ?>"><?= rpt_label($rt['result'] ?? '') ?></span>
                            </td>
                            <td class="small"><strong><?= rpt_e($rt['method'] ?? '') ?></strong><br><?= nl2br(rpt_e($rt['observation'] ?? '')) ?></td>
                            <td class="small"><?= rpt_e($rt['tester_name'] ?? '') ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </article>
    <?php endforeach; ?>
</div>

<?php if (!$isExecutive && !empty($snapshot['test_log'])): ?>
<!-- ===================== CHECK LOG ===================== -->
<div class="page page-break">
    <h2 style="margin-top:0">8. Security check log</h2>
    <p class="small muted">Every predefined check in the plan and its recorded outcome. This is the audit trail that shows what was tested, not only what was found.</p>
    <table class="data">
        <thead><tr><th style="width:96px">Code</th><th>Check</th><th style="width:96px">Result</th><th style="width:88px">Review</th><th style="width:96px">Tested by</th><th style="width:44px">Ev.</th></tr></thead>
        <tbody>
        <?php foreach ($snapshot['test_log'] as $t):
            $badge = match ($t['status'] ?? '') {
                'pass' => 'background:#15803d', 'fail' => 'background:var(--critical)',
                'manual_review' => 'background:var(--medium)', 'not_applicable' => 'background:var(--info)',
                default => 'background:#9ca3af',
            }; ?>
            <tr>
                <td class="mono small"><?= rpt_e($t['code'] ?? '') ?></td>
                <td>
                    <?= rpt_e($t['title'] ?? '') ?>
                    <?php if (trim((string) ($t['observation'] ?? '')) !== ''): ?>
                        <div class="small muted"><?= rpt_e(mb_substr((string) $t['observation'], 0, 260)) ?><?= mb_strlen((string) $t['observation']) > 260 ? '...' : '' ?></div>
                    <?php endif; ?>
                </td>
                <td><span class="badge" style="<?= $badge ?>"><?= rpt_label($t['status'] ?? '') ?></span></td>
                <td class="small"><?= rpt_label($t['review_status'] ?? '') ?></td>
                <td class="small"><?= rpt_e($t['tested_by'] ?? '-') ?></td>
                <td class="num small"><?= (int) ($t['evidence_count'] ?? 0) ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

<!-- ===================== REMEDIATION + ASSURANCE ===================== -->
<div class="page page-break">
    <h2 style="margin-top:0"><?= $isExecutive ? '8' : '9' ?>. Remediation tracker</h2>
    <?php $tracker = $snapshot['remediation_tracker'] ?? []; if ($tracker === []): ?>
        <p class="muted">Nothing to track.</p>
    <?php else: ?>
    <table class="data">
        <thead><tr><th style="width:56px">Ref</th><th>Finding</th><th style="width:74px">Severity</th><th style="width:96px">Status</th><th style="width:108px">Owner</th><th style="width:80px">Due</th><th style="width:78px">Retests</th></tr></thead>
        <tbody>
        <?php foreach ($tracker as $row): ?>
            <tr>
                <td class="mono"><?= rpt_e($row['ref_code'] ?? '') ?></td>
                <td class="small"><?= rpt_e($row['title'] ?? '') ?></td>
                <td><span class="badge <?= rpt_sev($row['severity'] ?? '') ?>"><?= rpt_e($row['severity'] ?? '') ?></span></td>
                <td class="small"><?= rpt_label($row['status'] ?? 'not started') ?></td>
                <td class="small"><?= rpt_e($row['owner_name'] ?? 'Unassigned') ?></td>
                <td class="small">
                    <?= !empty($row['due_date']) ? rpt_date($row['due_date'], 'd M Y') : '-' ?>
                    <?php if (!empty($row['is_overdue'])): ?><br><span style="color:var(--critical);font-weight:700">OVERDUE</span><?php endif; ?>
                </td>
                <td class="small"><?= (int) ($row['retest_count'] ?? 0) ?><?= !empty($row['last_retest_result']) ? ' &middot; ' . rpt_label($row['last_retest_result']) : '' ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <h2><?= $isExecutive ? '9' : '10' ?>. Assurance, AI usage and record integrity</h2>

    <h3>Record integrity</h3>
    <?php $integrity = $snapshot['integrity']['audit_chain'] ?? []; ?>
    <?php if (($integrity['valid'] ?? false) === true): ?>
        <div class="callout ok">
            <strong>Audit trail verified.</strong> All <?= (int) ($integrity['checked'] ?? 0) ?> audit entries form an
            unbroken SHA-256 hash chain, confirming no recorded action was altered or removed after it was written.
        </div>
    <?php else: ?>
        <div class="callout bad">
            <strong>Audit trail verification failed at entry <?= (int) ($integrity['broken_at'] ?? 0) ?>.</strong>
            <?= rpt_e($integrity['reason'] ?? '') ?> Treat the record as untrusted and investigate before relying on this report.
        </div>
    <?php endif; ?>
    <p class="small"><?= rpt_e($snapshot['integrity']['snapshot_note'] ?? '') ?>
        <?= (int) ($snapshot['integrity']['evidence_count'] ?? 0) ?> evidence artefacts are held for this assessment, each
        hashed with SHA-256 at the moment of capture and carrying its own chain of custody.</p>

    <h3>Use of AI assistance</h3>
    <p class="small"><?= rpt_e($snapshot['ai_usage']['note'] ?? '') ?></p>
    <?php $usage = $snapshot['ai_usage']['usage'] ?? []; if ($usage === []): ?>
        <p class="small muted">No model assistance was used during this assessment.</p>
    <?php else: ?>
    <table class="data">
        <thead><tr><th>Task</th><th style="width:120px">Engine</th><th>Model</th><th class="num" style="width:60px">Runs</th><th class="num" style="width:88px">Mean confidence</th><th class="num" style="width:76px">Accepted</th></tr></thead>
        <tbody>
        <?php foreach ($usage as $row): ?>
            <tr>
                <td><?= rpt_label($row['task'] ?? '') ?></td>
                <td class="small"><?= rpt_e($row['engine'] ?? '') ?></td>
                <td class="small"><?= rpt_e($row['model_name'] ?? '') ?></td>
                <td class="num"><?= (int) ($row['runs'] ?? 0) ?></td>
                <td class="num"><?= $row['avg_confidence'] !== null ? rpt_e(number_format((float) $row['avg_confidence'] * 100, 1)) . '%' : '-' ?></td>
                <td class="num"><?= (int) ($row['accepted'] ?? 0) ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <?php
    $excludedFp = $snapshot['excluded']['false_positive'] ?? [];
    $excludedDup = $snapshot['excluded']['duplicate'] ?? [];
    if ($excludedFp !== [] || $excludedDup !== []): ?>
        <h3>Items excluded from the findings section</h3>
        <table class="data">
            <thead><tr><th style="width:70px">Ref</th><th>Title</th><th style="width:150px">Reason for exclusion</th></tr></thead>
            <tbody>
            <?php foreach (array_merge($excludedFp, $excludedDup) as $row): ?>
                <tr>
                    <td class="mono"><?= rpt_e($row['ref_code'] ?? '') ?></td>
                    <td class="small"><?= rpt_e($row['title'] ?? '') ?></td>
                    <td class="small"><?= rpt_e($row['reason'] ?? '') ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <p class="small muted">Excluded items remain in the platform record with their full history and can be re-opened.</p>
    <?php endif; ?>

    <h3>Limitations</h3>
    <p class="small">
        This assessment covers only the target and scope stated in section 3, at the point in time stated on the cover.
        It is a controlled laboratory exercise: no Internet-facing system was tested and no destructive technique was
        used. A clean result for a check means the specific condition tested for was not observed with the techniques
        applied; it is not a guarantee that no weakness of that class exists.
    </p>

    <div class="sig-grid">
        <div class="sig">Prepared by<br><strong style="color:var(--ink)"><?= rpt_e($meta['generated_by_name'] ?: ($meta['generated_by'] ?? '')) ?></strong><br><?= rpt_date($meta['generated_at'] ?? null) ?></div>
        <div class="sig">Reviewed by<br><strong style="color:var(--ink)"><?= rpt_e($a['lead_analyst'] ?? '') ?></strong><br>Lead analyst</div>
        <div class="sig">Report reference<br><strong style="color:var(--ink)"><?= rpt_e($reportMeta['ref_code'] ?? '') ?></strong><br><?= rpt_label($reportMeta['status'] ?? 'draft') ?></div>
    </div>

    <p class="small muted" style="margin-top:2em; border-top:1px solid var(--line); padding-top:10px;">
        <?= rpt_e($meta['footer'] ?? 'CONFIDENTIAL') ?> &middot;
        <?= rpt_e($reportMeta['ref_code'] ?? '') ?> &middot;
        Snapshot SHA-256 <span class="mono"><?= rpt_e(substr((string) ($reportMeta['sha256'] ?? ''), 0, 32)) ?>...</span>
    </p>
</div>

</body>
</html>
