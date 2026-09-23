/* ==========================================================================
   Reports tab - generate frozen, hashed report snapshots and export them.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, $ = DXB.$;

    DXB.tabs.reports = function (a, panel) {
        panel.innerHTML = ui.loading();

        api.get('/assessments/' + a.id + '/reports', null, { silent: true }).then(function (payload) {
            var reports = payload.data;
            panel.innerHTML =
                readiness(a) +
                '<div class="card">' +
                    '<header><h3>Generated reports</h3><div class="spacer"></div>' +
                        (ui.can('report.generate') ? '<button class="btn sm primary" id="btnGen">Generate report</button>' : '') +
                    '</header>' +
                    (reports.length ? table(reports) : ui.empty('No reports generated yet.',
                        'A report freezes the whole assessment into a hashed snapshot you can print, export or re-open unchanged later.')) +
                '</div>' +
                explainer();

            if ($('#btnGen')) { $('#btnGen').addEventListener('click', function () { generateDialog(a); }); }

            DXB.on(panel, 'click', '[data-verify-report]', function (event, el) {
                api.get('/reports/' + el.getAttribute('data-verify-report') + '/verify', null, { silent: true })
                    .then(function (res) {
                        DXB.modal({
                            title: 'Report integrity',
                            body: '<div class="callout ' + (res.data.verified ? 'ok' : 'bad') + '"><b>' +
                                    (res.data.verified ? 'Verified.' : 'Verification failed.') + '</b><br>' + esc(res.data.message) + '</div>' +
                                '<dl class="kv"><dt>Recorded</dt><dd class="mono wrap-any">' + esc(res.data.expected) + '</dd>' +
                                '<dt>Computed</dt><dd class="mono wrap-any">' + esc(res.data.actual) + '</dd></dl>',
                            actions: [{ label: 'Close' }]
                        });
                    }).catch(function (error) { DXB.toast(error.message, 'bad'); });
            });

            DXB.on(panel, 'click', '[data-finalise]', function (event, el) {
                DXB.confirm({
                    title: 'Finalise this report?',
                    message: 'A finalised report is locked: it cannot be deleted, and changes require a new version.',
                    confirmLabel: 'Finalise',
                    kind: 'primary'
                }).then(function (ok) {
                    if (!ok) { return; }
                    api.post('/reports/' + el.getAttribute('data-finalise') + '/finalise')
                        .then(function () { DXB.resolveRoute(); })
                        .catch(function (error) { DXB.toast(error.message, 'bad'); });
                });
            });

            DXB.on(panel, 'click', '[data-del-report]', function (event, el) {
                DXB.confirm({ title: 'Delete draft report?', message: 'Only draft reports can be deleted.', confirmLabel: 'Delete' })
                    .then(function (ok) {
                        if (!ok) { return; }
                        api.del('/reports/' + el.getAttribute('data-del-report'))
                            .then(function () { DXB.resolveRoute(); })
                            .catch(function (error) { DXB.toast(error.message, 'bad'); });
                    });
            });
        }).catch(function (error) { panel.innerHTML = ui.error(error.message); });
    };

    function readiness(a) {
        var s = a.stats || {};
        var problems = [];
        if (s.tests_pending > 0) {
            problems.push(s.tests_pending + ' check(s) still have no recorded result - they will appear as pending in the check log.');
        }
        if ((s.critical + s.high) > 0 && s.resolved === 0) {
            problems.push('Critical or high findings are open with no verified retest.');
        }
        if (s.evidence_count === 0) {
            problems.push('No evidence has been captured. Findings without evidence are flagged in the report.');
        }
        if (s.overdue > 0) {
            problems.push(s.overdue + ' remediation item(s) are past their target date.');
        }

        if (!problems.length) {
            return '<div class="callout ok"><b>The assessment record is complete.</b> Every check has a result, evidence is attached and remediation is within target.</div>';
        }
        return '<div class="callout warn"><b>Before you finalise, note:</b><ul style="margin:6px 0 0;padding-left:18px">' +
            problems.map(function (p) { return '<li>' + esc(p) + '</li>'; }).join('') +
            '</ul><div class="small dim mt1">You can still generate a draft report - these appear in it as-is.</div></div>';
    }

    function table(rows) {
        return '<div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th style="width:190px">Reference</th><th>Title</th><th style="width:96px">Type</th>' +
            '<th style="width:80px">Status</th><th style="width:150px">Generated</th><th style="width:290px">Actions</th>' +
            '</tr></thead><tbody>' + rows.map(function (r) {
                var base = DXB.apiBase + '/reports/' + r.id;
                return '<tr>' +
                    '<td class="mono small">' + esc(r.ref_code) +
                        '<div class="dim" style="font-size:10px">sha256 ' + esc(r.sha256_short) + '...</div></td>' +
                    '<td>' + esc(r.title) + '</td>' +
                    '<td class="small">' + esc(fmt.label(r.report_type)) + ' v' + esc(r.version) + '</td>' +
                    '<td>' + fmt.result(r.status) + '</td>' +
                    '<td class="small dim">' + esc(fmt.date(r.generated_at, true)) + '<br>' + esc(r.generated_by_name || '') + '</td>' +
                    '<td><div class="btn-row">' +
                        '<a class="btn xs primary" href="' + attr(base + '/html') + '" target="_blank" rel="noopener">Open</a>' +
                        '<a class="btn xs" href="' + attr(base + '/csv') + '">CSV</a>' +
                        '<a class="btn xs" href="' + attr(base + '/json') + '">JSON</a>' +
                        '<button class="btn xs" data-verify-report="' + r.id + '">Verify</button>' +
                        (r.status !== 'final' && ui.can('report.finalise')
                            ? '<button class="btn xs" data-finalise="' + r.id + '">Finalise</button>' +
                              '<button class="btn xs ghost" data-del-report="' + r.id + '">Delete</button>'
                            : '') +
                    '</div></td>' +
                '</tr>';
            }).join('') + '</tbody></table></div>';
    }

    function generateDialog(a) {
        DXB.modal({
            title: 'Generate report',
            body:
                ui.field('Report type', ui.select('report_type', [
                    { value: 'full', label: 'Full technical report - findings, evidence, check log, remediation' },
                    { value: 'executive', label: 'Executive summary - management-facing, top findings only' },
                    { value: 'delta', label: 'Retest report - focused on what changed since remediation' }
                ], 'full')) +
                ui.field('Title', '<input type="text" name="title" placeholder="Leave blank to use the default">') +
                '<div class="callout info small">Generating freezes the current state into a snapshot and hashes it. ' +
                    'Re-opening this report later reproduces exactly what you see now, even after the assessment moves on. ' +
                    'The executive summary is drafted by the local assistant when it is running, and from a deterministic ' +
                    'template otherwise - either way you can regenerate after editing.</div>',
            actions: [
                { label: 'Cancel' },
                {
                    label: 'Generate', kind: 'primary', close: false,
                    onClick: function (bodyEl, close, button) {
                        button.disabled = true;
                        button.textContent = 'Building snapshot...';
                        api.post('/assessments/' + a.id + '/reports', ui.readForm(bodyEl)).then(function (payload) {
                            close();
                            DXB.resolveRoute();
                            window.open(DXB.apiBase + '/reports/' + payload.data.id + '/html', '_blank', 'noopener');
                        }).catch(function (error) {
                            DXB.toast(error.message, 'bad', 9000);
                            button.disabled = false;
                            button.textContent = 'Generate';
                        });
                        return false;
                    }
                }
            ]
        });
    }

    function explainer() {
        return '<div class="grid c3 mt2">' +
            card('What goes in the report', [
                'Cover page with the classification, target, window and snapshot hash',
                'Executive summary, scope and rules of engagement, methodology',
                'The full risk model: the 5x5 matrix, the CVSS approach and the SLA table',
                'Every finding with its severity derivation, evidence hashes and chain of custody',
                'The complete check log - what was tested, not only what was found',
                'Remediation tracker, retest history and the AI usage register'
            ]) +
            card('Why it is audit-ready', [
                'The snapshot is hashed; altering a single character breaks the hash',
                'The audit trail is a SHA-256 hash chain that is re-verified at generation',
                'Every evidence artefact carries the hash taken at capture, before redaction',
                'Severity is never asserted - the derivation is printed for every finding',
                'Model assistance is disclosed with the task, engine and analyst acceptance'
            ]) +
            card('Getting a PDF', [
                'Open the report and press Ctrl+P (Cmd+P on macOS)',
                'Choose "Save as PDF" as the destination',
                'Set margins to Default and enable background graphics',
                'The print stylesheet handles page breaks, headers and the footer',
                'No PDF library is needed, so nothing extra has to be installed'
            ]) +
        '</div>';
    }

    function card(title, items) {
        return '<div class="card"><header><h3>' + esc(title) + '</h3></header><div class="body">' +
            '<ul class="small" style="padding-left:17px;line-height:1.8;margin:0">' +
            items.map(function (i) { return '<li>' + esc(i) + '</li>'; }).join('') +
            '</ul></div></div>';
    }

}(window.DXB));
