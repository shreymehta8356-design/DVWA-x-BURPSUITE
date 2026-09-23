/* ==========================================================================
   Assessment workspace - the shell that hosts every stage of the workflow:
   Overview -> Checks -> Findings -> Evidence -> Remediation -> Import -> Reports
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, charts = DXB.charts, $ = DXB.$;

    var TABS = [
        { key: 'overview',    label: 'Overview' },
        { key: 'tests',       label: 'Security checks' },
        { key: 'findings',    label: 'Findings' },
        { key: 'evidence',    label: 'Evidence' },
        { key: 'remediation', label: 'Remediation & retest' },
        { key: 'import',      label: 'Burp import' },
        { key: 'reports',     label: 'Reports' }
    ];

    /** Shared state for the currently open assessment, read by the tab modules. */
    DXB.workspace = { assessment: null, id: null };

    DXB.views.workspace = function (params, view) {
        var id = parseInt(params.id, 10);
        var tab = params.tab || 'overview';
        DXB.workspace.id = id;

        view.innerHTML = ui.loading('Opening assessment...');

        api.get('/assessments/' + id, null, { silent: true }).then(function (payload) {
            var assessment = payload.data;
            DXB.workspace.assessment = assessment;
            renderShell(view, assessment, tab);

            var handler = DXB.tabs[tab];
            var panel = $('#tabPanel');
            if (!handler) {
                panel.innerHTML = ui.empty('Unknown section.');
                return;
            }
            handler(assessment, panel);
        }).catch(function (error) {
            view.innerHTML = ui.error(error.message);
        });
    };

    function renderShell(view, a, activeTab) {
        var stats = a.stats || {};

        DXB.setHeader(
            a.title,
            '<a href="#/assessments">Assessments</a> / <span class="mono">' + esc(a.ref_code) + '</span>',
            statusControl(a)
        );

        var counts = {
            tests: stats.tests_total || 0,
            findings: stats.findings_total || 0,
            evidence: stats.evidence_count || 0,
            remediation: stats.findings_open || 0
        };

        view.innerHTML =
            headerCard(a, stats) +
            '<nav class="tabs">' + TABS.map(function (t) {
                var n = counts[t.key];
                return '<a href="#/assessment/' + a.id + '/' + t.key + '"' +
                    (t.key === activeTab ? ' class="active"' : '') + '>' + esc(t.label) +
                    (n ? '<span class="n">' + n + '</span>' : '') + '</a>';
            }).join('') + '</nav>' +
            '<div id="tabPanel">' + ui.loading() + '</div>';
    }

    function statusControl(a) {
        if (!ui.can('assessment.edit')) {
            return fmt.result(a.status);
        }
        var next = {
            draft: ['in_progress'],
            in_progress: ['testing_complete'],
            testing_complete: ['in_remediation'],
            in_remediation: ['retest'],
            retest: ['closed'],
            closed: ['in_remediation']
        }[a.status] || [];

        return fmt.result(a.status) +
            next.map(function (s) {
                return '<button class="btn sm" data-set-status="' + esc(s) + '">Move to ' + esc(fmt.label(s)) + '</button>';
            }).join('');
    }

    function headerCard(a, stats) {
        var severityData = ['critical', 'high', 'medium', 'low', 'info'].map(function (key) {
            return { label: key, value: stats[key] || 0 };
        });
        var hasFindings = severityData.some(function (d) { return d.value > 0; });

        return '<div class="card mb2"><div class="body">' +
            '<div class="grid" style="grid-template-columns:1.4fr 1fr 1fr; gap:20px; align-items:center">' +
                '<div>' +
                    '<dl class="kv">' +
                        '<dt>Target</dt><dd>' + esc(a.target_name) + ' <span class="dim mono small">' + esc(a.target_base_url) + '</span></dd>' +
                        '<dt>Environment</dt><dd>' + esc(fmt.label(a.environment)) + ' &middot; ' + esc(a.methodology) + '</dd>' +
                        '<dt>Window</dt><dd>' + esc(fmt.date(a.start_date)) + ' &ndash; ' + esc(fmt.date(a.end_date)) + '</dd>' +
                        '<dt>Lead</dt><dd>' + esc(a.lead_name || 'Not assigned') + '</dd>' +
                    '</dl>' +
                '</div>' +
                '<div>' +
                    '<div class="small dim mb1">Check progress</div>' +
                    ui.progress(stats.progress || 0) +
                    '<div class="small mt1">' + (stats.tests_executed || 0) + ' of ' + (stats.tests_total || 0) +
                        ' executed &middot; <b>' + (stats.tests_fail || 0) + '</b> failed &middot; ' +
                        (stats.tests_manual || 0) + ' manual review</div>' +
                    '<div class="flex mt2" style="gap:14px">' +
                        '<div><div class="dim small">Evidence</div><b>' + (stats.evidence_count || 0) + '</b></div>' +
                        '<div><div class="dim small">Retests</div><b>' + (stats.retest_count || 0) + '</b></div>' +
                        '<div><div class="dim small">Overdue</div><b style="color:' +
                            ((stats.overdue || 0) > 0 ? 'var(--critical)' : 'var(--ok)') + '">' + (stats.overdue || 0) + '</b></div>' +
                    '</div>' +
                '</div>' +
                '<div class="flex" style="gap:16px">' +
                    charts.gauge(stats.risk_score || 0, { size: 128 }) +
                    '<div style="flex:1">' +
                        (hasFindings ? severityMini(severityData) : '<div class="dim small">No findings raised yet.</div>') +
                    '</div>' +
                '</div>' +
            '</div>' +
        '</div></div>';
    }

    function severityMini(data) {
        var max = Math.max.apply(null, data.map(function (d) { return d.value; }).concat([1]));
        return '<div class="sevbars">' + data.map(function (d) {
            return '<div class="sevbar">' +
                '<span class="nm">' + esc(d.label) + '</span>' +
                '<span class="tr"><span class="fl fl-' + esc(d.label) + '" style="width:' +
                    (d.value > 0 ? Math.max(4, Math.round(d.value / max * 100)) : 0) + '%"></span></span>' +
                '<span class="ct">' + d.value + '</span></div>';
        }).join('') + '</div>';
    }

    /* ======================================================================
       OVERVIEW TAB
       ====================================================================== */

    DXB.tabs.overview = function (a, panel) {
        panel.innerHTML = ui.loading();

        api.get('/assessments/' + a.id + '/coverage', null, { silent: true }).then(function (payload) {
            var coverage = payload.data;
            panel.innerHTML =
                '<div class="split">' +
                    '<div>' +
                        '<div class="card mb2">' +
                            '<header><h3>Coverage by category</h3><div class="spacer"></div>' +
                                '<span class="small dim">pass &middot; fail &middot; manual &middot; n/a &middot; pending</span></header>' +
                            '<div class="body">' +
                                (coverage.length ? coverage.map(function (row) {
                                    return '<div style="margin-bottom:12px">' +
                                        '<div class="flex small mb1"><b style="flex:1">' + esc(row.category) + '</b>' +
                                            '<span class="dim">' + (row.total - row.pending) + ' / ' + row.total + '</span></div>' +
                                        charts.coverageBar(row) + '</div>';
                                }).join('') : '<div class="dim small">No checks in the plan yet. Open the Security checks tab to add them.</div>') +
                            '</div>' +
                        '</div>' +

                        '<div class="card mb2">' +
                            '<header><h3>Objective and rules of engagement</h3><div class="spacer"></div>' +
                                (ui.can('assessment.edit') ? '<button class="btn xs" data-edit-assessment>Edit</button>' : '') +
                            '</header>' +
                            '<div class="body">' +
                                '<h4>Objective</h4>' + paragraphs(a.objective) +
                                '<h4 class="mt2">Rules of engagement</h4>' + paragraphs(a.rules_of_engagement) +
                                (a.constraints ? '<h4 class="mt2">Constraints</h4>' + paragraphs(a.constraints) : '') +
                            '</div>' +
                        '</div>' +

                        '<div class="card">' +
                            '<header><h3>Workflow</h3></header>' +
                            '<div class="body">' + workflowDiagram(a.stats) + '</div>' +
                        '</div>' +
                    '</div>' +

                    '<div>' +
                        '<div class="card mb2">' +
                            '<header><h3>Scope</h3><div class="spacer"></div>' +
                                (ui.can('assessment.edit') ? '<button class="btn xs" data-add-scope>Add</button>' : '') +
                            '</header>' +
                            '<div class="body" id="scopeList">' + scopeList(a.scope) + '</div>' +
                        '</div>' +
                        '<div class="card">' +
                            '<header><h3>Danger zone</h3></header>' +
                            '<div class="body small">' +
                                '<p class="dim">Deleting an assessment removes its findings, evidence, retests and reports. The action itself is recorded in the audit trail.</p>' +
                                (ui.can('assessment.delete')
                                    ? '<button class="btn sm danger" data-delete-assessment>Delete assessment</button>'
                                    : '<span class="dim">Only an administrator can delete an assessment.</span>') +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                '</div>';
        }).catch(function (error) { panel.innerHTML = ui.error(error.message); });
    };

    function paragraphs(text) {
        if (!text || !String(text).trim()) { return '<p class="dim small">Not recorded.</p>'; }
        return String(text).split(/\n{2,}/).map(function (block) {
            return '<p class="small">' + esc(block).replace(/\n/g, '<br>') + '</p>';
        }).join('');
    }

    function scopeList(scope) {
        if (!scope || !scope.length) {
            return '<div class="dim small">No scope items recorded. The target base URL defines the scope.</div>';
        }
        return '<div style="display:flex;flex-direction:column;gap:7px">' + scope.map(function (item) {
            return '<div class="flex" style="gap:8px">' +
                '<span class="badge ' + (Number(item.in_scope) ? 'ok' : 'mute') + '">' +
                    (Number(item.in_scope) ? 'in' : 'out') + '</span>' +
                '<span class="mono small truncate" style="flex:1" title="' + DXB.attr(item.value) + '">' + esc(item.value) + '</span>' +
                (ui.can('assessment.edit')
                    ? '<button class="btn xs ghost" data-remove-scope="' + item.id + '" title="Remove">&times;</button>' : '') +
            '</div>' + (item.notes ? '<div class="small dim" style="margin:-4px 0 4px 34px">' + esc(item.notes) + '</div>' : '');
        }).join('') + '</div>';
    }

    function workflowDiagram(stats) {
        var steps = [
            { name: 'Assessment', done: true, detail: 'Defined' },
            { name: 'Checks', done: (stats.tests_executed || 0) > 0, detail: (stats.tests_executed || 0) + ' executed' },
            { name: 'Evidence', done: (stats.evidence_count || 0) > 0, detail: (stats.evidence_count || 0) + ' items' },
            { name: 'Findings', done: (stats.findings_total || 0) > 0, detail: (stats.findings_total || 0) + ' raised' },
            { name: 'Risk', done: (stats.findings_total || 0) > 0, detail: 'Matrix + CVSS' },
            { name: 'Remediation', done: Object.keys(stats.remediation || {}).length > 0, detail: (stats.findings_open || 0) + ' open' },
            { name: 'Retest', done: (stats.retest_count || 0) > 0, detail: (stats.retest_count || 0) + ' rounds' },
            { name: 'Report', done: false, detail: 'Generate' }
        ];
        return '<div class="flex wrap" style="gap:6px">' + steps.map(function (step, index) {
            return '<div style="flex:1;min-width:96px;text-align:center;padding:9px 6px;border-radius:6px;border:1px solid ' +
                    (step.done ? '#155e5a' : 'var(--line)') + ';background:' + (step.done ? 'rgba(45,212,191,.07)' : 'var(--bg-2)') + '">' +
                '<div style="font-size:12px;font-weight:600;color:' + (step.done ? 'var(--accent)' : 'var(--fg-2)') + '">' + esc(step.name) + '</div>' +
                '<div class="small dim" style="font-size:10.5px">' + esc(step.detail) + '</div>' +
            '</div>' + (index < steps.length - 1 ? '<span class="dim" style="align-self:center">&rsaquo;</span>' : '');
        }).join('') + '</div>';
    }

    /* ======================================================================
       Overview actions (delegated from app.js)
       ====================================================================== */

    DXB.workspaceActions = {
        addScope: function () {
            var a = DXB.workspace.assessment;
            DXB.modal({
                title: 'Add scope item',
                body:
                    ui.field('Type', ui.select('item_type', [
                        { value: 'url', label: 'URL' }, { value: 'host', label: 'Host' },
                        { value: 'module', label: 'Application module' }, { value: 'ip', label: 'IP address' },
                        { value: 'credential_role', label: 'Credential / role' }
                    ], 'url')) +
                    ui.field('Value', '<input type="text" name="value" class="mono" placeholder="http://localhost/DVWA/vulnerabilities/sqli/">') +
                    ui.field('Notes', '<input type="text" name="notes" placeholder="Optional">') +
                    '<label class="inline-check"><input type="checkbox" name="in_scope" checked> In scope</label>',
                actions: [
                    { label: 'Cancel' },
                    {
                        label: 'Add', kind: 'primary', close: false,
                        onClick: function (bodyEl, close) {
                            api.post('/assessments/' + a.id + '/scope', ui.readForm(bodyEl)).then(function () {
                                close();
                                DXB.resolveRoute();
                            }).catch(function (error) { DXB.toast(error.message, 'bad'); });
                            return false;
                        }
                    }
                ]
            });
        },

        removeScope: function (scopeId) {
            var a = DXB.workspace.assessment;
            api.del('/assessments/' + a.id + '/scope/' + scopeId).then(function () { DXB.resolveRoute(); })
                .catch(function (error) { DXB.toast(error.message, 'bad'); });
        },

        editAssessment: function () {
            var a = DXB.workspace.assessment;
            DXB.meta().then(function (meta) {
                DXB.modal({
                    title: 'Edit assessment',
                    size: 'wide',
                    body:
                        '<div class="grid c2">' +
                            ui.field('Title', '<input type="text" name="title" value="' + DXB.attr(a.title) + '">') +
                            ui.field('Target name', '<input type="text" name="target_name" value="' + DXB.attr(a.target_name) + '">') +
                        '</div>' +
                        '<div class="grid c2">' +
                            ui.field('Target base URL', '<input type="url" name="target_base_url" class="mono" value="' + DXB.attr(a.target_base_url) + '">') +
                            ui.field('Environment', ui.select('environment', meta.environments.map(function (e) {
                                return { value: e, label: fmt.label(e) };
                            }), a.environment)) +
                        '</div>' +
                        '<div class="grid c3">' +
                            ui.field('Methodology', '<input type="text" name="methodology" value="' + DXB.attr(a.methodology) + '">') +
                            ui.field('Start date', '<input type="date" name="start_date" value="' + DXB.attr(a.start_date || '') + '">') +
                            ui.field('End date', '<input type="date" name="end_date" value="' + DXB.attr(a.end_date || '') + '">') +
                        '</div>' +
                        ui.field('Objective', '<textarea name="objective" rows="3">' + esc(a.objective || '') + '</textarea>') +
                        ui.field('Rules of engagement', '<textarea name="rules_of_engagement" rows="6">' + esc(a.rules_of_engagement || '') + '</textarea>') +
                        ui.field('Constraints', '<textarea name="constraints" rows="3">' + esc(a.constraints || '') + '</textarea>'),
                    actions: [
                        { label: 'Cancel' },
                        {
                            label: 'Save', kind: 'primary', close: false,
                            onClick: function (bodyEl, close) {
                                api.put('/assessments/' + a.id, ui.readForm(bodyEl)).then(function () {
                                    close();
                                    DXB.resolveRoute();
                                }).catch(function (error) { DXB.toast(error.message, 'bad'); });
                                return false;
                            }
                        }
                    ]
                });
            });
        },

        setStatus: function (status) {
            var a = DXB.workspace.assessment;
            api.post('/assessments/' + a.id + '/status', { status: status })
                .then(function () { DXB.resolveRoute(); })
                .catch(function (error) { DXB.toast(error.message, 'bad', 9000); });
        },

        deleteAssessment: function () {
            var a = DXB.workspace.assessment;
            DXB.modal({
                title: 'Delete ' + a.ref_code + '?',
                body:
                    '<div class="callout bad">This permanently removes every check result, finding, evidence artefact, retest and report in this assessment. It cannot be undone.</div>' +
                    ui.field('Type the assessment reference to confirm',
                        '<input type="text" name="confirm" class="mono" placeholder="' + DXB.attr(a.ref_code) + '" autocomplete="off">'),
                actions: [
                    { label: 'Cancel' },
                    {
                        label: 'Delete permanently', kind: 'danger', close: false,
                        onClick: function (bodyEl, close) {
                            api.del('/assessments/' + a.id, ui.readForm(bodyEl)).then(function () {
                                close();
                                DXB.navigate('/assessments');
                            }).catch(function (error) { DXB.toast(error.message, 'bad'); });
                            return false;
                        }
                    }
                ]
            });
        }
    };

}(window.DXB));
