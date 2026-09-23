/* ==========================================================================
   Dashboard - platform-wide posture, activity and the queue of items that
   need a decision from a lead.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, fmt = DXB.fmt, ui = DXB.ui, charts = DXB.charts, api = DXB.api;

    DXB.views.dashboard = function (params, view) {
        DXB.setHeader('Dashboard', 'Platform overview',
            '<a class="btn sm" href="#/assessments">All assessments</a>' +
            (ui.can('assessment.create') ? '<button class="btn sm primary" data-new-assessment>New assessment</button>' : ''));

        view.innerHTML = ui.loading('Building the dashboard...');

        Promise.all([
            api.get('/dashboard', null, { silent: true }),
            api.get('/dashboard/trend', { days: 30 }, { silent: true }),
            api.get('/assessments', null, { silent: true })
        ]).then(function (results) {
            render(view, results[0].data, results[1].data, results[2].data);
        }).catch(function (error) {
            view.innerHTML = ui.error(error.message);
        });
    };

    function render(view, data, trend, assessments) {
        var severity = data.findings.severity;
        var severityData = ['critical', 'high', 'medium', 'low', 'info'].map(function (key) {
            return { label: key, value: severity[key] || 0 };
        });

        var active = assessments.filter(function (a) {
            return a.status !== 'closed' && a.status !== 'draft';
        }).slice(0, 6);

        view.innerHTML =
            '<div class="grid c4 mb2">' +
                ui.stat(data.assessments.total, 'Assessments', data.assessments.active + ' active, ' + data.assessments.draft + ' draft') +
                ui.stat(data.tests.executed + ' / ' + data.tests.total, 'Checks executed',
                    (data.tests.outcomes.fail || 0) + ' failed, ' + (data.tests.outcomes.manual_review || 0) + ' manual review') +
                ui.stat(data.findings.total, 'Findings',
                    data.findings.open + ' open, ' + data.findings.resolved + ' resolved') +
                ui.stat(data.remediation.overdue, 'Overdue remediation',
                    data.remediation.overdue > 0 ? 'Past the severity target date' : 'Everything is within target',
                    data.remediation.overdue > 0 ? 'var(--critical)' : 'var(--ok)') +
            '</div>' +

            '<div class="grid mb2" style="grid-template-columns:1.15fr .85fr">' +
                '<div class="card">' +
                    '<header><h3>Findings raised, last 30 days</h3><div class="spacer"></div>' +
                        '<span class="small dim">' + esc(data.evidence.total) + ' evidence items held</span></header>' +
                    '<div class="body">' + charts.sparkline(trend) + '</div>' +
                '</div>' +
                '<div class="card">' +
                    '<header><h3>Risk posture</h3></header>' +
                    '<div class="body flex" style="gap:20px">' +
                        '<div>' + charts.gauge(data.risk_score) + '</div>' +
                        '<div style="flex:1">' + severityBars(severityData) + '</div>' +
                    '</div>' +
                '</div>' +
            '</div>' +

            '<div class="grid c3 mb2">' +
                '<div class="card">' +
                    '<header><h3>Findings by class</h3></header>' +
                    '<div class="body">' +
                        (data.findings.by_class.length
                            ? charts.bars(data.findings.by_class.slice(0, 8), { labelWidth: 138 })
                            : '<div class="dim small">No findings recorded yet.</div>') +
                    '</div>' +
                '</div>' +
                '<div class="card">' +
                    '<header><h3>OWASP Top 10 coverage</h3></header>' +
                    '<div class="body">' +
                        (data.findings.by_owasp.length
                            ? charts.bars(data.findings.by_owasp.slice(0, 8), { labelWidth: 138 })
                            : '<div class="dim small">No findings mapped yet.</div>') +
                    '</div>' +
                '</div>' +
                '<div class="card">' +
                    '<header><h3>Remediation status</h3></header>' +
                    '<div class="body flex" style="gap:14px">' +
                        charts.donut(remediationSeries(data.remediation.by_status), { size: 130, centreLabel: 'items' }) +
                        '<div style="flex:1">' + charts.legend(remediationSeries(data.remediation.by_status)) + '</div>' +
                    '</div>' +
                '</div>' +
            '</div>' +

            '<div class="grid mb2" style="grid-template-columns:1.3fr .7fr">' +
                '<div class="card">' +
                    '<header><h3>Active assessments</h3><div class="spacer"></div>' +
                        '<a class="btn xs" href="#/assessments">View all</a></header>' +
                    (active.length ? activeTable(active) : ui.empty('No assessments in progress.', 'Create one to start recording results.')) +
                '</div>' +
                '<div class="card">' +
                    '<header><h3>Recent activity</h3></header>' +
                    '<div class="body">' + activityList(data.recent) + '</div>' +
                '</div>' +
            '</div>' +

            attentionSection(data.attention) +

            '<div class="card mt2">' +
                '<header><h3>AI assistance</h3><div class="spacer"></div><a class="btn xs" href="#/ai">Model console</a></header>' +
                '<div class="body">' + aiSummary(data.ai) + '</div>' +
            '</div>';
    }

    function severityBars(data) {
        var max = Math.max.apply(null, data.map(function (d) { return d.value; }).concat([1]));
        return '<div class="sevbars">' + data.map(function (d) {
            var width = d.value > 0 ? Math.max(4, Math.round(d.value / max * 100)) : 0;
            return '<div class="sevbar">' +
                '<span class="nm">' + esc(d.label) + '</span>' +
                '<span class="tr"><span class="fl fl-' + esc(d.label) + '" style="width:' + width + '%"></span></span>' +
                '<span class="ct">' + esc(d.value) + '</span>' +
            '</div>';
        }).join('') + '</div>';
    }

    function remediationSeries(byStatus) {
        var order = ['not_started', 'in_progress', 'implemented', 'verified', 'deferred', 'accepted'];
        var colours = {
            not_started: '#5d6b7d', in_progress: '#60a5fa', implemented: '#2dd4bf',
            verified: '#34d399', deferred: '#fbbf24', accepted: '#a78bfa'
        };
        var series = order.map(function (key) {
            return { label: key, value: byStatus[key] || 0, colour: colours[key] };
        }).filter(function (d) { return d.value > 0; });
        return series.length ? series : [{ label: 'none', value: 0, colour: '#5d6b7d' }];
    }

    function activeTable(rows) {
        return '<div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th>Reference</th><th>Assessment</th><th>Status</th><th style="width:150px">Progress</th><th class="num">Findings</th>' +
            '</tr></thead><tbody>' +
            rows.map(function (a) {
                return '<tr class="clickable" onclick="location.hash=\'#/assessment/' + a.id + '/overview\'">' +
                    '<td class="mono small">' + esc(a.ref_code) + '</td>' +
                    '<td><b>' + esc(a.title) + '</b><div class="small dim">' + esc(a.target_name) + '</div></td>' +
                    '<td>' + fmt.result(a.status) + '</td>' +
                    '<td>' + ui.progress(a.progress) +
                        '<div class="small dim mt1">' + a.tests_done + ' / ' + a.tests_total + ' checks</div></td>' +
                    '<td class="num">' + a.findings_total +
                        (a.findings_serious > 0 ? ' <span class="badge sev-high">' + a.findings_serious + '</span>' : '') + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table></div>';
    }

    function activityList(entries) {
        if (!entries || !entries.length) { return '<div class="dim small">Nothing recorded yet.</div>'; }
        return '<div class="timeline">' + entries.map(function (entry) {
            return '<div class="ti">' +
                '<div class="tm">' + esc(fmt.ago(entry.created_at)) + '</div>' +
                '<div style="font-size:12.5px">' +
                    '<b>' + esc(entry.actor_username || 'system') + '</b> ' +
                    esc(fmt.label(entry.action).toLowerCase()) +
                    (entry.assessment_ref ? ' <span class="dim mono small">' + esc(entry.assessment_ref) + '</span>' : '') +
                '</div>' +
            '</div>';
        }).join('') + '</div>';
    }

    function attentionSection(attention) {
        var overdue = attention.overdue_remediation || [];
        var retest = attention.awaiting_retest || [];
        var review = attention.awaiting_review || [];
        if (!overdue.length && !retest.length && !review.length) {
            return '<div class="callout ok"><b>Nothing is waiting on you.</b> No overdue remediation, no findings awaiting retest and no results awaiting peer review.</div>';
        }

        function block(title, rows, renderRow, kind) {
            if (!rows.length) { return ''; }
            return '<div class="card">' +
                '<header><h3>' + esc(title) + '</h3><div class="spacer"></div>' +
                    '<span class="badge ' + kind + '">' + rows.length + '</span></header>' +
                '<div class="body" style="display:flex;flex-direction:column;gap:8px">' +
                    rows.map(renderRow).join('') + '</div></div>';
        }

        return '<div class="grid c3">' +
            block('Overdue remediation', overdue, function (row) {
                return '<a href="#/assessment/' + row.assessment_id + '/findings?finding=' + row.finding_id + '" class="flex" style="gap:9px;color:inherit">' +
                    fmt.sev(row.severity) +
                    '<span class="truncate" style="flex:1">' + esc(row.ref_code) + ' ' + esc(row.title) + '</span>' +
                    '<span class="small" style="color:var(--critical)">' + esc(fmt.date(row.due_date)) + '</span></a>';
            }, 'bad') +
            block('Awaiting retest', retest, function (row) {
                return '<a href="#/assessment/' + row.assessment_id + '/remediation" class="flex" style="gap:9px;color:inherit">' +
                    fmt.sev(row.severity) +
                    '<span class="truncate" style="flex:1">' + esc(row.ref_code) + ' ' + esc(row.title) + '</span></a>';
            }, 'accent') +
            block('Awaiting peer review', review, function (row) {
                return '<a href="#/assessment/' + row.assessment_id + '/tests" class="flex" style="gap:9px;color:inherit">' +
                    fmt.result(row.status) +
                    '<span class="truncate" style="flex:1">' + esc(row.code) + ' ' + esc(row.title) + '</span></a>';
            }, 'warn') +
        '</div>';
    }

    function aiSummary(ai) {
        var acceptance = (ai.accepted + ai.rejected) > 0
            ? Math.round(ai.accepted / (ai.accepted + ai.rejected) * 100) + '%'
            : 'n/a';
        return '<div class="grid c4 mb2">' +
                ui.stat(ai.total_runs, 'Model invocations', 'All recorded in ai_runs') +
                ui.stat(acceptance, 'Analyst acceptance', ai.accepted + ' accepted, ' + ai.rejected + ' rejected') +
                ui.stat(ai.training_rows, 'Training examples', 'Grows as findings are confirmed') +
                ui.stat(ai.by_task.length, 'Active tasks', 'Triage, dedup, narrative, redaction') +
            '</div>' +
            (ai.by_task.length
                ? charts.bars(ai.by_task.map(function (t) {
                    return { label: fmt.label(t.task) + ' (' + t.engine + ')', value: t.runs };
                }), { labelWidth: 210 })
                : '<div class="dim small">No model has been invoked yet. Record a failing check result and use "Suggest classification" to see the offline classifier work.</div>');
    }

}(window.DXB));
