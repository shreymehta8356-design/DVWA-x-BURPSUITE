/* ==========================================================================
   Remediation and retest tab.
   A finding closes only when a retest records a "fixed" result - the tracker
   and the retest recorder both live here.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, $ = DXB.$;

    DXB.tabs.remediation = function (a, panel) {
        panel.innerHTML = ui.loading();

        api.get('/assessments/' + a.id + '/remediation', null, { silent: true }).then(function (payload) {
            var rows = payload.data;
            panel.innerHTML = summary(rows) + tracker(rows);

            DXB.on(panel, 'click', '[data-rem]', function (event, el) {
                openRemediation(a, parseInt(el.getAttribute('data-rem'), 10));
            });
            DXB.on(panel, 'click', '[data-retest]', function (event, el) {
                event.stopPropagation();
                retestDialog(a, parseInt(el.getAttribute('data-retest'), 10),
                    el.getAttribute('data-ref'), el.getAttribute('data-title'));
            });
        }).catch(function (error) { panel.innerHTML = ui.error(error.message); });
    };

    function summary(rows) {
        var open = rows.filter(function (r) {
            return ['not_started', 'in_progress', 'deferred'].indexOf(r.status) !== -1;
        }).length;
        var overdue = rows.filter(function (r) { return r.is_overdue; }).length;
        var verified = rows.filter(function (r) { return r.status === 'verified'; }).length;
        var awaiting = rows.filter(function (r) { return r.finding_status === 'ready_for_retest'; }).length;

        return '<div class="grid c4 mb2">' +
            ui.stat(rows.length, 'Tracked findings', 'Excludes duplicates and false positives') +
            ui.stat(open, 'Awaiting a fix', 'Not started, in progress or deferred') +
            ui.stat(awaiting, 'Ready for retest', awaiting > 0 ? 'Verify the fix and record the result' : 'Nothing queued', awaiting > 0 ? 'var(--accent)' : null) +
            ui.stat(overdue, 'Past target date', overdue > 0 ? 'Beyond the severity SLA' : 'All within target',
                overdue > 0 ? 'var(--critical)' : 'var(--ok)') +
        '</div>' +
        (verified > 0 ? '<div class="callout ok">' + verified + ' finding(s) have been fixed and independently retested.</div>' : '');
    }

    function tracker(rows) {
        if (!rows.length) {
            return ui.empty('Nothing to track yet.', 'Every finding gets a remediation record automatically when it is raised.');
        }
        return '<div class="card"><div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th style="width:62px">Ref</th><th>Finding</th><th style="width:82px">Severity</th>' +
            '<th style="width:120px">Remediation</th><th style="width:120px">Owner</th>' +
            '<th style="width:120px">Target date</th><th style="width:112px">Retest</th><th style="width:96px"></th>' +
            '</tr></thead><tbody>' +
            rows.map(function (r) {
                return '<tr class="clickable" data-rem="' + r.finding_id + '">' +
                    '<td class="mono small">' + esc(r.ref_code) + '</td>' +
                    '<td><b>' + esc(r.title) + '</b><div class="small dim">' + esc(fmt.label(r.finding_status)) + '</div></td>' +
                    '<td>' + fmt.sev(r.severity) + '</td>' +
                    '<td>' + fmt.result(r.status || 'not_started') + '</td>' +
                    '<td class="small">' + esc(r.owner_name || '<unassigned>') + '</td>' +
                    '<td class="small">' + (r.due_date ? esc(fmt.date(r.due_date)) : '-') +
                        (r.is_overdue
                            ? '<div class="badge bad">overdue</div>'
                            : (r.days_remaining !== null && r.days_remaining !== undefined && r.days_remaining <= 7 && r.days_remaining >= 0
                                ? '<div class="small dim">' + r.days_remaining + ' day(s) left</div>' : '')) + '</td>' +
                    '<td class="small">' + (r.retest_count > 0
                        ? r.retest_count + ' round(s)<div>' + fmt.result(r.last_retest_result) + '</div>'
                        : '<span class="dim">none</span>') + '</td>' +
                    '<td>' + (ui.can('retest.record')
                        ? '<button class="btn xs" data-retest="' + r.finding_id + '" data-ref="' + attr(r.ref_code) +
                          '" data-title="' + attr(r.title) + '">Retest</button>' : '') + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table></div></div>';
    }

    /* ======================================================================
       Remediation editor
       ====================================================================== */

    function openRemediation(a, findingId) {
        Promise.all([
            api.get('/findings/' + findingId, null, { silent: true }),
            DXB.meta()
        ]).then(function (results) {
            var f = results[0].data;
            var meta = results[1];
            var r = f.remediation || {};

            DXB.modal({
                title: 'Remediation - ' + f.ref_code + ' ' + f.title,
                size: 'xwide',
                body:
                    '<div class="split"><div>' +
                        ui.field('Recommendation',
                            '<textarea name="recommendation" id="recField" rows="8">' + esc(r.recommendation || '') + '</textarea>',
                            'Specific and actionable. This is printed verbatim in the report.') +
                        ui.field('Reference implementation',
                            '<textarea name="secure_code_example" rows="10" class="mono">' + esc(r.secure_code_example || '') + '</textarea>') +
                        ui.field('References', '<textarea name="reference_links" rows="3">' + esc(r.reference_links || '') + '</textarea>') +
                        ui.field('Notes', '<textarea name="notes" rows="3">' + esc(r.notes || '') + '</textarea>') +
                        (ui.can('ai.use')
                            ? '<button type="button" class="btn sm" id="btnRemDraft">Draft remediation with AI</button>' +
                              '<span class="small dim" style="margin-left:9px">Uses the curated knowledge base, or the local model when it is running.</span>'
                            : '') +
                    '</div><div>' +
                        '<div class="card mb2"><header><h3>Tracking</h3></header><div class="body">' +
                            ui.field('Status', ui.select('status', meta.remediation_status.map(function (s) {
                                return { value: s, label: fmt.label(s) };
                            }), r.status || 'not_started'),
                                'Marking "verified" requires a retest with a fixed result.') +
                            ui.field('Status note', '<input type="text" name="status_note" placeholder="Recorded in the remediation history">') +
                            '<div class="grid c2">' +
                                ui.field('Owner', '<input type="text" name="owner_name" value="' + attr(r.owner_name || '') + '">') +
                                ui.field('Team', '<input type="text" name="owner_team" value="' + attr(r.owner_team || '') + '">') +
                            '</div>' +
                            '<div class="grid c2">' +
                                ui.field('Target date', '<input type="date" name="due_date" value="' + attr(r.due_date || '') + '">') +
                                ui.field('Effort', ui.select('effort', meta.effort.map(function (e) {
                                    return { value: e, label: fmt.label(e) };
                                }), r.effort || 'medium')) +
                            '</div>' +
                            '<div class="small dim">Severity ' + esc(f.severity) + ' carries a ' + (r.sla_days || '-') +
                                ' day remediation target from the published SLA table.</div>' +
                        '</div></div>' +

                        (r.history && r.history.length
                            ? '<div class="card"><header><h3>History</h3></header><div class="body"><div class="timeline">' +
                              r.history.map(function (h) {
                                  return '<div class="ti"><div class="tm">' + esc(fmt.date(h.created_at, true)) + ' &middot; ' + esc(h.actor_name || '') + '</div>' +
                                      '<div class="small">' + esc(fmt.label(h.from_status || 'new')) + ' &rarr; <b>' + esc(fmt.label(h.to_status)) + '</b></div>' +
                                      (h.note ? '<div class="small dim">' + esc(h.note) + '</div>' : '') + '</div>';
                              }).join('') + '</div></div></div>'
                            : '') +
                    '</div></div>',
                actions: [
                    { label: 'Close' },
                    ui.can('retest.record') ? {
                        label: 'Record retest', close: true,
                        onClick: function () { setTimeout(function () { retestDialog(a, f.id, f.ref_code, f.title); }, 60); }
                    } : null,
                    ui.can('remediation.edit') ? {
                        label: 'Save', kind: 'primary', close: false,
                        onClick: function (bodyEl, close, button) {
                            button.disabled = true;
                            api.put('/findings/' + f.id + '/remediation', ui.readForm(bodyEl)).then(function () {
                                close();
                                DXB.resolveRoute();
                            }).catch(function (error) {
                                DXB.toast(error.message, 'bad', 9000);
                                button.disabled = false;
                            });
                            return false;
                        }
                    } : null
                ].filter(Boolean),
                onMount: function (bodyEl) {
                    var draft = $('#btnRemDraft', bodyEl);
                    if (!draft) { return; }
                    draft.addEventListener('click', function () {
                        draft.disabled = true;
                        draft.textContent = 'Drafting...';
                        api.post('/ai/remediation', { finding_id: f.id }, { silent: true }).then(function (payload) {
                            $('#recField', bodyEl).value = payload.data.recommendation;
                            var codeField = bodyEl.querySelector('textarea[name=secure_code_example]');
                            if (payload.data.secure_code && !codeField.value.trim()) { codeField.value = payload.data.secure_code; }
                            DXB.toast(payload.data.fallback
                                ? 'Drafted from the curated knowledge base.'
                                : 'Drafted with the local model ' + payload.data.model + '.', 'ok');
                        }).catch(function (error) { DXB.toast(error.message, 'bad'); })
                          .finally(function () {
                              draft.disabled = false;
                              draft.textContent = 'Draft remediation with AI';
                          });
                    });
                }
            });
        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
    }

    /* ======================================================================
       Retest
       ====================================================================== */

    function retestDialog(a, findingId, refCode, title) {
        DXB.meta().then(function (meta) {
            DXB.modal({
                title: 'Record retest - ' + refCode,
                size: 'wide',
                body:
                    '<div class="callout info small"><b>' + esc(title) + '</b><br>' +
                        'A "fixed" result closes the finding and marks the remediation verified. Anything else reopens it for another round.</div>' +
                    '<div class="grid c2">' +
                        ui.field('Result', ui.select('result', meta.retest_results.map(function (r) {
                            return { value: r, label: fmt.label(r) };
                        }), 'fixed')) +
                        ui.field('Retest date', '<input type="date" name="retest_date" value="' + attr(todayIso()) + '">') +
                    '</div>' +
                    ui.field('Method', '<input type="text" name="method" placeholder="Replayed the original request in Burp Repeater at security level low">',
                        'How the retest was performed, so it can be repeated.') +
                    ui.field('Observation', '<textarea name="observation" rows="5" placeholder="What the application did this time, and why that confirms the outcome."></textarea>') +
                    ui.field('Residual severity (if not fully fixed)', ui.select('residual_severity',
                        [{ value: '', label: 'Derive automatically' }].concat(
                            meta.severities.slice().reverse().map(function (s) { return { value: s, label: fmt.label(s) }; })), '')) +
                    ui.field('Retest evidence', '<textarea name="evidence_text" rows="7" class="mono" placeholder="Paste the request/response from the retest. Stored as hashed evidence linked to this round."></textarea>'),
                actions: [
                    { label: 'Cancel' },
                    {
                        label: 'Record retest', kind: 'primary', close: false,
                        onClick: function (bodyEl, close, button) {
                            button.disabled = true;
                            api.post('/findings/' + findingId + '/retests', ui.readForm(bodyEl)).then(function () {
                                close();
                                DXB.resolveRoute();
                            }).catch(function (error) {
                                DXB.toast(error.message, 'bad', 9000);
                                button.disabled = false;
                            });
                            return false;
                        }
                    }
                ]
            });
        });
    }

    function todayIso() {
        var d = new Date();
        return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    }

}(window.DXB));
