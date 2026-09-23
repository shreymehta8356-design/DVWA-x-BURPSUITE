/* ==========================================================================
   Findings tab - create, classify and rate findings.
   Contains the interactive risk calculator (5x5 matrix + CVSS v3.1), the
   duplicate-detection guard and the AI drafting controls.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api,
        charts = DXB.charts, $ = DXB.$, $$ = DXB.$$;

    var filters = { severity: '', status: '', search: '' };

    DXB.tabs.findings = function (a, panel) {
        panel.innerHTML =
            '<div class="filters">' +
                '<input type="search" class="grow" id="fSearch" placeholder="Search findings..." value="' + attr(filters.search) + '">' +
                '<select id="fSeverity"></select><select id="fStatus"></select>' +
                '<div class="spacer"></div>' +
                (ui.can('finding.create') ? '<button class="btn sm primary" id="newFinding">New finding</button>' : '') +
            '</div>' +
            '<div id="findingList">' + ui.loading() + '</div>';

        DXB.meta().then(function (meta) {
            $('#fSeverity').innerHTML = opts([{ value: '', label: 'Any severity' }].concat(
                meta.severities.slice().reverse().map(function (s) { return { value: s, label: fmt.label(s) }; })), filters.severity);
            $('#fStatus').innerHTML = opts([{ value: '', label: 'Any status' }].concat(
                meta.finding_status.map(function (s) { return { value: s, label: fmt.label(s) }; })), filters.status);
        });

        var debounce;
        $('#fSearch').addEventListener('input', function () {
            filters.search = this.value;
            clearTimeout(debounce);
            debounce = setTimeout(load, 250);
        });
        $('#fSeverity').addEventListener('change', function () { filters.severity = this.value; load(); });
        $('#fStatus').addEventListener('change', function () { filters.status = this.value; load(); });
        if ($('#newFinding')) {
            $('#newFinding').addEventListener('click', function () { DXB.findingEditor(a, null, {}); });
        }

        function load() {
            api.get('/assessments/' + a.id + '/findings', filters, { silent: true }).then(function (payload) {
                $('#findingList').innerHTML = renderList(payload.data);
                DXB.on($('#findingList'), 'click', '[data-finding]', function (event, el) {
                    DXB.openFinding(a, parseInt(el.getAttribute('data-finding'), 10));
                });
            }).catch(function (error) { $('#findingList').innerHTML = ui.error(error.message); });
        }
        load();

        // Deep link support: #/assessment/1/findings?finding=12
        var deep = (window.location.hash.split('?')[1] || '').match(/finding=(\d+)/);
        if (deep) { DXB.openFinding(a, parseInt(deep[1], 10)); }
    };

    function opts(list, selected) {
        return list.map(function (o) {
            return '<option value="' + attr(o.value) + '"' + (String(o.value) === String(selected) ? ' selected' : '') + '>' + esc(o.label) + '</option>';
        }).join('');
    }

    function renderList(rows) {
        if (!rows.length) {
            return ui.empty('No findings recorded.',
                'Findings normally come from a failing check, or from promoting a Burp Suite issue.');
        }
        return '<div class="card"><div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th style="width:62px">Ref</th><th>Finding</th><th style="width:86px">Severity</th>' +
            '<th style="width:56px" class="num">CVSS</th><th style="width:126px">Status</th>' +
            '<th style="width:118px">Remediation</th><th style="width:86px">Due</th><th style="width:64px" class="num">Ev.</th>' +
            '</tr></thead><tbody>' +
            rows.map(function (f) {
                return '<tr class="clickable" data-finding="' + f.id + '">' +
                    '<td class="mono small">' + esc(f.ref_code) + '</td>' +
                    '<td><b>' + esc(f.title) + '</b>' +
                        '<div class="small dim">' + esc(f.vuln_class || 'Unclassified') +
                            (f.cwe_id ? ' &middot; ' + esc(f.cwe_id) : '') +
                            (f.test_code ? ' &middot; ' + esc(f.test_code) : '') + '</div></td>' +
                    '<td>' + fmt.sev(f.severity) + '</td>' +
                    '<td class="num small">' + (f.cvss_base_score !== null ? esc(Number(f.cvss_base_score).toFixed(1)) : '-') + '</td>' +
                    '<td>' + fmt.result(f.status) + '</td>' +
                    '<td>' + (f.remediation_status ? fmt.result(f.remediation_status) : '<span class="dim small">-</span>') + '</td>' +
                    '<td class="small' + (f.is_overdue ? '" style="color:var(--critical);font-weight:600' : '') + '">' +
                        (f.due_date ? esc(fmt.date(f.due_date)) : '-') + '</td>' +
                    '<td class="num small">' + f.evidence_count + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table></div></div>';
    }

    /* ======================================================================
       Finding detail
       ====================================================================== */

    DXB.openFinding = function (a, findingId) {
        api.get('/findings/' + findingId, null, { silent: true }).then(function (payload) {
            var f = payload.data;
            DXB.modal({
                title: f.ref_code + ' - ' + f.title,
                size: 'xwide',
                body: detailBody(f),
                actions: [
                    { label: 'Close' },
                    ui.can('finding.edit') ? {
                        label: 'Edit', close: true,
                        onClick: function () { setTimeout(function () { DXB.findingEditor(a, f, {}); }, 60); }
                    } : null
                ].filter(Boolean),
                onMount: function (bodyEl) { wireDetail(a, f, bodyEl); }
            });
        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
    };

    function detailBody(f) {
        var risk = f.risk_detail || {};
        var cvss = risk.cvss;

        return '<div class="split">' +
            '<div>' +
                '<div class="card mb2"><header><h3>Description</h3><div class="spacer"></div>' +
                    fmt.sev(f.severity) + fmt.result(f.status) + '</header><div class="body">' +
                    para(f.description) +
                    (f.impact_narrative ? '<h4 class="mt2">Business impact</h4>' + para(f.impact_narrative) : '') +
                    (f.reproduction_steps ? '<h4 class="mt2">Steps to reproduce</h4><pre class="code">' + esc(f.reproduction_steps) + '</pre>' : '') +
                '</div></div>' +

                '<div class="card mb2"><header><h3>How this severity was derived</h3></header><div class="body">' +
                    '<div class="callout info" style="white-space:pre-wrap">' + esc(f.severity_rationale || 'Not recorded.') + '</div>' +
                    '<div class="grid c2">' +
                        '<div><h4>Qualitative matrix</h4><dl class="kv">' +
                            '<dt>Likelihood</dt><dd>' + f.likelihood + '</dd>' +
                            '<dt>Impact</dt><dd>' + f.impact + '</dd>' +
                            '<dt>Score</dt><dd>' + (f.matrix_score || '-') + '</dd>' +
                            '<dt>Band</dt><dd>' + fmt.sev(f.matrix_band) + '</dd>' +
                        '</dl></div>' +
                        '<div><h4>CVSS v3.1</h4>' +
                            (cvss
                                ? '<dl class="kv">' +
                                    '<dt>Base score</dt><dd><b>' + esc(cvss.base_score) + '</b> ' + fmt.sev(cvss.band) + '</dd>' +
                                    '<dt>Vector</dt><dd class="mono small wrap-any">' + esc(cvss.vector) + '</dd>' +
                                    '<dt>Impact SS</dt><dd>' + esc(cvss.impact_subscore) + '</dd>' +
                                    '<dt>Exploitability SS</dt><dd>' + esc(cvss.exploitability_subscore) + '</dd>' +
                                  '</dl>' +
                                  '<div class="small dim mt1">' + Object.keys(cvss.metrics_readable || {}).map(function (k) {
                                      return esc(k) + ': ' + esc(cvss.metrics_readable[k]);
                                  }).join(' &middot; ') + '</div>'
                                : '<p class="dim small">No CVSS vector recorded for this finding.</p>') +
                        '</div>' +
                    '</div>' +
                '</div></div>' +

                (f.evidence.length
                    ? '<div class="card mb2"><header><h3>Evidence</h3><div class="spacer"></div>' +
                      '<span class="small dim">' + f.evidence.length + ' item(s)</span></header><div class="body">' +
                      f.evidence.map(evidenceBlock).join('') + '</div></div>'
                    : '<div class="callout warn">No evidence is attached to this finding. Attach the request, response or screenshot that proves it before the report is finalised.</div>') +

                (f.retests.length
                    ? '<div class="card"><header><h3>Retest history</h3></header><div class="body"><div class="timeline">' +
                      f.retests.map(function (r) {
                          return '<div class="ti"><div class="tm">Round ' + r.round_no + ' &middot; ' + esc(fmt.date(r.retest_date)) +
                              ' &middot; ' + esc(r.tester_name || '') + '</div>' +
                              '<div>' + fmt.result(r.result) + ' <b class="small">' + esc(r.method) + '</b></div>' +
                              '<div class="small dim mt1">' + esc(r.observation) + '</div></div>';
                      }).join('') + '</div></div></div>'
                    : '') +
            '</div>' +

            '<div>' +
                '<div class="card mb2"><header><h3>Classification</h3></header><div class="body small">' +
                    '<dl class="kv">' +
                        '<dt>Reference</dt><dd class="mono">' + esc(f.ref_code) + '</dd>' +
                        '<dt>Class</dt><dd>' + esc(f.vuln_class || '-') + '</dd>' +
                        '<dt>CWE</dt><dd>' + esc(f.cwe_id || '-') + '</dd>' +
                        '<dt>OWASP</dt><dd>' + esc(f.owasp_top10 || '-') + '</dd>' +
                        '<dt>Component</dt><dd>' + esc(f.affected_component || '-') + '</dd>' +
                        '<dt>URL</dt><dd class="mono wrap-any">' + esc(f.affected_url || '-') + '</dd>' +
                        '<dt>Confidence</dt><dd>' + esc(fmt.label(f.confidence)) + '</dd>' +
                        '<dt>Raised by</dt><dd>' + esc(f.created_by_name || '-') + '</dd>' +
                        '<dt>Raised on</dt><dd>' + esc(fmt.date(f.created_at, true)) + '</dd>' +
                        (f.duplicate_of_ref ? '<dt>Duplicate of</dt><dd class="mono">' + esc(f.duplicate_of_ref) + '</dd>' : '') +
                    '</dl>' +
                '</div></div>' +

                (ui.can('finding.edit')
                    ? '<div class="card mb2"><header><h3>Lifecycle</h3></header><div class="body">' +
                        '<div class="btn-row">' +
                            ['in_remediation', 'ready_for_retest', 'resolved', 'risk_accepted', 'false_positive'].map(function (s) {
                                return '<button class="btn xs' + (f.status === s ? ' primary' : '') + '" data-status="' + s + '">' +
                                    esc(fmt.label(s)) + '</button>';
                            }).join('') +
                        '</div>' +
                        '<p class="small dim mt2">A finding can only be marked resolved once a retest has recorded a "fixed" result. ' +
                        'Accepting risk or marking a false positive requires a written justification.</p>' +
                        (ui.can('finding.delete')
                            ? '<button class="btn xs danger mt1" data-delete-finding>Delete finding</button>' : '') +
                      '</div></div>'
                    : '') +

                (f.remediation
                    ? '<div class="card"><header><h3>Remediation</h3><div class="spacer"></div>' +
                        fmt.result(f.remediation.status) + '</header><div class="body small">' +
                        '<dl class="kv mb2">' +
                            '<dt>Owner</dt><dd>' + esc(f.remediation.owner_name || 'Unassigned') + '</dd>' +
                            '<dt>Due</dt><dd>' + esc(fmt.date(f.remediation.due_date)) +
                                (f.remediation.is_overdue ? ' <span class="badge bad">overdue</span>' : '') + '</dd>' +
                            '<dt>Effort</dt><dd>' + esc(fmt.label(f.remediation.effort)) + '</dd>' +
                        '</dl>' +
                        '<div class="small">' + esc(String(f.remediation.recommendation || '').slice(0, 400)) +
                            (String(f.remediation.recommendation || '').length > 400 ? '...' : '') + '</div>' +
                        '<a class="btn xs mt2" href="#/assessment/' + f.assessment_id + '/remediation">Open remediation tracker</a>' +
                      '</div></div>'
                    : '') +
            '</div>' +
        '</div>';
    }

    function evidenceBlock(item) {
        return '<div class="ev-card mb1"><div class="eh">' +
            '<b class="small">' + esc(item.title) + '</b>' +
            '<span class="badge mute">' + esc(fmt.label(item.evidence_type)) + '</span>' +
            (item.is_redacted ? '<span class="badge accent" title="' + attr(item.redaction_summary || '') + '">redacted</span>' : '') +
            '<div class="spacer"></div>' +
            '<span class="small dim">' + esc(item.collected_by_name || '') + ' &middot; ' + esc(fmt.date(item.captured_at, true)) + '</span>' +
        '</div><div class="eb">' +
            (item.description ? '<p class="small">' + esc(item.description) + '</p>' : '') +
            (item.content_text ? '<pre class="code">' + esc(String(item.content_text).slice(0, 6000)) + '</pre>' : '') +
            (item.has_file && item.is_image
                ? '<img class="ev-img" alt="' + attr(item.title) + '" src="' + attr(DXB.apiBase + '/evidence/' + item.id + '/file') + '">'
                : (item.has_file ? '<a class="btn xs" href="' + attr(DXB.apiBase + '/evidence/' + item.id + '/file') + '">Download artefact</a>' : '')) +
            '<div class="hash mt1">SHA-256 ' + esc(item.sha256) + '</div>' +
        '</div></div>';
    }

    function para(text) {
        if (!text) { return '<p class="dim small">Not recorded.</p>'; }
        return String(text).split(/\n{2,}/).map(function (block) {
            return '<p>' + esc(block).replace(/\n/g, '<br>') + '</p>';
        }).join('');
    }

    function wireDetail(a, f, bodyEl) {
        DXB.on(bodyEl, 'click', '[data-status]', function (event, el) {
            var status = el.getAttribute('data-status');
            var needsNote = status === 'risk_accepted' || status === 'false_positive';
            DXB.modal({
                title: 'Set status: ' + fmt.label(status),
                body: (needsNote
                        ? '<div class="callout warn">A written justification is required and will be printed in the report.</div>'
                        : '') +
                    ui.field('Note', '<textarea name="note" rows="3" placeholder="' +
                        (needsNote ? 'Why is this risk being accepted, or why is it not a real issue?' : 'Optional note') + '"></textarea>'),
                actions: [
                    { label: 'Cancel' },
                    {
                        label: 'Apply', kind: 'primary', close: false,
                        onClick: function (inner, close) {
                            api.post('/findings/' + f.id + '/status', {
                                status: status, note: $('textarea[name=note]', inner).value
                            }).then(function () {
                                close();
                                DXB.resolveRoute();
                                $$('.modal-backdrop').forEach(function (m) { m.remove(); });
                            }).catch(function (error) { DXB.toast(error.message, 'bad', 9000); });
                            return false;
                        }
                    }
                ]
            });
        });

        DXB.on(bodyEl, 'click', '[data-delete-finding]', function () {
            DXB.confirm({
                title: 'Delete ' + f.ref_code + '?',
                message: 'This removes the finding, its remediation record and its retest history.',
                detail: 'Prefer "false positive" if the finding was raised in error - it keeps the decision on record.',
                confirmLabel: 'Delete'
            }).then(function (ok) {
                if (!ok) { return; }
                api.del('/findings/' + f.id).then(function () {
                    $$('.modal-backdrop').forEach(function (m) { m.remove(); });
                    DXB.resolveRoute();
                }).catch(function (error) { DXB.toast(error.message, 'bad'); });
            });
        });
    }

    /* ======================================================================
       Finding editor with the live risk calculator
       ====================================================================== */

    DXB.findingEditor = function (a, existing, prefill) {
        Promise.all([DXB.meta(), api.get('/risk/matrix', null, { silent: true })]).then(function (results) {
            var meta = results[0];
            var matrixData = results[1].data;
            var f = existing || {};
            var values = Object.assign({
                title: '', vuln_class: '', cwe_id: '', owasp_top10: '', affected_component: '',
                affected_url: a.target_base_url, description: '', impact_narrative: '', reproduction_steps: '',
                likelihood: 3, impact: 3, cvss_vector: '', confidence: 'confirmed', test_id: ''
            }, prefill || {}, existing ? {
                title: f.title, vuln_class: f.vuln_class || '', cwe_id: f.cwe_id || '', owasp_top10: f.owasp_top10 || '',
                affected_component: f.affected_component || '', affected_url: f.affected_url || '',
                description: f.description || '', impact_narrative: f.impact_narrative || '',
                reproduction_steps: f.reproduction_steps || '', likelihood: f.likelihood, impact: f.impact,
                cvss_vector: f.cvss_vector || '', confidence: f.confidence, test_id: f.test_id || ''
            } : {});

            DXB.modal({
                title: existing ? 'Edit ' + f.ref_code : 'New finding',
                size: 'xwide',
                body: editorBody(meta, matrixData, values, a),
                actions: [
                    { label: 'Cancel' },
                    {
                        label: existing ? 'Save changes' : 'Create finding', kind: 'primary', close: false,
                        onClick: function (bodyEl, close, button) {
                            submit(a, existing, bodyEl, close, button);
                            return false;
                        }
                    }
                ],
                onMount: function (bodyEl) { wireEditor(a, existing, values, bodyEl); }
            });
        });
    };

    function editorBody(meta, matrixData, v, a) {
        return '<div class="split">' +
            '<div>' +
                '<div id="dupWarning"></div>' +
                ui.field('Title', '<input type="text" name="title" value="' + attr(v.title) + '" placeholder="Reflected cross-site scripting in the name parameter">') +
                '<div class="grid c2">' +
                    ui.field('Vulnerability class', ui.select('vuln_class',
                        [{ value: '', label: 'Not classified' }].concat(meta.vuln_classes.map(function (c) {
                            return { value: c, label: c };
                        })), v.vuln_class, 'id="vulnClass"')) +
                    ui.field('Confidence', ui.select('confidence', meta.confidence.map(function (c) {
                        return { value: c, label: fmt.label(c) };
                    }), v.confidence)) +
                '</div>' +
                '<div class="grid c2">' +
                    ui.field('CWE', '<input type="text" name="cwe_id" id="cweId" class="mono" value="' + attr(v.cwe_id) + '" placeholder="CWE-79">') +
                    ui.field('OWASP Top 10', '<input type="text" name="owasp_top10" id="owaspId" value="' + attr(v.owasp_top10) + '">') +
                '</div>' +
                '<div class="grid c2">' +
                    ui.field('Affected component', '<input type="text" name="affected_component" value="' + attr(v.affected_component) + '" placeholder="XSS (Reflected) module, name parameter">') +
                    ui.field('Affected URL', '<input type="text" name="affected_url" class="mono" value="' + attr(v.affected_url) + '">') +
                '</div>' +

                ui.field('Description',
                    '<textarea name="description" id="descField" rows="6" placeholder="What the weakness is, where it was found and what was observed.">' + esc(v.description) + '</textarea>') +
                ui.field('Business impact',
                    '<textarea name="impact_narrative" id="impactField" rows="4" placeholder="What an attacker gains and what that means for the business.">' + esc(v.impact_narrative) + '</textarea>') +
                ui.field('Steps to reproduce',
                    '<textarea name="reproduction_steps" rows="5" class="mono" placeholder="1. Browse to ...\n2. Submit the payload ...\n3. Observe ...">' + esc(v.reproduction_steps) + '</textarea>') +

                (ui.can('ai.use')
                    ? '<div class="btn-row"><button type="button" class="btn sm" id="btnDraft">Draft description with AI</button>' +
                      '<button type="button" class="btn sm" id="btnDupCheck">Check for duplicates</button></div>' +
                      '<div class="small dim mt1">Offline models run locally. Narrative drafting uses the local assistant when it is installed, ' +
                      'and deterministic templates otherwise - either way the text is labelled and you edit it before saving.</div>'
                    : '') +

                '<input type="hidden" name="test_id" value="' + attr(v.test_id) + '">' +
            '</div>' +

            '<div>' +
                '<div class="card mb2"><header><h3>Risk rating</h3></header><div class="body">' +
                    '<div id="riskResult" class="mb2"></div>' +
                    '<div class="mb2" id="matrixHost">' + charts.matrix(matrixData.matrix, {
                        selected: { likelihood: Number(v.likelihood), impact: Number(v.impact) }
                    }) + '</div>' +
                    '<div class="grid c2">' +
                        ui.field('Likelihood', '<input type="number" name="likelihood" id="likelihood" min="1" max="5" value="' + attr(v.likelihood) + '">') +
                        ui.field('Impact', '<input type="number" name="impact" id="impact" min="1" max="5" value="' + attr(v.impact) + '">') +
                    '</div>' +
                    ui.field('CVSS v3.1 vector',
                        '<input type="text" name="cvss_vector" id="cvssVector" class="mono" value="' + attr(v.cvss_vector) + '" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N">',
                        'Leave blank to rate on the matrix alone. Choosing a vulnerability class suggests a starting vector.') +
                    (ui.can('finding.severity')
                        ? ui.field('Override severity', ui.select('severity_override',
                            [{ value: '', label: 'Use the computed value' }].concat(
                                meta.severities.slice().reverse().map(function (s) { return { value: s, label: fmt.label(s) }; })), ''),
                            'An override is recorded with your name and printed in the report.')
                        : '') +
                '</div></div>' +
                '<div class="card"><header><h3>Assessment</h3></header><div class="body small">' +
                    '<dl class="kv"><dt>Reference</dt><dd class="mono">' + esc(a.ref_code) + '</dd>' +
                    '<dt>Target</dt><dd>' + esc(a.target_name) + '</dd></dl>' +
                '</div></div>' +
            '</div>' +
        '</div>';
    }

    function wireEditor(a, existing, values, bodyEl) {
        var likelihood = $('#likelihood', bodyEl);
        var impact = $('#impact', bodyEl);
        var vector = $('#cvssVector', bodyEl);
        var override = $('select[name=severity_override]', bodyEl);
        var timer;

        function recompute() {
            clearTimeout(timer);
            timer = setTimeout(function () {
                api.post('/risk/evaluate', {
                    likelihood: Number(likelihood.value),
                    impact: Number(impact.value),
                    cvss_vector: vector.value,
                    severity_override: override ? override.value : ''
                }, { silent: true }).then(function (payload) {
                    $('#riskResult', bodyEl).innerHTML = riskHtml(payload.data);
                    highlightCell(bodyEl, Number(likelihood.value), Number(impact.value));
                }).catch(function (error) {
                    $('#riskResult', bodyEl).innerHTML = ui.error(error.message);
                });
            }, 160);
        }

        [likelihood, impact, vector].forEach(function (input) {
            input.addEventListener('input', recompute);
            input.addEventListener('change', recompute);
        });
        if (override) { override.addEventListener('change', recompute); }

        DXB.on(bodyEl, 'click', '.matrix .cell', function (event, el) {
            likelihood.value = el.getAttribute('data-l');
            impact.value = el.getAttribute('data-i');
            recompute();
        });

        // Selecting a class fills in CWE, OWASP and a starting CVSS vector.
        $('#vulnClass', bodyEl).addEventListener('change', function () {
            var vulnClass = this.value;
            if (!vulnClass) { return; }
            api.post('/ai/triage', { observation: vulnClass + ' ' + $('#descField', bodyEl).value }, { silent: true })
                .then(function () { /* recorded for governance; suggestion below is deterministic */ })
                .catch(function () { /* non-fatal */ });
            var maps = DXB.classDefaults[vulnClass];
            if (maps) {
                $('#cweId', bodyEl).value = maps.cwe;
                $('#owaspId', bodyEl).value = maps.owasp;
                if (!vector.value) { vector.value = maps.vector; }
                recompute();
            }
        });

        var draftBtn = $('#btnDraft', bodyEl);
        if (draftBtn) {
            draftBtn.addEventListener('click', function () {
                var form = ui.readForm(bodyEl);
                if (!form.title) { DXB.toast('Give the finding a title first.', 'warn'); return; }
                draftBtn.disabled = true;
                draftBtn.textContent = 'Drafting...';
                api.post('/ai/narrative', {
                    assessment_id: a.id,
                    finding_id: existing ? existing.id : 0,
                    title: form.title, vuln_class: form.vuln_class,
                    affected_component: form.affected_component, affected_url: form.affected_url,
                    description: form.description, observation: form.description
                }, { silent: true }).then(function (payload) {
                    var data = payload.data;
                    if (data.description) { $('#descField', bodyEl).value = data.description; }
                    if (data.impact_narrative) { $('#impactField', bodyEl).value = data.impact_narrative; }
                    DXB.toast(data.fallback
                        ? 'Drafted from the built-in template (no local model is running).'
                        : 'Drafted with the local model ' + data.model + '. Review it before saving.', 'ok', 7000);
                }).catch(function (error) { DXB.toast(error.message, 'bad'); })
                  .finally(function () {
                      draftBtn.disabled = false;
                      draftBtn.textContent = 'Draft description with AI';
                  });
            });
        }

        var dupBtn = $('#btnDupCheck', bodyEl);
        if (dupBtn) {
            dupBtn.addEventListener('click', function () { runDuplicateCheck(a, existing, bodyEl); });
        }

        recompute();
    }

    function highlightCell(bodyEl, likelihood, impact) {
        $$('.matrix .cell', bodyEl).forEach(function (cell) {
            cell.classList.toggle('selected',
                Number(cell.getAttribute('data-l')) === likelihood && Number(cell.getAttribute('data-i')) === impact);
        });
    }

    function riskHtml(risk) {
        var cvss = risk.cvss;
        return '<div class="flex mb1" style="gap:10px">' +
                fmt.sev(risk.severity) +
                '<span class="small dim">from the ' + esc(risk.source) + ' input</span>' +
                '<div class="spacer"></div>' +
                '<span class="small">SLA ' + risk.sla_days + ' days</span>' +
            '</div>' +
            '<div class="callout info small" style="margin-bottom:0">' + esc(risk.rationale) + '</div>' +
            (risk.cvss_error ? '<div class="callout bad small mt1">' + esc(risk.cvss_error) + '</div>' : '') +
            (cvss
                ? '<div class="small dim mt1">CVSS base <b>' + esc(cvss.base_score) + '</b> &middot; impact ' +
                  esc(cvss.impact_subscore) + ' &middot; exploitability ' + esc(cvss.exploitability_subscore) + '</div>'
                : '');
    }

    function runDuplicateCheck(a, existing, bodyEl) {
        var form = ui.readForm(bodyEl);
        return api.post('/ai/duplicates', {
            assessment_id: a.id,
            title: form.title,
            description: form.description,
            exclude_finding_id: existing ? existing.id : 0
        }, { silent: true }).then(function (payload) {
            var data = payload.data;
            var host = $('#dupWarning', bodyEl);
            if (!data.matches.length) {
                host.innerHTML = '<div class="callout ok small">No similar finding in this assessment (TF-IDF cosine similarity, threshold ' +
                    Math.round(data.threshold * 100) + '%).</div>';
                return data;
            }
            host.innerHTML = '<div class="callout ' + (data.duplicate_suspected ? 'warn' : 'info') + ' small">' +
                '<b>' + (data.duplicate_suspected ? 'Possible duplicate.' : 'Similar findings exist.') + '</b> ' +
                'Similarity computed offline with TF-IDF cosine distance.' +
                '<div class="mt1">' + data.matches.map(function (m) {
                    return '<div class="flex" style="gap:8px;margin-top:4px">' +
                        '<span class="badge ' + (m.is_duplicate ? 'bad' : 'mute') + '">' + Math.round(m.similarity * 100) + '%</span>' +
                        '<span class="mono small">' + esc(m.ref_code) + '</span>' +
                        '<span class="truncate" style="flex:1">' + esc(m.title) + '</span>' +
                    '</div>';
                }).join('') + '</div></div>';
            return data;
        }).catch(function (error) { DXB.toast(error.message, 'bad'); return null; });
    }

    function submit(a, existing, bodyEl, close, button) {
        var data = ui.readForm(bodyEl);
        data.likelihood = Number(data.likelihood);
        data.impact = Number(data.impact);

        button.disabled = true;
        button.textContent = 'Saving...';

        var request = existing
            ? api.put('/findings/' + existing.id, data)
            : api.post('/assessments/' + a.id + '/findings', data);

        request.then(function () {
            close();
            DXB.resolveRoute();
        }).catch(function (error) {
            button.disabled = false;
            button.textContent = existing ? 'Save changes' : 'Create finding';

            if (error.payload && error.payload.code === 'duplicate_suspected') {
                var duplicates = error.payload.duplicates;
                DXB.modal({
                    title: 'Possible duplicate finding',
                    body: '<p>This finding looks very similar to something already recorded in this assessment:</p>' +
                        duplicates.matches.filter(function (m) { return m.is_duplicate; }).map(function (m) {
                            return '<div class="callout warn small"><b>' + esc(m.ref_code) + '</b> ' + esc(m.title) +
                                '<div class="dim mt1">Similarity ' + Math.round(m.similarity * 100) + '% &middot; shared terms: ' +
                                esc((m.shared_terms || []).join(', ')) + '</div></div>';
                        }).join('') +
                        '<p class="small dim">Duplicate findings inflate the report and the severity counts. Save anyway only if this is a genuinely separate issue.</p>',
                    actions: [
                        { label: 'Go back and edit' },
                        {
                            label: 'Save anyway', kind: 'primary', close: false,
                            onClick: function (inner, closeInner) {
                                data.ignore_duplicates = true;
                                api.post('/assessments/' + a.id + '/findings', data).then(function () {
                                    closeInner();
                                    close();
                                    DXB.resolveRoute();
                                }).catch(function (e2) { DXB.toast(e2.message, 'bad'); });
                                return false;
                            }
                        }
                    ]
                });
                return;
            }
            DXB.toast(error.message, 'bad', 9000);
        });
    }

    /* Deterministic class defaults mirrored from RiskEngine, so selecting a
       class fills the references without a server round trip. */
    DXB.classDefaults = {
        'SQL Injection':                   { cwe: 'CWE-89',  owasp: 'A03:2021 Injection', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
        'Cross-Site Scripting':            { cwe: 'CWE-79',  owasp: 'A03:2021 Injection', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
        'Command Injection':               { cwe: 'CWE-78',  owasp: 'A03:2021 Injection', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
        'Path Traversal / File Inclusion': { cwe: 'CWE-22',  owasp: 'A01:2021 Broken Access Control', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
        'Cross-Site Request Forgery':      { cwe: 'CWE-352', owasp: 'A01:2021 Broken Access Control', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N' },
        'Insecure File Upload':            { cwe: 'CWE-434', owasp: 'A04:2021 Insecure Design', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
        'Broken Authentication':           { cwe: 'CWE-287', owasp: 'A07:2021 Identification and Authentication Failures', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
        'Session Management':              { cwe: 'CWE-384', owasp: 'A07:2021 Identification and Authentication Failures', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
        'Broken Access Control':           { cwe: 'CWE-284', owasp: 'A01:2021 Broken Access Control', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N' },
        'Open Redirect':                   { cwe: 'CWE-601', owasp: 'A01:2021 Broken Access Control', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N' },
        'Security Misconfiguration':       { cwe: 'CWE-16',  owasp: 'A05:2021 Security Misconfiguration', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
        'Information Disclosure':          { cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
        'Cryptographic Failure':           { cwe: 'CWE-327', owasp: 'A02:2021 Cryptographic Failures', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
        'Business Logic Flaw':             { cwe: 'CWE-840', owasp: 'A04:2021 Insecure Design', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N' },
        'Server-Side Request Forgery':     { cwe: 'CWE-918', owasp: 'A10:2021 Server-Side Request Forgery', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N' }
    };

}(window.DXB));
