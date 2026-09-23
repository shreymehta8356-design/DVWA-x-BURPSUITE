/* ==========================================================================
   Security checks tab - execute predefined checks and record PASS / FAIL /
   MANUAL REVIEW / NOT APPLICABLE with an observation and captured traffic.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, $ = DXB.$, $$ = DXB.$$;

    var filters = { status: '', category: '', search: '' };

    DXB.tabs.tests = function (a, panel) {
        panel.innerHTML =
            '<div class="filters">' +
                '<input type="search" class="grow" id="tSearch" placeholder="Search checks by code, title or observation..." value="' + attr(filters.search) + '">' +
                '<select id="tStatus"></select>' +
                '<select id="tCategory"></select>' +
                '<div class="spacer"></div>' +
                (ui.can('assessment.edit') ? '<button class="btn sm" id="addChecks">Add checks to plan</button>' : '') +
            '</div>' +
            '<div id="testList">' + ui.loading() + '</div>';

        DXB.meta().then(function (meta) {
            $('#tStatus').innerHTML = optionList([{ value: '', label: 'Any result' }].concat(
                meta.test_results.map(function (r) { return { value: r, label: fmt.label(r) }; })), filters.status);
            $('#tCategory').innerHTML = optionList([{ value: '', label: 'All categories' }].concat(
                meta.categories.map(function (c) { return { value: c, label: c }; })), filters.category);
        });

        var debounce;
        $('#tSearch').addEventListener('input', function () {
            filters.search = this.value;
            clearTimeout(debounce);
            debounce = setTimeout(load, 250);
        });
        $('#tStatus').addEventListener('change', function () { filters.status = this.value; load(); });
        $('#tCategory').addEventListener('change', function () { filters.category = this.value; load(); });
        if ($('#addChecks')) { $('#addChecks').addEventListener('click', function () { addChecksDialog(a); }); }

        function load() {
            api.get('/assessments/' + a.id + '/tests', filters, { silent: true }).then(function (payload) {
                $('#testList').innerHTML = renderList(payload.data);
                DXB.on($('#testList'), 'click', '[data-test]', function (event, el) {
                    openTest(a, parseInt(el.getAttribute('data-test'), 10));
                });
            }).catch(function (error) { $('#testList').innerHTML = ui.error(error.message); });
        }
        load();
    };

    function optionList(options, selected) {
        return options.map(function (option) {
            return '<option value="' + attr(option.value) + '"' +
                (String(option.value) === String(selected) ? ' selected' : '') + '>' + esc(option.label) + '</option>';
        }).join('');
    }

    function renderList(rows) {
        if (!rows.length) {
            return ui.empty('No checks match these filters.',
                'Use "Add checks to plan" to bring predefined checks in from the catalogue.');
        }

        var grouped = {};
        rows.forEach(function (row) {
            (grouped[row.category] = grouped[row.category] || []).push(row);
        });

        return Object.keys(grouped).map(function (category) {
            var items = grouped[category];
            var done = items.filter(function (t) { return t.status !== 'pending' && t.status !== 'in_progress'; }).length;
            return '<div class="card mb2">' +
                '<header><h3>' + esc(category) + '</h3><div class="spacer"></div>' +
                    '<span class="small dim">' + done + ' / ' + items.length + ' executed</span></header>' +
                items.map(row).join('') +
            '</div>';
        }).join('');
    }

    function row(t) {
        var flags = '';
        if (t.evidence_count > 0) { flags += '<span class="badge mute" title="Evidence attached">' + t.evidence_count + ' ev</span> '; }
        if (t.finding_count > 0) { flags += '<span class="badge sev-high" title="Findings raised">' + t.finding_count + ' finding</span> '; }
        if (t.review_status === 'approved') { flags += '<span class="badge ok" title="Peer reviewed">reviewed</span> '; }
        if (t.review_status === 'rework') { flags += '<span class="badge warn">rework</span> '; }
        if (t.ai_category) {
            flags += '<span class="badge accent" title="Offline classifier suggestion">' +
                esc(t.ai_category) + ' ' + Math.round((t.ai_confidence || 0) * 100) + '%</span> ';
        }

        return '<div class="test-row" data-test="' + t.id + '">' +
            '<div class="code">' + esc(t.code) + '</div>' +
            '<div class="ttl">' +
                '<b>' + esc(t.title) + '</b>' +
                '<div class="meta">' + esc(t.owasp_top10 || '') +
                    (t.dvwa_module ? ' &middot; DVWA: ' + esc(t.dvwa_module) : '') +
                    (t.cwe_id ? ' &middot; ' + esc(t.cwe_id) : '') + '</div>' +
                (t.observation ? '<div class="small dim mt1 truncate" style="max-width:820px">' + esc(t.observation) + '</div>' : '') +
                (flags ? '<div class="mt1">' + flags + '</div>' : '') +
            '</div>' +
            '<div class="rt">' + fmt.result(t.status) + '</div>' +
        '</div>';
    }

    /* ======================================================================
       Check execution dialog
       ====================================================================== */

    function openTest(a, testId) {
        api.get('/tests/' + testId, null, { silent: true }).then(function (payload) {
            var t = payload.data;
            var dialog = DXB.modal({
                title: t.code + ' - ' + t.title,
                size: 'xwide',
                body: testBody(t),
                actions: [
                    { label: 'Close' },
                    ui.can('test.execute') ? {
                        label: 'Save result', kind: 'primary', close: false,
                        onClick: function (bodyEl, close, button) { saveResult(a, t, bodyEl, close, button); return false; }
                    } : null
                ].filter(Boolean),
                onMount: function (bodyEl) { wire(a, t, bodyEl); }
            });
            return dialog;
        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
    }

    function testBody(t) {
        return '<div class="split">' +
            '<div>' +
                '<div class="card mb2"><header><h3>Record result</h3><div class="spacer"></div>' +
                    fmt.result(t.status) + '</header><div class="body">' +
                    '<div class="btn-row mb2" id="resultButtons">' +
                        ['pass', 'fail', 'manual_review', 'not_applicable'].map(function (value) {
                            return '<button type="button" class="btn sm' + (t.status === value ? ' primary' : '') +
                                '" data-result="' + value + '">' + esc(fmt.label(value)) + '</button>';
                        }).join('') +
                        '<input type="hidden" name="status" value="' + attr(t.status === 'pending' ? '' : t.status) + '">' +
                    '</div>' +

                    ui.field('Observation',
                        '<textarea name="observation" rows="5" placeholder="What did you send, what came back, and why does that pass or fail? Be specific enough that another analyst could repeat it.">' +
                        esc(t.observation || '') + '</textarea>',
                        'A FAIL or MANUAL REVIEW needs at least 20 characters. This text is what the offline classifier reads.') +

                    '<div class="grid c2">' +
                        ui.field('Payload used', '<input type="text" name="payload_used" class="mono" value="' + attr(t.payload_used || '') + '" placeholder="1&#39; OR &#39;1&#39;=&#39;1">') +
                        ui.field('DVWA security level', ui.select('dvwa_security_level',
                            [{ value: '', label: 'Not applicable' }, { value: 'low', label: 'Low' },
                             { value: 'medium', label: 'Medium' }, { value: 'high', label: 'High' },
                             { value: 'impossible', label: 'Impossible' }], t.dvwa_security_level || '')) +
                    '</div>' +

                    '<div class="grid c2">' +
                        ui.field('Captured request',
                            '<textarea name="request_snippet" rows="7" class="mono" placeholder="Paste the raw request from Burp (right-click > Copy to file / Copy as ...)"></textarea>',
                            'Stored as hashed evidence. Secrets are redacted automatically.') +
                        ui.field('Captured response',
                            '<textarea name="response_snippet" rows="7" class="mono" placeholder="Paste the raw response, or just the relevant portion"></textarea>',
                            'Truncate long bodies to the part that evidences the result.') +
                    '</div>' +

                    '<div class="btn-row">' +
                        (ui.can('ai.use') ? '<button type="button" class="btn sm" id="btnTriage">Suggest classification</button>' : '') +
                        '<button type="button" class="btn sm" id="btnRedactPreview">Preview redaction</button>' +
                        (ui.can('finding.create') ? '<button type="button" class="btn sm" id="btnRaise">Raise finding from this check</button>' : '') +
                    '</div>' +
                    '<div id="aiOut" class="mt2"></div>' +
                '</div></div>' +

                (t.evidence && t.evidence.length ? evidenceCard(t.evidence) : '') +

                (ui.can('test.review') && t.status !== 'pending'
                    ? '<div class="card"><header><h3>Peer review</h3><div class="spacer"></div>' + fmt.result(t.review_status) + '</header>' +
                      '<div class="body">' +
                        (t.reviewed_by_name ? '<p class="small dim">Reviewed by ' + esc(t.reviewed_by_name) + ' on ' + esc(fmt.date(t.reviewed_at, true)) + '</p>' : '') +
                        (t.review_note ? '<p class="small">' + esc(t.review_note) + '</p>' : '') +
                        ui.field('Review note', '<input type="text" id="reviewNote" placeholder="Required when sending back for rework">') +
                        '<div class="btn-row">' +
                            '<button type="button" class="btn sm primary" data-review="approved">Approve</button>' +
                            '<button type="button" class="btn sm" data-review="rework">Send back for rework</button>' +
                        '</div>' +
                        '<p class="small dim mt1">Separation of duties: you cannot review a result you recorded yourself.</p>' +
                      '</div></div>'
                    : '') +
            '</div>' +

            '<div>' +
                '<div class="card mb2"><header><h3>What this check is for</h3></header><div class="body small">' +
                    '<dl class="kv mb2">' +
                        '<dt>Code</dt><dd class="mono">' + esc(t.code) + '</dd>' +
                        '<dt>Category</dt><dd>' + esc(t.category) + '</dd>' +
                        '<dt>OWASP</dt><dd>' + esc(t.owasp_top10 || '-') + '</dd>' +
                        '<dt>CWE</dt><dd>' + esc(t.cwe_id || '-') + '</dd>' +
                        (t.dvwa_module ? '<dt>DVWA module</dt><dd>' + esc(t.dvwa_module) + '</dd>' : '') +
                        '<dt>Default L/I</dt><dd>' + t.default_likelihood + ' / ' + t.default_impact + '</dd>' +
                    '</dl>' +
                    '<h4>Objective</h4><p>' + esc(t.test_objective || t.description || '') + '</p>' +
                    '<h4>How to test</h4><pre class="code">' + esc(t.test_steps || 'No steps recorded.') + '</pre>' +
                    '<h4>Expected secure behaviour</h4><p>' + esc(t.expected_secure_behaviour || '-') + '</p>' +
                    (t.tools_hint ? '<h4>Tools</h4><p class="dim">' + esc(t.tools_hint) + '</p>' : '') +
                '</div></div>' +
                (t.tested_by_name
                    ? '<div class="card"><header><h3>Execution record</h3></header><div class="body small">' +
                        '<dl class="kv">' +
                            '<dt>Tested by</dt><dd>' + esc(t.tested_by_name) + '</dd>' +
                            '<dt>Tested at</dt><dd>' + esc(fmt.date(t.tested_at, true)) + '</dd>' +
                            '<dt>Review</dt><dd>' + esc(fmt.label(t.review_status)) + '</dd>' +
                        '</dl></div></div>'
                    : '') +
            '</div>' +
        '</div>';
    }

    function evidenceCard(items) {
        return '<div class="card mb2"><header><h3>Evidence on this check</h3><div class="spacer"></div>' +
            '<span class="small dim">' + items.length + ' item(s)</span></header><div class="body">' +
            items.map(function (item) {
                return '<div class="ev-card mb1"><div class="eh">' +
                        '<b class="small">' + esc(item.title) + '</b>' +
                        '<span class="badge mute">' + esc(fmt.label(item.evidence_type)) + '</span>' +
                        (item.is_redacted ? '<span class="badge accent">redacted</span>' : '') +
                        '<div class="spacer"></div><span class="small dim">' + esc(fmt.date(item.captured_at, true)) + '</span>' +
                    '</div><div class="eb">' +
                        (item.content_text ? '<pre class="code">' + esc(String(item.content_text).slice(0, 4000)) + '</pre>' : '') +
                        '<div class="hash">SHA-256 ' + esc(item.sha256) + '</div>' +
                    '</div></div>';
            }).join('') + '</div></div>';
    }

    function wire(a, t, bodyEl) {
        // Result buttons behave as a radio group.
        DXB.on(bodyEl, 'click', '[data-result]', function (event, el) {
            $$('[data-result]', bodyEl).forEach(function (button) { button.classList.remove('primary'); });
            el.classList.add('primary');
            $('input[name=status]', bodyEl).value = el.getAttribute('data-result');
        });

        var triageBtn = $('#btnTriage', bodyEl);
        if (triageBtn) {
            triageBtn.addEventListener('click', function () {
                var observation = $('textarea[name=observation]', bodyEl).value;
                if (observation.trim().length < 12) {
                    DXB.toast('Write the observation first - the classifier reads it.', 'warn');
                    return;
                }
                triageBtn.disabled = true;
                triageBtn.textContent = 'Classifying...';
                api.post('/ai/triage', { observation: observation, assessment_id: a.id, test_id: t.id }, { silent: true })
                    .then(function (payload) { $('#aiOut', bodyEl).innerHTML = triageHtml(payload.data); })
                    .catch(function (error) { $('#aiOut', bodyEl).innerHTML = ui.error(error.message); })
                    .finally(function () {
                        triageBtn.disabled = false;
                        triageBtn.textContent = 'Suggest classification';
                    });
            });
        }

        $('#btnRedactPreview', bodyEl).addEventListener('click', function () {
            var text = $('textarea[name=request_snippet]', bodyEl).value + '\n' + $('textarea[name=response_snippet]', bodyEl).value;
            if (!text.trim()) { DXB.toast('Paste a request or response first.', 'warn'); return; }
            api.post('/ai/redact-preview', { text: text }, { silent: true }).then(function (payload) {
                var data = payload.data;
                DXB.modal({
                    title: 'Redaction preview',
                    size: 'wide',
                    body: (data.redactions === 0
                        ? '<div class="callout ok">Nothing matched the secret or personal-data patterns. The capture will be stored as-is.</div>'
                        : '<div class="callout warn"><b>' + data.redactions + ' item(s) would be removed:</b> ' + esc(data.summary) + '</div>') +
                        '<pre class="code tall">' + esc(data.preview) + '</pre>' +
                        '<p class="small dim">The SHA-256 recorded for this evidence covers the original capture, so integrity is still provable after redaction.</p>',
                    actions: [{ label: 'Close' }]
                });
            }).catch(function (error) { DXB.toast(error.message, 'bad'); });
        });

        var raiseBtn = $('#btnRaise', bodyEl);
        if (raiseBtn) {
            raiseBtn.addEventListener('click', function () {
                DXB.findingEditor(a, null, {
                    test_id: t.id,
                    title: t.title,
                    vuln_class: t.ai_category || '',
                    affected_component: t.dvwa_module || t.category,
                    affected_url: a.target_base_url,
                    description: t.observation || '',
                    likelihood: t.default_likelihood,
                    impact: t.default_impact,
                    cvss_vector: t.default_cvss_vector || '',
                    cwe_id: t.cwe_id || '',
                    owasp_top10: t.owasp_top10 || ''
                });
            });
        }

        DXB.on(bodyEl, 'click', '[data-review]', function (event, el) {
            api.post('/tests/' + t.id + '/review', {
                review_status: el.getAttribute('data-review'),
                note: ($('#reviewNote', bodyEl) || {}).value || ''
            }).then(function () { DXB.resolveRoute(); })
              .catch(function (error) { DXB.toast(error.message, 'bad', 8000); });
        });
    }

    function triageHtml(data) {
        if (!data.available) {
            return '<div class="callout warn">' + esc(data.reason) + '</div>';
        }
        var suggestion = data.suggestion;
        return '<div class="ai-panel">' +
            '<div class="h">&#9673; Offline classifier &mdash; Multinomial Naive Bayes</div>' +

            (data.label
                ? '<div class="flex mb1"><b style="font-size:15px">' + esc(data.label) + '</b>' +
                  '<span class="badge ' + (data.confident ? 'accent' : 'warn') + '">' +
                  Math.round(data.confidence * 100) + '% confidence</span></div>' +
                  '<div class="conf-bar"><i style="width:' + Math.round(data.confidence * 100) + '%"></i></div>' +
                  '<div class="small dim">Trained on ' + data.corpus.documents + ' examples, ' +
                    data.corpus.vocabulary + ' term vocabulary. Threshold ' + Math.round(data.threshold * 100) + '%.</div>'
                : '<div class="small">The classifier could not settle on a class from this text.</div>') +

            (data.evidence && data.evidence.length
                ? '<div class="mt2"><div class="small dim mb1">Terms that drove the decision:</div>' +
                  '<div class="ai-terms">' + data.evidence.map(function (e) {
                      return '<span class="t">' + esc(e.term) + '</span>';
                  }).join('') + '</div></div>'
                : '') +

            (data.ranking && data.ranking.length > 1
                ? '<div class="mt2 small dim">Alternatives: ' + data.ranking.slice(1).map(function (r) {
                    return esc(r.label) + ' ' + Math.round(r.probability * 100) + '%';
                  }).join(' &middot; ') + '</div>'
                : '') +

            (data.catalogue && data.catalogue.length
                ? '<div class="mt2 small dim">Closest catalogue check: <b class="mono">' + esc(data.catalogue[0].code) +
                  '</b> ' + esc(data.catalogue[0].title) + ' (similarity ' + Math.round(data.catalogue[0].score * 100) + '%)</div>'
                : '') +

            (suggestion
                ? '<div class="mt2" style="border-top:1px solid var(--line);padding-top:10px">' +
                  '<div class="small dim mb1">Suggested finding starting point:</div>' +
                  '<dl class="kv">' +
                    '<dt>Title</dt><dd>' + esc(suggestion.title) + '</dd>' +
                    '<dt>CWE / OWASP</dt><dd>' + esc(suggestion.cwe_id) + ' &middot; ' + esc(suggestion.owasp_top10) + '</dd>' +
                    '<dt>CVSS</dt><dd class="mono">' + esc(suggestion.cvss_vector) + ' = ' + esc(suggestion.cvss_score) +
                        ' (' + esc(suggestion.cvss_band) + ')</dd>' +
                    '<dt>Likelihood / Impact</dt><dd>' + suggestion.likelihood + ' / ' + suggestion.impact + '</dd>' +
                  '</dl></div>'
                : '') +

            '<div class="small dim mt2">' + esc(data.disclaimer) + '</div>' +
        '</div>';
    }

    function saveResult(a, t, bodyEl, close, button) {
        var data = ui.readForm(bodyEl);
        if (!data.status) {
            DXB.toast('Choose PASS, FAIL, MANUAL REVIEW or NOT APPLICABLE.', 'warn');
            return;
        }
        button.disabled = true;
        button.textContent = 'Saving...';
        api.post('/tests/' + t.id + '/result', data).then(function () {
            close();
            DXB.resolveRoute();
        }).catch(function (error) {
            DXB.toast(error.message, 'bad', 9000);
            button.disabled = false;
            button.textContent = 'Save result';
        });
    }

    /* ======================================================================
       Add checks from the catalogue
       ====================================================================== */

    function addChecksDialog(a) {
        api.get('/catalog', null, { silent: true }).then(function (payload) {
            var items = payload.data.items;
            DXB.modal({
                title: 'Add predefined checks to the plan',
                size: 'wide',
                body:
                    '<div class="filters"><input type="search" id="cSearch" class="grow" placeholder="Filter the catalogue..."></div>' +
                    '<div class="btn-row mb2">' +
                        '<button type="button" class="btn xs" data-select="all">Select all</button>' +
                        '<button type="button" class="btn xs" data-select="none">Clear</button>' +
                        '<span class="small dim" id="selCount"></span>' +
                    '</div>' +
                    '<div id="catList" style="max-height:430px;overflow:auto;border:1px solid var(--line);border-radius:6px">' +
                        catalogRows(items) +
                    '</div>' +
                    '<p class="small dim mt1">Checks already in the plan are skipped automatically.</p>',
                actions: [
                    { label: 'Cancel' },
                    {
                        label: 'Add selected', kind: 'primary', close: false,
                        onClick: function (bodyEl, close) {
                            var ids = $$('input[name=cat]:checked', bodyEl).map(function (i) { return parseInt(i.value, 10); });
                            if (!ids.length) { DXB.toast('Select at least one check.', 'warn'); return false; }
                            api.post('/assessments/' + a.id + '/test-plan', { catalog_ids: ids }).then(function () {
                                close();
                                DXB.resolveRoute();
                            }).catch(function (error) { DXB.toast(error.message, 'bad'); });
                            return false;
                        }
                    }
                ],
                onMount: function (bodyEl) {
                    function updateCount() {
                        $('#selCount', bodyEl).textContent = $$('input[name=cat]:checked', bodyEl).length + ' selected';
                    }
                    DXB.on(bodyEl, 'change', 'input[name=cat]', updateCount);
                    DXB.on(bodyEl, 'click', '[data-select]', function (event, el) {
                        var check = el.getAttribute('data-select') === 'all';
                        $$('input[name=cat]', bodyEl).forEach(function (input) {
                            if (input.closest('label').style.display !== 'none') { input.checked = check; }
                        });
                        updateCount();
                    });
                    $('#cSearch', bodyEl).addEventListener('input', function () {
                        var needle = this.value.toLowerCase();
                        $$('#catList label', bodyEl).forEach(function (label) {
                            label.style.display = label.textContent.toLowerCase().indexOf(needle) === -1 ? 'none' : '';
                        });
                    });
                    updateCount();
                }
            });
        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
    }

    function catalogRows(items) {
        return items.map(function (item) {
            return '<label class="inline-check" style="padding:7px 11px;border-bottom:1px solid var(--line);margin:0">' +
                '<input type="checkbox" name="cat" value="' + item.id + '">' +
                '<span style="flex:1">' +
                    '<b class="mono small">' + esc(item.code) + '</b> ' + esc(item.title) +
                    '<div class="small dim">' + esc(item.category) +
                        (item.dvwa_module ? ' &middot; DVWA: ' + esc(item.dvwa_module) : '') + '</div>' +
                '</span></label>';
        }).join('');
    }

}(window.DXB));
