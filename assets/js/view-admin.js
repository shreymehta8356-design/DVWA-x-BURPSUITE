/* ==========================================================================
   AI model console, audit trail, administration and account screens.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api,
        charts = DXB.charts, $ = DXB.$, $$ = DXB.$$;

    /* ======================================================================
       AI MODELS
       ====================================================================== */

    DXB.views.ai = function (params, view) {
        DXB.setHeader('AI models', 'Offline engines and the optional local assistant',
            ui.can('ai.train') ? '<button class="btn sm" id="btnEval">Cross-validate</button>' +
                                 '<button class="btn sm primary" id="btnRetrain">Retrain classifier</button>' : '');
        view.innerHTML = ui.loading('Reading model state...');

        var calls = [api.get('/ai/status', null, { silent: true })];
        if (ui.can('admin.audit') || ui.can('ai.train')) {
            calls.push(api.get('/admin/ai/model', null, { silent: true }).catch(function () { return null; }));
        }

        Promise.all(calls).then(function (results) {
            var status = results[0].data;
            var model = results[1] ? results[1].data : null;

            view.innerHTML =
                '<div class="callout info"><b>Everything here runs on this machine.</b> The classifier, the similarity ' +
                'index, the CVSS engine and the redactor are implemented in PHP with no dependencies and no network calls. ' +
                'The narrative assistant is optional: without it, drafting falls back to deterministic templates and every ' +
                'output says which produced it.</div>' +

                '<div class="grid c2 mb2">' +
                    status.offline_engines.map(engineCard).join('') +
                '</div>' +

                llmCard(status.llm) +
                (model ? classifierCard(model) : '') +
                '<div id="evalOut"></div>';

            if ($('#btnRetrain')) {
                $('#btnRetrain').addEventListener('click', function () {
                    var button = this;
                    button.disabled = true;
                    button.textContent = 'Training...';
                    api.post('/admin/ai/retrain').then(function () { DXB.resolveRoute(); })
                        .catch(function (error) { DXB.toast(error.message, 'bad'); button.disabled = false; button.textContent = 'Retrain classifier'; });
                });
            }
            if ($('#btnEval')) {
                $('#btnEval').addEventListener('click', function () {
                    var button = this;
                    button.disabled = true;
                    button.textContent = 'Evaluating...';
                    $('#evalOut').innerHTML = ui.loading('Running 5-fold stratified cross validation...');
                    api.post('/admin/ai/evaluate', { folds: 5 }, { silent: true }).then(function (payload) {
                        $('#evalOut').innerHTML = evaluation(payload.data);
                    }).catch(function (error) { $('#evalOut').innerHTML = ui.error(error.message); })
                      .finally(function () { button.disabled = false; button.textContent = 'Cross-validate'; });
                });
            }
            if ($('#btnTestLlm')) {
                $('#btnTestLlm').addEventListener('click', function () {
                    var button = this;
                    button.disabled = true;
                    button.textContent = 'Testing...';
                    api.post('/admin/ai/llm-test', { run_prompt: true }, { silent: true }).then(function (payload) {
                        var data = payload.data;
                        DXB.modal({
                            title: 'Local model connection test',
                            body: '<div class="callout ' + (data.available ? 'ok' : 'warn') + '">' + esc(data.message) + '</div>' +
                                (data.models && data.models.length
                                    ? '<p class="small"><b>Models available locally:</b> ' + esc(data.models.join(', ')) + '</p>' : '') +
                                (data.sample ? '<h4>Sample reply</h4><pre class="code">' + esc(data.sample) + '</pre>' +
                                    '<p class="small dim">Round trip ' + esc(data.latency_ms || 0) + ' ms.</p>' : '') +
                                '<p class="small dim">If this fails, install Ollama, run <code>ollama serve</code> and ' +
                                '<code>ollama pull ' + esc(data.model) + '</code>. The platform works fully without it.</p>',
                            actions: [{ label: 'Close' }]
                        });
                    }).catch(function (error) { DXB.toast(error.message, 'bad'); })
                      .finally(function () { button.disabled = false; button.textContent = 'Test connection'; });
                });
            }
        }).catch(function (error) { view.innerHTML = ui.error(error.message); });
    };

    function engineCard(engine) {
        var badge = engine.status === 'ready' ? 'ok' : (engine.status === 'disabled' ? 'mute' : 'warn');
        var detail = '';
        if (engine.engine === 'naive_bayes' && engine.detail) {
            detail = '<dl class="kv small mt2">' +
                '<dt>Algorithm</dt><dd>' + esc(engine.detail.algorithm) + '</dd>' +
                '<dt>Classes</dt><dd>' + esc(engine.detail.class_count) + '</dd>' +
                '<dt>Documents</dt><dd>' + esc(engine.detail.documents) + '</dd>' +
                '<dt>Vocabulary</dt><dd>' + esc(engine.detail.vocabulary) + ' terms</dd>' +
                '<dt>Trained</dt><dd>' + esc(fmt.date(engine.detail.trained_at, true)) + '</dd>' +
            '</dl>';
        } else if (engine.detail) {
            detail = '<dl class="kv small mt2">' + Object.keys(engine.detail).map(function (key) {
                return '<dt>' + esc(fmt.label(key)) + '</dt><dd>' + esc(String(engine.detail[key])) + '</dd>';
            }).join('') + '</dl>';
        }
        return '<div class="card"><header><h3>' + esc(engine.name) + '</h3><div class="spacer"></div>' +
            '<span class="badge ' + badge + '">' + esc(engine.status) + '</span></header>' +
            '<div class="body"><p class="small">' + esc(engine.purpose) + '</p>' + detail + '</div></div>';
    }

    function llmCard(llm) {
        return '<div class="card mb2"><header><h3>Narrative assistant (optional)</h3><div class="spacer"></div>' +
            '<span class="badge ' + (llm.enabled ? 'accent' : 'mute') + '">' + (llm.enabled ? 'enabled' : 'disabled') + '</span>' +
            (ui.can('admin.settings') ? '<button class="btn xs" id="btnTestLlm">Test connection</button>' : '') +
            '</header><div class="body">' +
                '<dl class="kv small mb2">' +
                    '<dt>Provider</dt><dd>' + esc(llm.provider) + '</dd>' +
                    '<dt>Endpoint</dt><dd class="mono">' + esc(llm.endpoint) + '</dd>' +
                    '<dt>Model</dt><dd class="mono">' + esc(llm.model) + '</dd>' +
                '</dl>' +
                '<p class="small dim">' + esc(llm.note) + '</p>' +
                (!llm.enabled
                    ? '<div class="callout info small mb0">To enable it: install Ollama, run <code>ollama pull llama3.2</code>, ' +
                      'then turn on <code>ai_llm_enabled</code> in Administration &rarr; Settings. Requests go to 127.0.0.1 and ' +
                      'nothing leaves this machine.</div>'
                    : '') +
            '</div></div>';
    }

    function classifierCard(model) {
        var classes = model.classifier.classes || [];
        return '<div class="grid mb2" style="grid-template-columns:1.2fr .8fr">' +
            '<div class="card"><header><h3>Training corpus by class</h3><div class="spacer"></div>' +
                '<span class="small dim">' + model.corpus.total + ' examples (' + model.corpus.analyst + ' from confirmed findings)</span>' +
            '</header><div class="body">' +
                (classes.length
                    ? charts.bars(classes.map(function (c) { return { label: c.label, value: c.documents }; }), { labelWidth: 200 })
                    : '<div class="dim small">No training data.</div>') +
            '</div></div>' +
            '<div class="card"><header><h3>How the classifier learns</h3></header><div class="body small">' +
                '<p>The corpus starts from a curated seed set plus the catalogue text. Every time an analyst confirms a ' +
                'finding with a vulnerability class, the observation is added as a new labelled example.</p>' +
                '<p class="dim">Retraining is explicit rather than automatic, so the model behind a report never changes ' +
                'underneath an assessment that is already in progress.</p>' +
                '<dl class="kv"><dt>Seed examples</dt><dd>' + model.corpus.seed + '</dd>' +
                '<dt>Analyst-confirmed</dt><dd>' + model.corpus.analyst + '</dd>' +
                '<dt>Catalogue-derived</dt><dd>' + model.corpus.catalogue_examples + '</dd></dl>' +
            '</div></div>' +
        '</div>';
    }

    function evaluation(data) {
        var rows = Object.keys(data.per_class).map(function (label) {
            var m = data.per_class[label];
            return { label: label, precision: m.precision, recall: m.recall, f1: m.f1, support: m.support };
        }).sort(function (a, b) { return b.support - a.support; });

        return '<div class="card mt2"><header><h3>' + data.folds + '-fold cross validation</h3><div class="spacer"></div>' +
            '<span class="badge accent">top-1 ' + Math.round(data.accuracy * 100) + '%</span>' +
            '<span class="badge ok">top-3 ' + Math.round((data.top3_accuracy || 0) * 100) + '%</span>' +
            '<span class="badge accent">macro F1 ' + data.macro_f1.toFixed(3) + '</span></header>' +
            '<div class="body">' +
                '<p class="small dim">' + esc(data.note) + '</p>' +
                '<div class="callout info small">Over ' + (data.classes || 0) + ' classes a random guess scores ' +
                    Math.round((data.random_baseline || 0) * 100) + '%. This model scores <b>' +
                    Math.round(data.accuracy * 100) + '%</b> top-1 and <b>' +
                    Math.round((data.top3_accuracy || 0) * 100) + '%</b> top-3. Because the suggestion panel shows a ' +
                    'ranked list and the analyst chooses, top-3 is the figure that reflects how the feature is actually used. ' +
                    'Reported confidence is temperature-calibrated so its average tracks measured accuracy.</div>' +
                '<div class="table-wrap"><table class="tbl"><thead><tr><th>Class</th>' +
                    '<th class="num">Precision</th><th class="num">Recall</th><th class="num">F1</th><th class="num">Support</th>' +
                '</tr></thead><tbody>' + rows.map(function (r) {
                    return '<tr><td>' + esc(r.label) + '</td>' +
                        '<td class="num">' + r.precision.toFixed(2) + '</td>' +
                        '<td class="num">' + r.recall.toFixed(2) + '</td>' +
                        '<td class="num"><b>' + r.f1.toFixed(2) + '</b></td>' +
                        '<td class="num">' + r.support + '</td></tr>';
                }).join('') + '</tbody></table></div>' +
            '</div></div>';
    }

    /* ======================================================================
       AUDIT TRAIL
       ====================================================================== */

    DXB.views.audit = function (params, view) {
        DXB.setHeader('Audit trail', 'Tamper-evident record of every action',
            '<button class="btn sm primary" id="btnVerifyChain">Verify chain</button>');
        view.innerHTML = '<div id="chainState"></div>' +
            '<div class="filters">' +
                '<input type="search" class="grow" id="aAction" placeholder="Filter by action prefix, e.g. finding. or evidence.">' +
                '<input type="text" id="aActor" placeholder="Username">' +
            '</div>' +
            '<div id="auditList">' + ui.loading() + '</div>';

        $('#btnVerifyChain').addEventListener('click', function () {
            var button = this;
            button.disabled = true;
            $('#chainState').innerHTML = ui.loading('Re-walking the hash chain...');
            api.get('/admin/audit/verify', null, { silent: true }).then(function (payload) {
                var data = payload.data;
                $('#chainState').innerHTML = '<div class="callout ' + (data.valid ? 'ok' : 'bad') + '">' +
                    '<b>' + (data.valid ? 'Chain intact.' : 'Chain broken at entry ' + data.broken_at + '.') + '</b> ' +
                    (data.valid ? data.checked + ' entries verified.' : esc(data.reason)) +
                    '<div class="small mt1">' + esc(data.explanation) + '</div></div>';
            }).catch(function (error) { $('#chainState').innerHTML = ui.error(error.message); })
              .finally(function () { button.disabled = false; });
        });

        var debounce;
        function load() {
            api.get('/admin/audit', {
                limit: 200, action: $('#aAction').value, actor: $('#aActor').value
            }, { silent: true }).then(function (payload) {
                $('#auditList').innerHTML = auditTable(payload.data);
            }).catch(function (error) { $('#auditList').innerHTML = ui.error(error.message); });
        }
        [$('#aAction'), $('#aActor')].forEach(function (input) {
            input.addEventListener('input', function () { clearTimeout(debounce); debounce = setTimeout(load, 260); });
        });
        load();
    };

    function auditTable(data) {
        if (!data.entries.length) { return ui.empty('No audit entries match.'); }
        return '<div class="card"><header><h3>Entries</h3><div class="spacer"></div>' +
            '<span class="small dim">showing ' + data.entries.length + ' of ' + data.total + '</span></header>' +
            '<div class="table-wrap"><table class="tbl"><thead><tr>' +
                '<th style="width:56px" class="num">ID</th><th style="width:150px">When</th><th style="width:112px">Actor</th>' +
                '<th style="width:190px">Action</th><th>Entity / detail</th><th style="width:104px">Hash</th>' +
            '</tr></thead><tbody>' + data.entries.map(function (e) {
                var detail = '';
                if (e.detail) {
                    try {
                        var parsed = JSON.parse(e.detail);
                        detail = Object.keys(parsed).slice(0, 4).map(function (k) {
                            var value = parsed[k];
                            if (value && typeof value === 'object') { value = JSON.stringify(value).slice(0, 60); }
                            return esc(k) + '=' + esc(String(value).slice(0, 60));
                        }).join(' &middot; ');
                    } catch (error) { detail = esc(String(e.detail).slice(0, 120)); }
                }
                return '<tr>' +
                    '<td class="num small dim">' + e.id + '</td>' +
                    '<td class="small">' + esc(fmt.date(e.created_at, true)) + '</td>' +
                    '<td class="small"><b>' + esc(e.actor_username || 'system') + '</b>' +
                        '<div class="dim mono" style="font-size:10px">' + esc(e.actor_ip || '') + '</div></td>' +
                    '<td class="small mono">' + esc(e.action) + '</td>' +
                    '<td class="small">' + esc(e.entity_type || '') + (e.entity_id ? ' #' + e.entity_id : '') +
                        (e.assessment_ref ? ' <span class="badge mute">' + esc(e.assessment_ref) + '</span>' : '') +
                        (detail ? '<div class="dim" style="font-size:11px">' + detail + '</div>' : '') + '</td>' +
                    '<td class="mono dim" style="font-size:10px">' + esc(e.hash_short) + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table></div></div>';
    }

    /* ======================================================================
       ADMINISTRATION
       ====================================================================== */

    DXB.views.admin = function (params, view) {
        DXB.setHeader('Administration', 'Users, settings and the risk model', '');
        view.innerHTML =
            '<nav class="tabs">' +
                '<a href="#/admin" class="active" data-atab="users">Users</a>' +
                '<a href="#/admin" data-atab="settings">Settings</a>' +
                '<a href="#/admin" data-atab="matrix">Risk matrix</a>' +
                '<a href="#/admin" data-atab="training">AI training data</a>' +
            '</nav><div id="adminPanel">' + ui.loading() + '</div>';

        DXB.on(view, 'click', '[data-atab]', function (event, el) {
            event.preventDefault();
            $$('[data-atab]', view).forEach(function (a) { a.classList.remove('active'); });
            el.classList.add('active');
            show(el.getAttribute('data-atab'));
        });

        function show(tab) {
            var panel = $('#adminPanel');
            panel.innerHTML = ui.loading();
            if (tab === 'users') { usersPanel(panel); }
            else if (tab === 'settings') { settingsPanel(panel, 'settings'); }
            else if (tab === 'matrix') { settingsPanel(panel, 'matrix'); }
            else { trainingPanel(panel); }
        }
        show('users');
    };

    function usersPanel(panel) {
        api.get('/admin/users', null, { silent: true }).then(function (payload) {
            panel.innerHTML =
                '<div class="card"><header><h3>Accounts</h3><div class="spacer"></div>' +
                    '<button class="btn sm primary" id="btnNewUser">New account</button></header>' +
                '<div class="table-wrap"><table class="tbl"><thead><tr>' +
                    '<th>Username</th><th>Name</th><th style="width:110px">Role</th><th style="width:96px">State</th>' +
                    '<th style="width:170px">Last sign-in</th><th style="width:210px">Actions</th>' +
                '</tr></thead><tbody>' + payload.data.map(function (u) {
                    return '<tr>' +
                        '<td class="mono small">' + esc(u.username) + '</td>' +
                        '<td>' + esc(u.full_name) + '<div class="small dim">' + esc(u.email || '') + '</div></td>' +
                        '<td><span class="badge accent">' + esc(u.role) + '</span></td>' +
                        '<td>' + (u.is_active ? '<span class="badge ok">active</span>' : '<span class="badge mute">disabled</span>') +
                            (u.must_change ? '<div class="badge warn mt1">must change password</div>' : '') + '</td>' +
                        '<td class="small dim">' + esc(u.last_login_at ? fmt.date(u.last_login_at, true) : 'never') + '</td>' +
                        '<td><div class="btn-row">' +
                            '<button class="btn xs" data-edit-user="' + u.id + '">Edit</button>' +
                            '<button class="btn xs" data-reset-user="' + u.id + '" data-username="' + attr(u.username) + '">Reset password</button>' +
                        '</div></td>' +
                    '</tr>';
                }).join('') + '</tbody></table></div></div>' +
                '<div class="callout info mt2"><b>Roles.</b> <b>analyst</b> runs checks, records evidence and drafts findings. ' +
                '<b>reviewer</b> reads everything and signs off peer review. <b>lead</b> owns assessments, sets severity and ' +
                'finalises reports. <b>admin</b> adds everything above plus users, settings and the AI configuration. ' +
                'Accounts are disabled rather than deleted, so the audit trail always names a real person.</div>';

            $('#btnNewUser').addEventListener('click', function () { userDialog(null, panel); });
            DXB.on(panel, 'click', '[data-edit-user]', function (event, el) {
                var user = payload.data.filter(function (u) { return u.id === parseInt(el.getAttribute('data-edit-user'), 10); })[0];
                userDialog(user, panel);
            });
            DXB.on(panel, 'click', '[data-reset-user]', function (event, el) {
                resetDialog(parseInt(el.getAttribute('data-reset-user'), 10), el.getAttribute('data-username'), panel);
            });
        }).catch(function (error) { panel.innerHTML = ui.error(error.message); });
    }

    function userDialog(user, panel) {
        var isNew = !user;
        DXB.meta().then(function (meta) {
            DXB.modal({
                title: isNew ? 'New account' : 'Edit ' + user.username,
                body:
                    (isNew ? ui.field('Username', '<input type="text" name="username" class="mono" placeholder="a.sharma">') : '') +
                    ui.field('Full name', '<input type="text" name="full_name" value="' + attr(isNew ? '' : user.full_name) + '">',
                        'Printed in the audit trail and on reports.') +
                    ui.field('Email', '<input type="email" name="email" value="' + attr(isNew ? '' : (user.email || '')) + '">') +
                    ui.field('Role', ui.select('role', meta.roles.map(function (r) { return { value: r, label: fmt.label(r) }; }),
                        isNew ? 'analyst' : user.role)) +
                    (isNew
                        ? ui.field('Initial password', '<input type="password" name="password" autocomplete="new-password">',
                            'At least 12 characters combining three of: lowercase, uppercase, digits, symbols.')
                        : '<label class="inline-check"><input type="checkbox" name="is_active"' + (user.is_active ? ' checked' : '') + '> Account active</label>'),
                actions: [
                    { label: 'Cancel' },
                    {
                        label: isNew ? 'Create' : 'Save', kind: 'primary', close: false,
                        onClick: function (bodyEl, close) {
                            var data = ui.readForm(bodyEl);
                            var request = isNew ? api.post('/admin/users', data) : api.put('/admin/users/' + user.id, data);
                            request.then(function () { close(); usersPanel(panel); })
                                   .catch(function (error) { DXB.toast(error.message, 'bad', 9000); });
                            return false;
                        }
                    }
                ]
            });
        });
    }

    function resetDialog(userId, username, panel) {
        DXB.modal({
            title: 'Reset password for ' + username,
            body: ui.field('New password', '<input type="password" name="new_password" autocomplete="new-password">',
                'The user is required to change it at next sign-in.'),
            actions: [
                { label: 'Cancel' },
                {
                    label: 'Reset', kind: 'primary', close: false,
                    onClick: function (bodyEl, close) {
                        api.put('/admin/users/' + userId, {
                            reset_password: true,
                            new_password: $('input[name=new_password]', bodyEl).value
                        }).then(function () { close(); usersPanel(panel); })
                          .catch(function (error) { DXB.toast(error.message, 'bad', 9000); });
                        return false;
                    }
                }
            ]
        });
    }

    function settingsPanel(panel, which) {
        api.get('/admin/settings', null, { silent: true }).then(function (payload) {
            var data = payload.data;
            if (which === 'matrix') {
                panel.innerHTML =
                    '<div class="card"><header><h3>Risk matrix</h3><div class="spacer"></div>' +
                        '<span class="small dim">Click a cell to cycle its band</span>' +
                        '<button class="btn sm primary" id="btnSaveMatrix">Save matrix</button></header>' +
                    '<div class="body">' +
                        '<div id="matrixHost">' + charts.matrix(data.risk_matrix) + '</div>' +
                        '<div class="callout info mt2 small">The matrix is printed in full in every report, so a reader can ' +
                        're-derive any rating by hand. Editing it does not change findings that were already rated - each ' +
                        'finding stores the rationale that produced its severity at the time.</div>' +
                        '<h4 class="mt2">Remediation targets</h4>' +
                        '<table class="tbl" style="max-width:520px"><thead><tr><th>Severity</th><th class="num">Target days</th><th>Definition</th></tr></thead><tbody>' +
                            data.sla.map(function (s) {
                                return '<tr><td>' + fmt.sev(s.severity) + '</td><td class="num">' + s.sla_days + '</td>' +
                                    '<td class="small dim">' + esc(s.description || '') + '</td></tr>';
                            }).join('') + '</tbody></table>' +
                    '</div></div>';

                var bands = ['info', 'low', 'medium', 'high', 'critical'];
                var colours = { info: '#6b7280', low: '#3b82f6', medium: '#f59e0b', high: '#f97316', critical: '#dc2626' };
                var edits = {};
                DXB.on(panel, 'click', '.matrix .cell', function (event, el) {
                    var key = el.getAttribute('data-l') + ':' + el.getAttribute('data-i');
                    var currentText = el.textContent.trim().toLowerCase();
                    var currentBand = bands.filter(function (b) { return b.indexOf(currentText.slice(0, 4)) === 0; })[0] || 'info';
                    var next = bands[(bands.indexOf(currentBand) + 1) % bands.length];
                    el.textContent = next.slice(0, 4).toUpperCase();
                    el.style.background = colours[next];
                    edits[key] = {
                        likelihood: parseInt(el.getAttribute('data-l'), 10),
                        impact: parseInt(el.getAttribute('data-i'), 10),
                        band: next, colour: colours[next]
                    };
                });
                $('#btnSaveMatrix').addEventListener('click', function () {
                    var cells = Object.keys(edits).map(function (k) { return edits[k]; });
                    if (!cells.length) { DXB.toast('No cells were changed.', 'warn'); return; }
                    api.put('/admin/risk-matrix', { cells: cells })
                        .then(function () { settingsPanel(panel, 'matrix'); })
                        .catch(function (error) { DXB.toast(error.message, 'bad'); });
                });
                return;
            }

            var groups = {
                'Reporting': ['org_name', 'report_footer', 'severity_strategy'],
                'AI': ['ai_enabled', 'ai_llm_enabled', 'ai_llm_provider', 'ai_llm_endpoint', 'ai_llm_model',
                       'ai_llm_timeout', 'ai_llm_api_key', 'ai_dedup_threshold', 'ai_triage_min_confidence'],
                'Evidence': ['evidence_max_mb', 'auto_redact_evidence'],
                'Security': ['login_max_attempts', 'login_lockout_minutes', 'session_idle_minutes', 'require_review']
            };
            var byKey = {};
            data.settings.forEach(function (s) { byKey[s.skey] = s; });

            panel.innerHTML = '<div class="grid c2">' +
                Object.keys(groups).map(function (group) {
                    return '<div class="card"><header><h3>' + esc(group) + '</h3></header><div class="body">' +
                        groups[group].map(function (key) {
                            var setting = byKey[key];
                            if (!setting) { return ''; }
                            var isBool = setting.value_type === 'bool';
                            var control = isBool
                                ? ui.select(key, [{ value: '1', label: 'Enabled' }, { value: '0', label: 'Disabled' }], setting.svalue)
                                : '<input type="' + (key === 'ai_llm_api_key' ? 'password' : 'text') + '" name="' + attr(key) +
                                  '" value="' + attr(setting.svalue) + '" class="' + (key.indexOf('endpoint') !== -1 ? 'mono' : '') + '">';
                            return ui.field(fmt.label(key), control, setting.description);
                        }).join('') +
                    '</div></div>';
                }).join('') +
            '</div>' +
            '<div class="btn-row mt2"><button class="btn primary" id="btnSaveSettings">Save settings</button>' +
                '<span class="small dim">Changes take effect immediately for new requests.</span></div>' +
            '<div class="callout warn mt2 small"><b>A note on the openai_compatible provider.</b> It exists for a local ' +
            'OpenAI-shaped server such as llama.cpp or LM Studio. Pointing it at an Internet endpoint would send assessment ' +
            'text off this machine and break the offline guarantee this platform is built on.</div>';

            $('#btnSaveSettings').addEventListener('click', function () {
                api.put('/admin/settings', { settings: ui.readForm(panel) })
                    .then(function () { settingsPanel(panel, 'settings'); })
                    .catch(function (error) { DXB.toast(error.message, 'bad', 9000); });
            });
        }).catch(function (error) { panel.innerHTML = ui.error(error.message); });
    }

    function trainingPanel(panel) {
        api.get('/admin/ai/training', { limit: 300 }, { silent: true }).then(function (payload) {
            var data = payload.data;
            panel.innerHTML =
                '<div class="split"><div>' +
                    '<div class="card"><header><h3>Training examples</h3><div class="spacer"></div>' +
                        '<span class="small dim">' + data.rows.length + ' shown</span>' +
                        '<button class="btn sm primary" id="btnAddTrain">Add example</button></header>' +
                    '<div class="table-wrap" style="max-height:620px"><table class="tbl"><thead><tr>' +
                        '<th>Observation</th><th style="width:190px">Label</th><th style="width:92px">Source</th><th style="width:70px"></th>' +
                    '</tr></thead><tbody>' + data.rows.map(function (r) {
                        return '<tr' + (Number(r.is_active) ? '' : ' style="opacity:.45"') + '>' +
                            '<td class="small">' + esc(r.text) + '</td>' +
                            '<td class="small"><b>' + esc(r.label) + '</b></td>' +
                            '<td><span class="badge mute">' + esc(r.source) + '</span></td>' +
                            '<td>' + (Number(r.is_active)
                                ? '<button class="btn xs ghost" data-del-train="' + r.id + '">Remove</button>' : '') + '</td>' +
                        '</tr>';
                    }).join('') + '</tbody></table></div></div>' +
                '</div><div>' +
                    '<div class="card"><header><h3>Label distribution</h3></header><div class="body">' +
                        charts.bars(data.labels.map(function (l) { return { label: l.label, value: l.count }; }), { labelWidth: 160 }) +
                        '<div class="callout info small mt2">A skewed corpus makes the classifier confident about the ' +
                        'wrong things. If one class dominates, add examples for the thin ones before retraining, then ' +
                        'cross-validate on the AI models screen to see the effect per class.</div>' +
                    '</div></div>' +
                '</div></div>';

            $('#btnAddTrain').addEventListener('click', function () {
                DXB.meta().then(function (meta) {
                    DXB.modal({
                        title: 'Add a training example',
                        body:
                            ui.field('Observation text',
                                '<textarea name="text" rows="4" placeholder="the id parameter accepts a single quote and returns a mysql syntax error"></textarea>',
                                'Write it the way an analyst would record an observation - that is what the model sees at prediction time.') +
                            ui.field('Label', ui.select('label', meta.vuln_classes.map(function (c) {
                                return { value: c, label: c };
                            }), 'SQL Injection')),
                        actions: [
                            { label: 'Cancel' },
                            {
                                label: 'Add', kind: 'primary', close: false,
                                onClick: function (bodyEl, close) {
                                    api.post('/admin/ai/training', ui.readForm(bodyEl))
                                        .then(function () { close(); trainingPanel(panel); })
                                        .catch(function (error) { DXB.toast(error.message, 'bad'); });
                                    return false;
                                }
                            }
                        ]
                    });
                });
            });

            DXB.on(panel, 'click', '[data-del-train]', function (event, el) {
                api.del('/admin/ai/training/' + el.getAttribute('data-del-train'))
                    .then(function () { trainingPanel(panel); })
                    .catch(function (error) { DXB.toast(error.message, 'bad'); });
            });
        }).catch(function (error) { panel.innerHTML = ui.error(error.message); });
    }

    /* ======================================================================
       ACCOUNT
       ====================================================================== */

    DXB.views.account = function (params, view) {
        DXB.setHeader('My account', 'Session and password', '');
        var user = DXB.user;

        view.innerHTML =
            '<div class="grid c2">' +
                '<div class="card"><header><h3>Change password</h3></header><div class="body">' +
                    (DXB.mustChangePassword
                        ? '<div class="callout warn">This account is still on its initial password. Change it before recording any assessment work.</div>'
                        : '') +
                    ui.field('Current password', '<input type="password" name="current_password" autocomplete="current-password">') +
                    ui.field('New password', '<input type="password" name="new_password" autocomplete="new-password">',
                        'At least 12 characters, combining three of: lowercase, uppercase, digits, symbols. Must not contain your username.') +
                    ui.field('Confirm new password', '<input type="password" name="confirm_password" autocomplete="new-password">') +
                    '<button class="btn primary" id="btnChangePw">Change password</button>' +
                '</div></div>' +
                '<div class="card"><header><h3>Session</h3></header><div class="body">' +
                    '<dl class="kv">' +
                        '<dt>Username</dt><dd class="mono">' + esc(user.username) + '</dd>' +
                        '<dt>Name</dt><dd>' + esc(user.full_name) + '</dd>' +
                        '<dt>Role</dt><dd><span class="badge accent">' + esc(user.role) + '</span></dd>' +
                    '</dl>' +
                    '<h4 class="mt2">What your role can do</h4>' +
                    '<div class="flex wrap">' + Object.keys(DXB.can).filter(function (k) { return DXB.can[k]; })
                        .map(function (k) { return '<span class="chip">' + esc(k) + '</span>'; }).join('') + '</div>' +
                '</div></div>' +
            '</div>';

        $('#btnChangePw').addEventListener('click', function () {
            var data = ui.readForm(view);
            if (data.new_password !== data.confirm_password) {
                DXB.toast('The new password and its confirmation do not match.', 'warn');
                return;
            }
            api.post('/auth/password', {
                current_password: data.current_password,
                new_password: data.new_password
            }).then(function () {
                DXB.mustChangePassword = false;
                $$('input[type=password]', view).forEach(function (i) { i.value = ''; });
            }).catch(function (error) { DXB.toast(error.message, 'bad', 9000); });
        });
    };

}(window.DXB));
