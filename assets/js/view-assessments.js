/* ==========================================================================
   Assessments list and the "new assessment" wizard.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, $ = DXB.$, $$ = DXB.$$;

    DXB.views.assessments = function (params, view) {
        DXB.setHeader('Assessments', 'All engagements',
            ui.can('assessment.create') ? '<button class="btn sm primary" data-new-assessment>New assessment</button>' : '');

        view.innerHTML =
            '<div class="filters">' +
                '<input type="search" class="grow" id="fSearch" placeholder="Search by title, reference or target...">' +
                ui.select('fStatus', [{ value: '', label: 'Any status' }].concat(
                    ['draft', 'in_progress', 'testing_complete', 'in_remediation', 'retest', 'closed']
                        .map(function (s) { return { value: s, label: fmt.label(s) }; })), '', 'id="fStatus"') +
            '</div>' +
            '<div id="list">' + ui.loading() + '</div>';

        function load() {
            api.get('/assessments', {
                search: $('#fSearch').value,
                status: $('#fStatus').value
            }, { silent: true }).then(function (payload) {
                $('#list').innerHTML = renderList(payload.data);
            }).catch(function (error) { $('#list').innerHTML = ui.error(error.message); });
        }

        var debounce;
        $('#fSearch').addEventListener('input', function () {
            clearTimeout(debounce);
            debounce = setTimeout(load, 250);
        });
        $('#fStatus').addEventListener('change', load);
        load();
    };

    function renderList(rows) {
        if (!rows.length) {
            return ui.empty('No assessments match.', 'Create an assessment to define a target, build a test plan and start recording results.');
        }
        return '<div class="card"><div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th style="width:130px">Reference</th><th>Assessment</th><th style="width:130px">Status</th>' +
            '<th style="width:170px">Check progress</th><th class="num" style="width:100px">Findings</th>' +
            '<th style="width:110px">Lead</th><th style="width:100px">Created</th>' +
            '</tr></thead><tbody>' +
            rows.map(function (a) {
                return '<tr class="clickable" onclick="location.hash=\'#/assessment/' + a.id + '/overview\'">' +
                    '<td class="mono small">' + esc(a.ref_code) + '</td>' +
                    '<td><b>' + esc(a.title) + '</b>' +
                        '<div class="small dim truncate">' + esc(a.target_name) + ' &middot; ' + esc(a.target_base_url) + '</div></td>' +
                    '<td>' + fmt.result(a.status) + '</td>' +
                    '<td>' + ui.progress(a.progress) + '<div class="small dim mt1">' + a.tests_done + ' / ' + a.tests_total + ' &middot; ' + fmt.percent(a.progress) + '</div></td>' +
                    '<td class="num">' + a.findings_total +
                        (a.findings_serious > 0 ? ' <span class="badge sev-high">' + a.findings_serious + ' open</span>' : '') + '</td>' +
                    '<td class="small">' + esc(a.lead_name || '-') + '</td>' +
                    '<td class="small dim">' + esc(fmt.date(a.created_at)) + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table></div></div>';
    }

    /* ----------------------------------------------------------------------
       New assessment
       ---------------------------------------------------------------------- */

    DXB.newAssessmentDialog = function () {
        DXB.meta().then(function (meta) {
            DXB.modal({
                title: 'New assessment',
                size: 'wide',
                body:
                    '<div class="callout info">The platform records assessments of a <b>locally hosted</b> target only. ' +
                    'A public host will be refused when the assessment is saved.</div>' +
                    '<div class="grid c2">' +
                        ui.field('Assessment title', '<input type="text" name="title" placeholder="DVWA baseline assessment - September 2026" required>') +
                        ui.field('Target name', '<input type="text" name="target_name" value="DVWA" placeholder="Damn Vulnerable Web Application">') +
                    '</div>' +
                    '<div class="grid c2">' +
                        ui.field('Target base URL', '<input type="url" name="target_base_url" value="http://localhost/DVWA" class="mono">',
                            'The local DVWA instance, for example http://localhost/DVWA') +
                        ui.field('Environment', ui.select('environment', meta.environments.map(function (e) {
                            return { value: e, label: fmt.label(e) };
                        }), 'local_lab')) +
                    '</div>' +
                    '<div class="grid c3">' +
                        ui.field('Methodology', '<input type="text" name="methodology" value="OWASP WSTG v4.2">') +
                        ui.field('Classification', ui.select('classification',
                            ['INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'ACADEMIC'], 'INTERNAL')) +
                        ui.field('Start date', '<input type="date" name="start_date" value="' + attr(today()) + '">') +
                    '</div>' +
                    ui.field('Objective', '<textarea name="objective" rows="3" placeholder="Identify and evidence security weaknesses in the locally hosted target, rate them consistently, and track remediation to verified closure."></textarea>') +
                    '<label class="inline-check"><input type="checkbox" name="seed_full_plan" checked> ' +
                        'Add every active check from the catalogue to the test plan</label>',
                actions: [
                    { label: 'Cancel' },
                    {
                        label: 'Create assessment',
                        kind: 'primary',
                        close: false,
                        onClick: function (bodyEl, close, button) {
                            var data = ui.readForm(bodyEl);
                            if (!data.title || data.title.trim().length < 4) {
                                DXB.toast('Give the assessment a title.', 'warn');
                                return false;
                            }
                            button.disabled = true;
                            button.textContent = 'Creating...';
                            api.post('/assessments', data).then(function (payload) {
                                close();
                                DXB.navigate('/assessment/' + payload.data.id + '/overview');
                            }).catch(function (error) {
                                DXB.toast(error.message, 'bad');
                                button.disabled = false;
                                button.textContent = 'Create assessment';
                            });
                            return false;
                        }
                    }
                ]
            });
        });
    };

    function today() {
        var d = new Date();
        return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    }

}(window.DXB));
