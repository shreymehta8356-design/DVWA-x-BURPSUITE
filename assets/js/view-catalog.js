/* ==========================================================================
   Security check catalogue - the library of predefined checks that assessments
   draw their test plans from.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, $ = DXB.$;

    DXB.views.catalog = function (params, view) {
        DXB.setHeader('Check catalogue', 'Predefined security checks',
            ui.can('catalog.edit') ? '<button class="btn sm primary" id="newCheck">New check</button>' : '');

        view.innerHTML =
            '<div class="filters">' +
                '<input type="search" class="grow" id="cSearch" placeholder="Search by code, title, description or DVWA module...">' +
                '<select id="cCategory"></select>' +
                '<label class="inline-check" style="margin:0"><input type="checkbox" id="cArchived"> Show archived</label>' +
            '</div>' +
            '<div id="catalogList">' + ui.loading() + '</div>';

        if ($('#newCheck')) { $('#newCheck').addEventListener('click', function () { editor(null); }); }

        var debounce;
        $('#cSearch').addEventListener('input', function () {
            clearTimeout(debounce);
            debounce = setTimeout(load, 250);
        });
        $('#cCategory').addEventListener('change', load);
        $('#cArchived').addEventListener('change', load);

        function load() {
            api.get('/catalog', {
                search: $('#cSearch').value,
                category: $('#cCategory').value,
                include_archived: $('#cArchived').checked ? 1 : ''
            }, { silent: true }).then(function (payload) {
                var data = payload.data;
                if (!$('#cCategory').options.length) {
                    $('#cCategory').innerHTML = '<option value="">All categories</option>' +
                        data.categories.map(function (c) { return '<option value="' + attr(c) + '">' + esc(c) + '</option>'; }).join('');
                }
                $('#catalogList').innerHTML = render(data.items);
                DXB.on($('#catalogList'), 'click', '[data-check]', function (event, el) {
                    var item = data.items.filter(function (i) { return i.id === parseInt(el.getAttribute('data-check'), 10); })[0];
                    if (item) { detail(item); }
                });
            }).catch(function (error) { $('#catalogList').innerHTML = ui.error(error.message); });
        }
        load();
    };

    function render(items) {
        if (!items.length) { return ui.empty('No checks match.'); }

        var grouped = {};
        items.forEach(function (item) { (grouped[item.category] = grouped[item.category] || []).push(item); });

        return '<div class="callout info">' + items.length + ' checks in the library, mapped to the OWASP Web Security ' +
            'Testing Guide and to the DVWA module that exercises each one. Assessments copy from here, so editing a check ' +
            'never changes a result that has already been recorded.</div>' +
            Object.keys(grouped).sort().map(function (category) {
                return '<div class="card mb2"><header><h3>' + esc(category) + '</h3><div class="spacer"></div>' +
                    '<span class="small dim">' + grouped[category].length + ' checks</span></header>' +
                    '<div class="table-wrap"><table class="tbl"><thead><tr>' +
                        '<th style="width:118px">Code</th><th>Check</th><th style="width:230px">OWASP Top 10</th>' +
                        '<th style="width:150px">DVWA module</th><th style="width:78px" class="num">L / I</th>' +
                    '</tr></thead><tbody>' +
                    grouped[category].map(function (item) {
                        return '<tr class="clickable" data-check="' + item.id + '"' + (item.is_active ? '' : ' style="opacity:.5"') + '>' +
                            '<td class="mono small">' + esc(item.code) + (item.is_active ? '' : ' <span class="badge mute">archived</span>') + '</td>' +
                            '<td><b>' + esc(item.title) + '</b>' +
                                '<div class="small dim truncate" style="max-width:640px">' + esc(item.test_objective || item.description || '') + '</div></td>' +
                            '<td class="small">' + esc(item.owasp_top10 || '-') + '</td>' +
                            '<td class="small">' + esc(item.dvwa_module || '-') + '</td>' +
                            '<td class="num small">' + item.default_likelihood + ' / ' + item.default_impact + '</td>' +
                        '</tr>';
                    }).join('') + '</tbody></table></div></div>';
            }).join('');
    }

    function detail(item) {
        DXB.modal({
            title: item.code + ' - ' + item.title,
            size: 'wide',
            body:
                '<dl class="kv mb2">' +
                    '<dt>Category</dt><dd>' + esc(item.category) + '</dd>' +
                    '<dt>OWASP Top 10</dt><dd>' + esc(item.owasp_top10 || '-') + '</dd>' +
                    '<dt>CWE</dt><dd>' + esc(item.cwe_id || '-') + '</dd>' +
                    '<dt>DVWA module</dt><dd>' + esc(item.dvwa_module || '-') + '</dd>' +
                    '<dt>Default rating</dt><dd>Likelihood ' + item.default_likelihood + ', impact ' + item.default_impact + '</dd>' +
                    (item.default_cvss_vector ? '<dt>Starting CVSS</dt><dd class="mono small wrap-any">' + esc(item.default_cvss_vector) + '</dd>' : '') +
                '</dl>' +
                '<h4>Description</h4><p class="small">' + esc(item.description || '-') + '</p>' +
                '<h4>Objective</h4><p class="small">' + esc(item.test_objective || '-') + '</p>' +
                '<h4>How to test</h4><pre class="code">' + esc(item.test_steps || '-') + '</pre>' +
                '<h4>Expected secure behaviour</h4><p class="small">' + esc(item.expected_secure_behaviour || '-') + '</p>' +
                (item.tools_hint ? '<h4>Tools</h4><p class="small dim">' + esc(item.tools_hint) + '</p>' : ''),
            actions: [
                { label: 'Close' },
                ui.can('catalog.edit') ? {
                    label: 'Edit', close: true,
                    onClick: function () { setTimeout(function () { editor(item); }, 60); }
                } : null
            ].filter(Boolean)
        });
    }

    function editor(item) {
        var isNew = !item;
        var v = item || {
            code: '', title: '', category: 'Custom', owasp_top10: '', cwe_id: '', description: '',
            test_objective: '', test_steps: '', tools_hint: '', expected_secure_behaviour: '',
            default_likelihood: 3, default_impact: 3, default_cvss_vector: '', dvwa_module: '', is_active: true
        };

        DXB.modal({
            title: isNew ? 'New catalogue check' : 'Edit ' + v.code,
            size: 'wide',
            body:
                '<div class="grid c2">' +
                    ui.field('Code', '<input type="text" name="code" class="mono" value="' + attr(v.code) + '"' +
                        (isNew ? ' placeholder="WSTG-INPV-99"' : ' readonly') + '>',
                        isNew ? 'Use the WSTG identifier where one exists, or your own scheme.' : 'The code cannot be changed once assessments reference it.') +
                    ui.field('Category', '<input type="text" name="category" value="' + attr(v.category) + '">') +
                '</div>' +
                ui.field('Title', '<input type="text" name="title" value="' + attr(v.title) + '">') +
                '<div class="grid c3">' +
                    ui.field('OWASP Top 10', '<input type="text" name="owasp_top10" value="' + attr(v.owasp_top10 || '') + '">') +
                    ui.field('CWE', '<input type="text" name="cwe_id" class="mono" value="' + attr(v.cwe_id || '') + '">') +
                    ui.field('DVWA module', '<input type="text" name="dvwa_module" value="' + attr(v.dvwa_module || '') + '">') +
                '</div>' +
                ui.field('Description', '<textarea name="description" rows="3">' + esc(v.description || '') + '</textarea>') +
                ui.field('Objective', '<textarea name="test_objective" rows="3">' + esc(v.test_objective || '') + '</textarea>') +
                ui.field('Test steps', '<textarea name="test_steps" rows="6" class="mono">' + esc(v.test_steps || '') + '</textarea>') +
                ui.field('Expected secure behaviour', '<textarea name="expected_secure_behaviour" rows="2">' + esc(v.expected_secure_behaviour || '') + '</textarea>') +
                '<div class="grid c4">' +
                    ui.field('Tools hint', '<input type="text" name="tools_hint" value="' + attr(v.tools_hint || '') + '">') +
                    ui.field('Default likelihood', '<input type="number" name="default_likelihood" min="1" max="5" value="' + attr(v.default_likelihood) + '">') +
                    ui.field('Default impact', '<input type="number" name="default_impact" min="1" max="5" value="' + attr(v.default_impact) + '">') +
                    ui.field('Active', '<select name="is_active"><option value="1"' + (v.is_active ? ' selected' : '') + '>Active</option>' +
                        '<option value=""' + (v.is_active ? '' : ' selected') + '>Archived</option></select>') +
                '</div>' +
                ui.field('Starting CVSS vector', '<input type="text" name="default_cvss_vector" class="mono" value="' + attr(v.default_cvss_vector || '') + '">'),
            actions: [
                { label: 'Cancel' },
                {
                    label: isNew ? 'Add check' : 'Save', kind: 'primary', close: false,
                    onClick: function (bodyEl, close) {
                        var data = ui.readForm(bodyEl);
                        data.is_active = !!data.is_active;
                        var request = isNew ? api.post('/catalog', data) : api.put('/catalog/' + item.id, data);
                        request.then(function () {
                            close();
                            DXB.resolveRoute();
                        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
                        return false;
                    }
                }
            ]
        });
    }

}(window.DXB));
