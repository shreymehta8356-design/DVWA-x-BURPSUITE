/* ==========================================================================
   Evidence tab - the artefact store. Every item is hashed at capture, carries
   a chain of custody, and can be verified against its recorded hash.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, $ = DXB.$;

    DXB.tabs.evidence = function (a, panel) {
        panel.innerHTML =
            '<div class="filters">' +
                '<input type="search" class="grow" id="eSearch" placeholder="Filter evidence by title or content...">' +
                '<div class="spacer"></div>' +
                (ui.can('evidence.add')
                    ? '<button class="btn sm" id="addText">Record text evidence</button>' +
                      '<button class="btn sm primary" id="addFile">Upload artefact</button>'
                    : '') +
            '</div>' +
            '<div id="evList">' + ui.loading() + '</div>';

        if ($('#addText')) { $('#addText').addEventListener('click', function () { textDialog(a); }); }
        if ($('#addFile')) { $('#addFile').addEventListener('click', function () { uploadDialog(a); }); }

        var all = [];
        function render() {
            var needle = $('#eSearch').value.toLowerCase();
            var rows = !needle ? all : all.filter(function (item) {
                return (item.title + ' ' + (item.description || '') + ' ' + (item.content_text || ''))
                    .toLowerCase().indexOf(needle) !== -1;
            });
            $('#evList').innerHTML = rows.length ? list(rows) : ui.empty('No evidence matches.',
                'Evidence is captured automatically when you paste a request or response into a check result.');
            DXB.on($('#evList'), 'click', '[data-verify]', function (event, el) {
                verify(parseInt(el.getAttribute('data-verify'), 10));
            });
            DXB.on($('#evList'), 'click', '[data-custody]', function (event, el) {
                custody(parseInt(el.getAttribute('data-custody'), 10));
            });
            DXB.on($('#evList'), 'click', '[data-del-ev]', function (event, el) {
                var id = parseInt(el.getAttribute('data-del-ev'), 10);
                DXB.confirm({
                    title: 'Delete evidence?',
                    message: 'The artefact and its hash are removed. The deletion itself is written to the audit trail.',
                    confirmLabel: 'Delete'
                }).then(function (ok) {
                    if (ok) { api.del('/evidence/' + id).then(load).catch(function (e) { DXB.toast(e.message, 'bad'); }); }
                });
            });
        }

        function load() {
            api.get('/assessments/' + a.id + '/evidence', null, { silent: true }).then(function (payload) {
                all = payload.data;
                render();
            }).catch(function (error) { $('#evList').innerHTML = ui.error(error.message); });
        }

        $('#eSearch').addEventListener('input', render);
        load();
        DXB.tabs.evidence.reload = load;
    };

    function list(rows) {
        return '<div class="grid c2">' + rows.map(function (item) {
            return '<div class="ev-card">' +
                '<div class="eh">' +
                    '<b class="small truncate" style="flex:1">' + esc(item.title) + '</b>' +
                    '<span class="badge mute">' + esc(fmt.label(item.evidence_type)) + '</span>' +
                    (item.is_redacted ? '<span class="badge accent" title="' + attr(item.redaction_summary || '') + '">redacted</span>' : '') +
                '</div>' +
                '<div class="eb">' +
                    (item.description ? '<p class="small dim">' + esc(item.description) + '</p>' : '') +
                    (item.content_text
                        ? '<pre class="code">' + esc(String(item.content_text).slice(0, 2600)) +
                          (String(item.content_text).length > 2600 ? '\n\n[truncated in this view]' : '') + '</pre>'
                        : '') +
                    (item.has_file && item.is_image
                        ? '<img class="ev-img" alt="' + attr(item.title) + '" loading="lazy" src="' + attr(DXB.apiBase + '/evidence/' + item.id + '/file') + '">'
                        : (item.has_file
                            ? '<a class="btn xs" href="' + attr(DXB.apiBase + '/evidence/' + item.id + '/file') + '">Download ' +
                              esc(item.original_name || 'artefact') + ' (' + esc(fmt.bytes(item.file_size)) + ')</a>'
                            : '')) +
                    '<div class="hash mt1">SHA-256 ' + esc(item.sha256) + '</div>' +
                    '<div class="flex small dim mt1">' +
                        '<span>' + esc(item.collected_by_name || 'unknown') + ' &middot; ' + esc(fmt.date(item.captured_at, true)) + '</span>' +
                        '<div class="spacer"></div>' +
                        '<button class="btn xs ghost" data-verify="' + item.id + '">Verify</button>' +
                        '<button class="btn xs ghost" data-custody="' + item.id + '">Custody</button>' +
                        (ui.can('evidence.delete') ? '<button class="btn xs ghost" data-del-ev="' + item.id + '">Delete</button>' : '') +
                    '</div>' +
                '</div>' +
            '</div>';
        }).join('') + '</div>';
    }

    function verify(id) {
        api.get('/evidence/' + id + '/verify', null, { silent: true }).then(function (payload) {
            var data = payload.data;
            DXB.modal({
                title: 'Integrity check',
                body: '<div class="callout ' + (data.verified ? 'ok' : 'warn') + '"><b>' +
                        (data.verified ? 'Hash matches.' : 'Hash does not match.') + '</b><br>' + esc(data.message) + '</div>' +
                    '<dl class="kv"><dt>Recorded</dt><dd class="mono wrap-any">' + esc(data.expected) + '</dd>' +
                    '<dt>Computed</dt><dd class="mono wrap-any">' + esc(data.actual || '-') + '</dd></dl>',
                actions: [{ label: 'Close' }]
            });
        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
    }

    function custody(id) {
        api.get('/evidence/' + id, null, { silent: true }).then(function (payload) {
            var chain = payload.data.custody || [];
            DXB.modal({
                title: 'Chain of custody',
                body: chain.length
                    ? '<div class="timeline">' + chain.map(function (entry) {
                        return '<div class="ti"><div class="tm">' + esc(fmt.date(entry.created_at, true)) + '</div>' +
                            '<div><b>' + esc(fmt.label(entry.action)) + '</b> by ' + esc(entry.actor_name || 'system') +
                            ' <span class="dim mono small">' + esc(entry.actor_ip || '') + '</span></div>' +
                            (entry.note ? '<div class="small dim">' + esc(entry.note) + '</div>' : '') + '</div>';
                    }).join('') + '</div>'
                    : '<p class="dim">No custody entries.</p>',
                actions: [{ label: 'Close' }]
            });
        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
    }

    function textDialog(a) {
        DXB.meta().then(function (meta) {
            DXB.modal({
                title: 'Record text evidence',
                size: 'wide',
                body:
                    '<div class="grid c2">' +
                        ui.field('Title', '<input type="text" name="title" placeholder="Response showing the SQL error">') +
                        ui.field('Type', ui.select('evidence_type', meta.evidence_types.map(function (t) {
                            return { value: t, label: fmt.label(t) };
                        }), 'http_response')) +
                    '</div>' +
                    ui.field('Description', '<input type="text" name="description" placeholder="Optional context for the reader">') +
                    ui.field('Content', '<textarea name="content_text" rows="14" class="mono" placeholder="Paste the raw request, response or log excerpt"></textarea>',
                        'Hashed with SHA-256 before any redaction, so integrity remains provable.'),
                actions: [
                    { label: 'Cancel' },
                    {
                        label: 'Record evidence', kind: 'primary', close: false,
                        onClick: function (bodyEl, close) {
                            var data = ui.readForm(bodyEl);
                            if (!data.content_text || !data.content_text.trim()) {
                                DXB.toast('Paste the evidence content.', 'warn');
                                return false;
                            }
                            api.post('/assessments/' + a.id + '/evidence', data).then(function () {
                                close();
                                DXB.tabs.evidence.reload();
                            }).catch(function (error) { DXB.toast(error.message, 'bad'); });
                            return false;
                        }
                    }
                ]
            });
        });
    }

    function uploadDialog(a) {
        DXB.modal({
            title: 'Upload evidence artefact',
            body:
                ui.field('File', '<input type="file" name="file" id="evFile">',
                    'Screenshots, exported logs, HAR files and PDFs. Validated by real content type, renamed on storage, and kept outside the web root.') +
                ui.field('Title', '<input type="text" name="title" placeholder="Defaults to the file name">') +
                ui.field('Description', '<input type="text" name="description" placeholder="Optional">'),
            actions: [
                { label: 'Cancel' },
                {
                    label: 'Upload', kind: 'primary', close: false,
                    onClick: function (bodyEl, close, button) {
                        var input = $('#evFile', bodyEl);
                        if (!input.files.length) { DXB.toast('Choose a file.', 'warn'); return false; }
                        var form = new FormData();
                        form.append('file', input.files[0]);
                        form.append('title', $('input[name=title]', bodyEl).value);
                        form.append('description', $('input[name=description]', bodyEl).value);
                        button.disabled = true;
                        button.textContent = 'Uploading...';
                        api.post('/assessments/' + a.id + '/evidence/upload', form).then(function () {
                            close();
                            DXB.tabs.evidence.reload();
                        }).catch(function (error) {
                            DXB.toast(error.message, 'bad', 9000);
                            button.disabled = false;
                            button.textContent = 'Upload';
                        });
                        return false;
                    }
                }
            ]
        });
    }

}(window.DXB));
