/* ==========================================================================
   Burp Suite import tab.
   Reads a Burp issue XML export, classifies each issue with the offline model,
   and stages them for the analyst to accept or ignore. Nothing becomes a
   finding without an explicit decision.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc, attr = DXB.attr, fmt = DXB.fmt, ui = DXB.ui, api = DXB.api, $ = DXB.$, $$ = DXB.$$;

    DXB.tabs['import'] = function (a, panel) {
        panel.innerHTML = ui.loading();

        api.get('/assessments/' + a.id + '/import', null, { silent: true }).then(function (payload) {
            var imports = payload.data;
            panel.innerHTML =
                '<div class="split"><div>' +
                    '<div class="card mb2">' +
                        '<header><h3>Imports</h3><div class="spacer"></div>' +
                            (ui.can('import.burp') ? '<button class="btn sm primary" id="btnImport">Import Burp XML</button>' : '') +
                        '</header>' +
                        (imports.length ? importTable(imports) : ui.empty('No Burp exports imported yet.',
                            'In Burp: Target > Site map > right-click the host > Issues > Report selected issues > XML.')) +
                    '</div>' +
                    '<div id="issuePanel"></div>' +
                '</div><div>' + helpCard() + '</div></div>';

            if ($('#btnImport')) { $('#btnImport').addEventListener('click', function () { importDialog(a); }); }
            DXB.on(panel, 'click', '[data-import]', function (event, el) {
                loadIssues(a, parseInt(el.getAttribute('data-import'), 10));
            });

            if (imports.length) { loadIssues(a, imports[0].id); }
        }).catch(function (error) { panel.innerHTML = ui.error(error.message); });
    };

    function importTable(rows) {
        return '<div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th>File</th><th style="width:96px" class="num">Issues</th><th style="width:104px" class="num">Promoted</th>' +
            '<th style="width:130px">Imported by</th><th style="width:104px">When</th>' +
            '</tr></thead><tbody>' + rows.map(function (i) {
                return '<tr class="clickable" data-import="' + i.id + '">' +
                    '<td><b>' + esc(i.filename) + '</b>' +
                        '<div class="small dim mono">sha256 ' + esc(i.file_sha256_short) + '...' +
                        (i.burp_version ? ' &middot; Burp ' + esc(i.burp_version) : '') + '</div></td>' +
                    '<td class="num">' + i.issue_count + '</td>' +
                    '<td class="num">' + i.promoted + '</td>' +
                    '<td class="small">' + esc(i.imported_by_name || '-') + '</td>' +
                    '<td class="small dim">' + esc(fmt.ago(i.created_at)) + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table></div>';
    }

    function helpCard() {
        return '<div class="card"><header><h3>Exporting from Burp Suite</h3></header><div class="body small">' +
            '<ol style="padding-left:18px;line-height:1.9">' +
                '<li>Configure the browser to proxy through Burp (127.0.0.1:8080) and browse the DVWA modules in scope.</li>' +
                '<li>Open <b>Target &rarr; Site map</b>, right-click the host and choose <b>Issues &rarr; Report selected issues</b> ' +
                    '(Professional), or select the issues you logged manually.</li>' +
                '<li>Choose the <b>XML</b> format, and tick <b>Base64-encode requests and responses</b> so the captured ' +
                    'traffic survives intact.</li>' +
                '<li>Save the file locally and upload it here.</li>' +
            '</ol>' +
            '<div class="callout info mt2">Imported issues are <b>staged, not accepted</b>. Each one is classified by the ' +
                'offline model and mapped to a catalogue check, and you decide which become findings. The request and ' +
                'response travel with the issue and are stored as hashed, redacted evidence.</div>' +
            '<p class="dim">Using Burp Community without the scanner is fine: log issues manually in Burp, or paste ' +
                'requests and responses straight into a check result instead.</p>' +
        '</div></div>';
    }

    function importDialog(a) {
        DXB.modal({
            title: 'Import Burp Suite issue export',
            body:
                ui.field('Burp XML export', '<input type="file" id="burpFile" accept=".xml,text/xml,application/xml">') +
                '<div class="callout info small">The parser refuses XML that declares entities, so a modified export ' +
                    'cannot be used to attack this platform. Requests and responses are decoded, truncated to 200 KB ' +
                    'and stored as evidence when an issue is promoted.</div>',
            actions: [
                { label: 'Cancel' },
                {
                    label: 'Import', kind: 'primary', close: false,
                    onClick: function (bodyEl, close, button) {
                        var input = $('#burpFile', bodyEl);
                        if (!input.files.length) { DXB.toast('Choose the XML export.', 'warn'); return false; }
                        var form = new FormData();
                        form.append('file', input.files[0]);
                        button.disabled = true;
                        button.textContent = 'Parsing...';
                        api.post('/assessments/' + a.id + '/import/burp', form).then(function () {
                            close();
                            DXB.resolveRoute();
                        }).catch(function (error) {
                            DXB.toast(error.message, 'bad', 10000);
                            button.disabled = false;
                            button.textContent = 'Import';
                        });
                        return false;
                    }
                }
            ]
        });
    }

    function loadIssues(a, importId) {
        var host = $('#issuePanel');
        host.innerHTML = ui.loading('Loading staged issues...');

        api.get('/imports/' + importId + '/issues', null, { silent: true }).then(function (payload) {
            var issues = payload.data;
            host.innerHTML =
                '<div class="card"><header><h3>Staged issues</h3><div class="spacer"></div>' +
                    '<span class="small dim" id="promoteCount"></span>' +
                    (ui.can('finding.create') ? '<button class="btn sm primary" id="btnPromote">Promote selected</button>' : '') +
                '</header>' +
                (issues.length ? issueTable(issues) : ui.empty('This export contained no issues.')) +
                '</div>';

            function updateCount() {
                var n = $$('#issuePanel input[name=iss]:checked').length;
                $('#promoteCount').textContent = n + ' selected';
                if ($('#btnPromote')) { $('#btnPromote').disabled = n === 0; }
            }
            DXB.on(host, 'change', 'input[name=iss]', updateCount);
            DXB.on(host, 'click', '[data-issue]', function (event, el) {
                if (event.target.tagName === 'INPUT') { return; }
                showIssue(parseInt(el.getAttribute('data-issue'), 10));
            });

            if ($('#btnPromote')) {
                $('#btnPromote').addEventListener('click', function () {
                    var ids = $$('#issuePanel input[name=iss]:checked').map(function (i) { return parseInt(i.value, 10); });
                    if (!ids.length) { return; }
                    this.disabled = true;
                    this.textContent = 'Creating findings...';
                    api.post('/assessments/' + a.id + '/import/promote', { issue_ids: ids })
                        .then(function () { DXB.resolveRoute(); })
                        .catch(function (error) { DXB.toast(error.message, 'bad', 9000); DXB.resolveRoute(); });
                });
            }
            updateCount();
        }).catch(function (error) { host.innerHTML = ui.error(error.message); });
    }

    function issueTable(issues) {
        return '<div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th style="width:34px"></th><th>Burp issue</th><th style="width:104px">Burp severity</th>' +
            '<th style="width:200px">Offline classification</th><th style="width:104px">Check</th><th style="width:110px">State</th>' +
            '</tr></thead><tbody>' + issues.map(function (issue) {
                var done = issue.action === 'imported';
                return '<tr class="clickable" data-issue="' + issue.id + '">' +
                    '<td>' + (done ? '' : '<input type="checkbox" name="iss" value="' + issue.id + '">') + '</td>' +
                    '<td><b>' + esc(issue.name) + '</b>' +
                        '<div class="small dim mono truncate" style="max-width:520px">' + esc(issue.host || '') + esc(issue.path || '') +
                        (issue.location ? ' &middot; ' + esc(issue.location) : '') + '</div></td>' +
                    '<td>' + burpSeverity(issue.burp_severity) +
                        '<div class="small dim">' + esc(issue.burp_confidence || '') + '</div></td>' +
                    '<td class="small">' + (issue.ai_category
                        ? esc(issue.ai_category) + ' <span class="badge accent">' + Math.round((issue.ai_confidence || 0) * 100) + '%</span>'
                        : '<span class="dim">unclassified</span>') + '</td>' +
                    '<td class="small mono">' + esc(issue.catalog_code || '-') + '</td>' +
                    '<td class="small">' + (done
                        ? '<span class="badge ok">' + esc(issue.finding_ref || 'imported') + '</span>'
                        : '<span class="badge mute">pending</span>') + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table></div>';
    }

    function burpSeverity(severity) {
        var map = { High: 'sev-high', Medium: 'sev-medium', Low: 'sev-low', Information: 'sev-info' };
        return '<span class="badge ' + (map[severity] || 'mute') + '">' + esc(severity || 'unknown') + '</span>';
    }

    function showIssue(issueId) {
        api.get('/burp-issues/' + issueId, null, { silent: true }).then(function (payload) {
            var issue = payload.data;
            DXB.modal({
                title: issue.name,
                size: 'xwide',
                body:
                    '<dl class="kv mb2">' +
                        '<dt>Host</dt><dd class="mono">' + esc(issue.host || '') + esc(issue.path || '') + '</dd>' +
                        '<dt>Location</dt><dd>' + esc(issue.location || '-') + '</dd>' +
                        '<dt>Burp rating</dt><dd>' + burpSeverity(issue.burp_severity) + ' / ' + esc(issue.burp_confidence || '') + '</dd>' +
                        '<dt>Offline class</dt><dd>' + esc(issue.ai_category || 'unclassified') + '</dd>' +
                    '</dl>' +
                    (issue.issue_detail ? '<h4>Issue detail</h4><div class="small">' + stripTags(issue.issue_detail) + '</div>' : '') +
                    (issue.issue_background ? '<h4 class="mt2">Background</h4><div class="small dim">' + stripTags(issue.issue_background) + '</div>' : '') +
                    (issue.remediation_background ? '<h4 class="mt2">Burp remediation guidance</h4><div class="small dim">' + stripTags(issue.remediation_background) + '</div>' : '') +
                    (issue.request_text ? '<h4 class="mt2">Request</h4><pre class="code">' + esc(issue.request_text) + '</pre>' : '') +
                    (issue.response_text ? '<h4 class="mt2">Response</h4><pre class="code tall">' + esc(issue.response_text) + '</pre>' : ''),
                actions: [{ label: 'Close' }]
            });
        }).catch(function (error) { DXB.toast(error.message, 'bad'); });
    }

    /** Burp issue text is HTML. Render it as escaped text with line breaks preserved. */
    function stripTags(html) {
        var text = String(html)
            .replace(/<\s*br\s*\/?>/gi, '\n')
            .replace(/<\/\s*(p|li|div|h[1-6])\s*>/gi, '\n')
            .replace(/<[^>]*>/g, '');
        var textarea = document.createElement('textarea');
        textarea.innerHTML = text;
        return esc(textarea.value).replace(/\n/g, '<br>');
    }

}(window.DXB));
