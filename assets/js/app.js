/* ==========================================================================
   Boot: route table, global event delegation and session handling.
   ========================================================================== */
(function (DXB, window, document) {
    'use strict';

    /* ---------------------------------------------------------------- routes */
    DXB.route('/dashboard',   DXB.views.dashboard);
    DXB.route('/assessments', DXB.views.assessments);
    DXB.route('/assessment/:id',      function (p, v) { DXB.views.workspace({ id: p.id, tab: 'overview' }, v); });
    DXB.route('/assessment/:id/:tab', DXB.views.workspace);
    DXB.route('/catalog', DXB.views.catalog);
    DXB.route('/ai',      DXB.views.ai);
    DXB.route('/audit',   DXB.views.audit);
    DXB.route('/admin',   DXB.views.admin);
    DXB.route('/account', DXB.views.account);

    /* ------------------------------------------------------- global actions */
    document.addEventListener('click', function (event) {
        var target = event.target.closest('[data-new-assessment]');
        if (target) { event.preventDefault(); DXB.newAssessmentDialog(); return; }

        var actions = DXB.workspaceActions || {};
        var map = [
            ['[data-add-scope]', function () { actions.addScope(); }],
            ['[data-edit-assessment]', function () { actions.editAssessment(); }],
            ['[data-delete-assessment]', function () { actions.deleteAssessment(); }]
        ];
        for (var i = 0; i < map.length; i++) {
            if (event.target.closest(map[i][0])) { event.preventDefault(); map[i][1](); return; }
        }

        var scope = event.target.closest('[data-remove-scope]');
        if (scope) { event.preventDefault(); actions.removeScope(scope.getAttribute('data-remove-scope')); return; }

        var status = event.target.closest('[data-set-status]');
        if (status) { event.preventDefault(); actions.setStatus(status.getAttribute('data-set-status')); return; }
    });

    /* --------------------------------------------------------------- logout */
    var logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function () {
            DXB.api.post('/auth/logout', {}, { silent: true }).finally(function () {
                window.location.href = DXB.base + '/';
            });
        });
    }

    /* ---------------------------------------------------------- hash router */
    window.addEventListener('hashchange', DXB.resolveRoute);

    if (!window.location.hash) { window.location.hash = '#/dashboard'; }
    DXB.resolveRoute();

    /* ------------------------------------------- first-login password prompt */
    if (DXB.mustChangePassword) {
        setTimeout(function () {
            DXB.toast('This account is still on its initial password. Change it in My account before recording assessment work.', 'warn', 12000);
        }, 900);
    }

    /* --------------------------------------------------------- session watch */
    // A quiet heartbeat: if the session has expired server side, send the
    // analyst back to the sign-in screen instead of letting saves fail.
    setInterval(function () {
        DXB.api.get('/auth/me', null, { silent: true, allowAnonymous: true }).then(function (payload) {
            if (payload.data && payload.data.authenticated === false) {
                window.location.href = DXB.base + '/';
            }
        }).catch(function () { /* transient; the next tick will retry */ });
    }, 120000);

}(window.DXB, window, document));
