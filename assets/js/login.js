/* ==========================================================================
   Sign-in handler.

   This lives in its own file rather than an inline <script> because the page
   ships a strict Content-Security-Policy (script-src 'self', no
   'unsafe-inline'). With an inline block the CSP silently blocked the handler,
   the browser fell back to a native form submit, and the password ended up in
   the URL and the Apache access log.
   ========================================================================== */
(function (document) {
    'use strict';

    var form = document.getElementById('loginForm');
    if (!form) { return; }

    var endpoint = form.getAttribute('data-endpoint');
    var base = form.getAttribute('data-base') || '';
    var button = document.getElementById('loginBtn');
    var errorBox = document.getElementById('loginError');

    function showError(message) {
        errorBox.textContent = message;
        errorBox.hidden = false;
    }

    form.addEventListener('submit', function (event) {
        // Stop the native submit unconditionally and first, so a later failure
        // can never leak the credentials into a GET query string.
        event.preventDefault();

        var username = document.getElementById('username').value;
        var password = document.getElementById('password').value;

        button.disabled = true;
        button.textContent = 'Signing in...';
        errorBox.hidden = true;

        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ username: username, password: password })
        }).then(function (response) {
            return response.json().catch(function () {
                throw new Error('The server did not return JSON (HTTP ' + response.status + '). Check storage/logs/php-error.log.');
            });
        }).then(function (payload) {
            if (payload && payload.ok) {
                window.location.replace(base + '/#/dashboard');
                window.location.reload();
                return;
            }
            showError((payload && payload.error) || 'Sign in failed.');
            button.disabled = false;
            button.textContent = 'Sign in';
        }).catch(function (error) {
            showError(error.message || 'Could not reach the server. Is Apache running in XAMPP?');
            button.disabled = false;
            button.textContent = 'Sign in';
        });
    });
}(document));
