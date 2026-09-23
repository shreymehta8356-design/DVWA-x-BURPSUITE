/* ==========================================================================
   DVWA x BURPSUITE - front-end core
   Vanilla JavaScript only. No framework, no build step, no CDN: the console
   must run from a plain XAMPP htdocs folder on a machine with no network.
   ========================================================================== */
(function (window, document) {
    'use strict';

    var DXB = window.DXB || (window.DXB = {});

    /* ----------------------------------------------------------------------
       Bootstrap.

       The server passes the session values as data attributes on the shell
       rather than an inline <script>, because the page ships a strict
       Content-Security-Policy with script-src 'self' and no 'unsafe-inline'.
       ---------------------------------------------------------------------- */
    (function bootstrap() {
        var shell = document.getElementById('app');
        if (!shell) { return; }

        function json(name, fallback) {
            var raw = shell.getAttribute('data-' + name);
            if (!raw) { return fallback; }
            try { return JSON.parse(raw); } catch (error) { return fallback; }
        }

        DXB.base = shell.getAttribute('data-base') || '';
        // NOTE: this is the API base URL. It must NOT be called DXB.api -
        // that name is taken by the API client object exported at the end of
        // this file, which would overwrite the string and send every request
        // to "/[object Object]/...".
        DXB.apiBase = shell.getAttribute('data-api') || (DXB.base + '/api/index.php');
        DXB.csrf = shell.getAttribute('data-csrf') || '';
        DXB.user = json('user', {});
        DXB.can = json('can', {});
        DXB.mustChangePassword = shell.getAttribute('data-must-change') === '1';
    }());

    /* ----------------------------------------------------------------------
       DOM helpers
       ---------------------------------------------------------------------- */

    /** Escapes a value for safe insertion into HTML. Used on EVERY interpolation. */
    function esc(value) {
        if (value === null || value === undefined) { return ''; }
        return String(value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    /** Escapes for use inside an HTML attribute delimited by double quotes. */
    function attr(value) { return esc(value); }

    function $(selector, root) { return (root || document).querySelector(selector); }
    function $$(selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); }

    function frag(htmlString) {
        var template = document.createElement('template');
        template.innerHTML = htmlString.trim();
        return template.content;
    }

    /** Delegated event binding: on(root, 'click', '[data-x]', handler) */
    function on(root, type, selector, handler) {
        root.addEventListener(type, function (event) {
            var target = event.target.closest(selector);
            if (target && root.contains(target)) { handler.call(target, event, target); }
        });
    }

    /* ----------------------------------------------------------------------
       API client
       ---------------------------------------------------------------------- */

    var inflight = 0;

    function request(method, path, body, options) {
        options = options || {};
        var url = DXB.apiBase + path;
        var init = {
            method: method,
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        };

        if (method !== 'GET' && method !== 'HEAD') {
            init.headers['X-CSRF-Token'] = DXB.csrf;
            if (body instanceof FormData) {
                body.append('_csrf', DXB.csrf);
                init.body = body;                    // browser sets the boundary
            } else if (body !== undefined && body !== null) {
                init.headers['Content-Type'] = 'application/json';
                init.body = JSON.stringify(body);
            }
        } else if (body) {
            var query = new URLSearchParams();
            Object.keys(body).forEach(function (key) {
                if (body[key] !== '' && body[key] !== null && body[key] !== undefined) {
                    query.append(key, body[key]);
                }
            });
            var queryString = query.toString();
            if (queryString) { url += (url.indexOf('?') === -1 ? '?' : '&') + queryString; }
        }

        inflight++;
        return fetch(url, init).then(function (response) {
            return response.json().catch(function () {
                throw new ApiError('The server returned a response that was not JSON (HTTP ' + response.status + '). Check storage/logs/php-error.log.', response.status, null);
            }).then(function (payload) {
                if (payload && payload.ok) {
                    if (payload.message && !options.silent) { toast(payload.message, 'ok'); }
                    return payload;
                }
                var error = new ApiError(
                    (payload && payload.error) || ('Request failed (HTTP ' + response.status + ')'),
                    response.status,
                    payload
                );
                if (response.status === 401 && !options.allowAnonymous) {
                    toast('Your session has ended. Signing you back in...', 'warn');
                    setTimeout(function () { window.location.href = DXB.base + '/'; }, 900);
                }
                throw error;
            });
        }).finally(function () { inflight--; });
    }

    function ApiError(message, status, payload) {
        this.name = 'ApiError';
        this.message = message;
        this.status = status;
        this.payload = payload;
    }
    ApiError.prototype = Object.create(Error.prototype);

    var api = {
        get: function (path, query, options) { return request('GET', path, query, options); },
        post: function (path, body, options) { return request('POST', path, body, options); },
        put: function (path, body, options) { return request('PUT', path, body, options); },
        del: function (path, body, options) { return request('DELETE', path, body, options); },
        /** Runs a call, showing any domain error as a toast, and resolves to null on failure. */
        safe: function (promise, onError) {
            return promise.catch(function (error) {
                if (onError) { onError(error); } else { toast(error.message, 'bad'); }
                return null;
            });
        }
    };

    /* ----------------------------------------------------------------------
       Toasts, modals, confirmation
       ---------------------------------------------------------------------- */

    function toast(message, kind, ms) {
        var host = $('#toasts');
        if (!host) { return; }
        var node = document.createElement('div');
        node.className = 'toast ' + (kind || '');
        node.textContent = message;
        host.appendChild(node);
        setTimeout(function () {
            node.style.transition = 'opacity .25s, transform .25s';
            node.style.opacity = '0';
            node.style.transform = 'translateX(14px)';
            setTimeout(function () { node.remove(); }, 260);
        }, ms || (kind === 'bad' ? 7000 : 4200));
    }

    /**
     * Opens a modal.
     * options: { title, body (HTML string or Node), size, actions:[{label,kind,onClick,close}],
     *            onMount(bodyEl, close) }
     */
    function modal(options) {
        var backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';

        var actionsHtml = (options.actions || []).map(function (action, index) {
            return '<button class="btn ' + attr(action.kind || '') + '" data-action="' + index + '">' + esc(action.label) + '</button>';
        }).join('');

        backdrop.innerHTML =
            '<div class="modal ' + attr(options.size || '') + '" role="dialog" aria-modal="true">' +
                '<header><h3>' + esc(options.title || '') + '</h3><button class="x" data-close aria-label="Close">&times;</button></header>' +
                '<div class="body"></div>' +
                (actionsHtml ? '<footer>' + actionsHtml + '</footer>' : '') +
            '</div>';

        var bodyEl = $('.body', backdrop);
        if (typeof options.body === 'string') { bodyEl.innerHTML = options.body; }
        else if (options.body) { bodyEl.appendChild(options.body); }

        function close() {
            document.removeEventListener('keydown', onKey);
            backdrop.remove();
        }
        function onKey(event) { if (event.key === 'Escape') { close(); } }

        backdrop.addEventListener('click', function (event) {
            if (event.target === backdrop || event.target.hasAttribute('data-close')) { close(); }
        });
        document.addEventListener('keydown', onKey);

        $$('[data-action]', backdrop).forEach(function (button) {
            button.addEventListener('click', function () {
                var action = options.actions[parseInt(button.getAttribute('data-action'), 10)];
                var result = action.onClick ? action.onClick(bodyEl, close, button) : true;
                if (action.close !== false && result !== false) { close(); }
            });
        });

        document.body.appendChild(backdrop);
        if (options.onMount) { options.onMount(bodyEl, close); }
        var firstInput = $('input:not([type=hidden]), textarea, select', bodyEl);
        if (firstInput) { firstInput.focus(); }
        return { close: close, body: bodyEl, root: backdrop };
    }

    function confirmAction(options) {
        return new Promise(function (resolve) {
            modal({
                title: options.title || 'Confirm',
                body: '<p>' + esc(options.message) + '</p>' +
                      (options.detail ? '<div class="callout warn">' + esc(options.detail) + '</div>' : ''),
                actions: [
                    { label: options.cancelLabel || 'Cancel', onClick: function () { resolve(false); } },
                    { label: options.confirmLabel || 'Confirm', kind: options.kind || 'danger', onClick: function () { resolve(true); } }
                ]
            });
        });
    }

    /* ----------------------------------------------------------------------
       Formatting
       ---------------------------------------------------------------------- */

    var fmt = {
        date: function (value, withTime) {
            if (!value) { return '-'; }
            var d = new Date(String(value).replace(' ', 'T'));
            if (isNaN(d.getTime())) { return String(value); }
            var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
            var out = String(d.getDate()).padStart(2, '0') + ' ' + months[d.getMonth()] + ' ' + d.getFullYear();
            if (withTime) {
                out += ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
            }
            return out;
        },
        ago: function (value) {
            if (!value) { return '-'; }
            var then = new Date(String(value).replace(' ', 'T')).getTime();
            if (isNaN(then)) { return String(value); }
            var seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
            if (seconds < 60) { return 'just now'; }
            if (seconds < 3600) { return Math.floor(seconds / 60) + ' min ago'; }
            if (seconds < 86400) { return Math.floor(seconds / 3600) + ' h ago'; }
            if (seconds < 2592000) { return Math.floor(seconds / 86400) + ' d ago'; }
            return fmt.date(value);
        },
        label: function (value) {
            if (!value) { return ''; }
            return String(value).replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
        },
        sev: function (severity) {
            var s = String(severity || 'info').toLowerCase();
            return '<span class="badge sev-' + attr(s) + '">' + esc(s) + '</span>';
        },
        result: function (status) {
            var map = {
                pass: 'ok', fail: 'bad', manual_review: 'warn', not_applicable: 'mute',
                pending: 'mute', in_progress: 'accent',
                fixed: 'ok', partially_fixed: 'warn', not_fixed: 'bad', not_testable: 'mute',
                open: 'bad', in_remediation: 'warn', ready_for_retest: 'accent', resolved: 'ok',
                risk_accepted: 'mute', false_positive: 'mute', duplicate: 'mute',
                not_started: 'mute', implemented: 'accent', verified: 'ok', deferred: 'warn', accepted: 'mute',
                approved: 'ok', unreviewed: 'mute', rework: 'warn',
                draft: 'mute', testing_complete: 'accent', retest: 'warn', closed: 'ok', final: 'ok'
            };
            var s = String(status || '');
            return '<span class="badge pill ' + attr(map[s] || 'mute') + '">' + esc(fmt.label(s)) + '</span>';
        },
        percent: function (n) { return Math.round(Number(n) || 0) + '%'; },
        bytes: function (n) {
            n = Number(n) || 0;
            if (n < 1024) { return n + ' B'; }
            if (n < 1048576) { return (n / 1024).toFixed(1) + ' KB'; }
            return (n / 1048576).toFixed(1) + ' MB';
        },
        num: function (n) { return String(Number(n) || 0); }
    };

    /* ----------------------------------------------------------------------
       Small building blocks used across views
       ---------------------------------------------------------------------- */

    var ui = {
        loading: function (message) {
            return '<div class="loading"><div class="spinner"></div> ' + esc(message || 'Loading...') + '</div>';
        },
        empty: function (message, hint) {
            return '<div class="empty"><div class="big">&#9634;</div><div>' + esc(message) + '</div>' +
                   (hint ? '<div class="small dim mt1">' + esc(hint) + '</div>' : '') + '</div>';
        },
        error: function (message) {
            return '<div class="callout bad"><b>Something went wrong.</b><br>' + esc(message) + '</div>';
        },
        stat: function (value, label, sub, colour) {
            return '<div class="stat">' +
                '<div class="v"' + (colour ? ' style="color:' + attr(colour) + '"' : '') + '>' + esc(value) + '</div>' +
                '<div class="l">' + esc(label) + '</div>' +
                (sub ? '<div class="sub">' + esc(sub) + '</div>' : '') +
            '</div>';
        },
        progress: function (percent) {
            var p = Math.max(0, Math.min(100, Math.round(Number(percent) || 0)));
            return '<div class="progress"><i style="width:' + p + '%"></i></div>';
        },
        field: function (label, controlHtml, hint) {
            return '<label class="field"><span class="lbl">' + esc(label) + '</span>' + controlHtml +
                   (hint ? '<span class="hint">' + esc(hint) + '</span>' : '') + '</label>';
        },
        select: function (name, options, selected, extra) {
            return '<select name="' + attr(name) + '" ' + (extra || '') + '>' +
                options.map(function (option) {
                    var value = typeof option === 'object' ? option.value : option;
                    var text = typeof option === 'object' ? option.label : fmt.label(option);
                    return '<option value="' + attr(value) + '"' + (String(value) === String(selected) ? ' selected' : '') + '>' + esc(text) + '</option>';
                }).join('') + '</select>';
        },
        /** Reads a form-like container into a plain object. */
        readForm: function (root) {
            var data = {};
            $$('input[name], select[name], textarea[name]', root).forEach(function (input) {
                if (input.type === 'checkbox') { data[input.name] = input.checked; }
                else if (input.type === 'radio') { if (input.checked) { data[input.name] = input.value; } }
                else if (input.type === 'number' || input.type === 'range') { data[input.name] = Number(input.value); }
                else { data[input.name] = input.value; }
            });
            return data;
        },
        can: function (capability) { return !!(DXB.can && DXB.can[capability]); }
    };

    /* ----------------------------------------------------------------------
       Hash router
       ---------------------------------------------------------------------- */

    var routes = [];
    var current = { path: '', params: {} };

    function route(pattern, handler) {
        var keys = [];
        var regex = new RegExp('^' + pattern.replace(/:([A-Za-z_]+)/g, function (_, key) {
            keys.push(key);
            return '([^/]+)';
        }) + '$');
        routes.push({ regex: regex, keys: keys, handler: handler, pattern: pattern });
    }

    function navigate(path) {
        if (window.location.hash === '#' + path) { resolve(); }
        else { window.location.hash = '#' + path; }
    }

    function resolve() {
        var path = (window.location.hash || '#/dashboard').slice(1) || '/dashboard';
        var view = $('#view');
        if (!view) { return; }

        for (var i = 0; i < routes.length; i++) {
            var match = path.match(routes[i].regex);
            if (!match) { continue; }
            var params = {};
            routes[i].keys.forEach(function (key, index) { params[key] = decodeURIComponent(match[index + 1]); });
            current = { path: path, params: params };
            highlightNav(path);
            view.scrollTop = 0;
            window.scrollTo(0, 0);
            try {
                routes[i].handler(params, view);
            } catch (error) {
                view.innerHTML = ui.error(error && error.message ? error.message : String(error));
            }
            return;
        }
        view.innerHTML = ui.empty('That screen does not exist.', 'Use the navigation on the left.');
        setHeader('Not found', '');
    }

    function highlightNav(path) {
        var section = path.split('/')[1] || 'dashboard';
        if (section === 'assessment') { section = 'assessments'; }
        $$('#nav a').forEach(function (link) {
            link.classList.toggle('active', link.getAttribute('data-nav') === section);
        });
    }

    function setHeader(title, crumbs, actionsHtml) {
        var titleEl = $('#pageTitle');
        var crumbEl = $('#crumbs');
        var actionsEl = $('#pageActions');
        if (titleEl) { titleEl.textContent = title; }
        if (crumbEl) { crumbEl.innerHTML = crumbs || ''; }
        if (actionsEl) { actionsEl.innerHTML = actionsHtml || ''; }
        document.title = title + ' - DVWA x BURPSUITE';
    }

    /* ----------------------------------------------------------------------
       Reference data, loaded once and cached
       ---------------------------------------------------------------------- */

    var metaCache = null;
    function meta() {
        if (metaCache) { return Promise.resolve(metaCache); }
        return api.get('/meta', null, { silent: true }).then(function (payload) {
            metaCache = payload.data;
            return metaCache;
        });
    }

    /* ----------------------------------------------------------------------
       Exports
       ---------------------------------------------------------------------- */

    DXB.esc = esc;
    DXB.attr = attr;
    DXB.$ = $;
    DXB.$$ = $$;
    DXB.frag = frag;
    DXB.on = on;
    DXB.api = api;
    DXB.toast = toast;
    DXB.modal = modal;
    DXB.confirm = confirmAction;
    DXB.fmt = fmt;
    DXB.ui = ui;
    DXB.route = route;
    DXB.navigate = navigate;
    DXB.resolveRoute = resolve;
    DXB.setHeader = setHeader;
    DXB.meta = meta;
    DXB.currentRoute = function () { return current; };
    DXB.views = {};
    DXB.tabs = {};

}(window, document));
