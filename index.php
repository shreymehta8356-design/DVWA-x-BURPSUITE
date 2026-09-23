<?php
/**
 * DVWA x BURPSUITE - application entry point.
 *
 * Serves the sign-in screen when there is no session, and the single-page
 * console when there is. Everything below the shell is rendered by
 * assets/js, which talks to api/index.php over JSON.
 */

declare(strict_types=1);

require_once __DIR__ . '/app/bootstrap.php';

use App\Core\Auth;
use App\Core\Config;
use App\Core\Csrf;
use App\Core\Database;
use App\Core\Http;

// Security headers for the interface itself. The platform is a security tool;
// it would be embarrassing for it to be vulnerable to the things it reports.
// script-src stays strict with no 'unsafe-inline': every script on this page is
// an external file, and the bootstrap values the console needs are passed as
// data attributes on <body> rather than an inline block. That matters more than
// it sounds - an earlier revision used inline scripts, the CSP blocked them,
// and the login form silently fell back to a native GET submit that put the
// password in the URL and the access log.
//
// style-src does allow 'unsafe-inline', because the interface positions chart
// bars and severity colours with style attributes generated at runtime. Inline
// styles cannot exfiltrate data or execute code, so this is the standard
// trade-off; the directive that actually stops script injection is unrelaxed.
header("Content-Security-Policy: default-src 'self'; script-src 'self'; "
     . "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
     . "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; "
     . "base-uri 'self'; object-src 'none'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

$base = rtrim((string) Config::get('app.base_path', ''), '/');
$appName = (string) Config::get('app.name', 'DVWA x BURPSUITE');
$tagline = (string) Config::get('app.tagline', 'Offline Web Application Security Assessment Platform');

// Has the database been installed yet?
$installed = true;
$installError = '';
try {
    Database::scalar('SELECT COUNT(*) FROM users');
} catch (Throwable $e) {
    $installed = false;
    $installError = $e->getMessage();
}

$user = $installed ? Auth::user() : null;
$e = static fn (?string $v): string => Http::e($v);
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= $e($appName) ?><?= $user ? ' - Console' : ' - Sign in' ?></title>
<link rel="stylesheet" href="<?= $e($base) ?>/assets/css/app.css">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%230d9488'/><text x='16' y='22' font-family='monospace' font-size='16' font-weight='bold' text-anchor='middle' fill='%23042f2e'>D</text></svg>">
</head>
<body>

<?php if (!$installed): ?>
<!-- ===================== NOT INSTALLED ===================== -->
<div class="login-wrap">
    <div class="login-card" style="max-width:560px">
        <div class="logo"><div class="mark">D&times;B</div><div><h1><?= $e($appName) ?></h1></div></div>
        <div class="tagline">Setup required</div>

        <div class="callout bad">
            <b>The database is not reachable yet.</b><br>
            <span class="mono small"><?= $e(mb_substr($installError, 0, 300)) ?></span>
        </div>

        <p class="small muted">Complete the installation in three steps:</p>
        <ol class="small muted" style="line-height:2; padding-left:20px">
            <li>Start <b>Apache</b> and <b>MySQL</b> in the XAMPP control panel.</li>
            <li>Import the schema and seed data:<br>
                <code class="mono">mysql -u root -p &lt; database/schema.sql</code><br>
                <code class="mono">mysql -u root -p &lt; database/seed_reference.sql</code><br>
                <code class="mono">mysql -u root -p &lt; database/seed_users.sql</code><br>
                <span class="dim">or run <code class="mono">php tools/install.php</code> from the project folder.</span>
            </li>
            <li>Check the credentials in <code class="mono">config/config.php</code>, then reload this page.</li>
        </ol>
    </div>
</div>

<?php elseif ($user === null): ?>
<!-- ===================== SIGN IN ===================== -->
<div class="login-wrap">
    <form class="login-card" id="loginForm" method="post" action="" autocomplete="on"
          data-endpoint="<?= $e($base) ?>/api/index.php/auth/login" data-base="<?= $e($base) ?>">
        <div class="logo">
            <div class="mark">D&times;B</div>
            <div>
                <h1><?= $e($appName) ?></h1>
                <div class="dim small" style="letter-spacing:1.4px; text-transform:uppercase; font-size:9.5px">Offline assessment console</div>
            </div>
        </div>
        <div class="tagline"><?= $e($tagline) ?></div>

        <div id="loginError" class="callout bad" hidden></div>

        <label class="field">
            <span class="lbl">Username</span>
            <input type="text" id="username" name="username" autocomplete="username" required autofocus>
        </label>
        <label class="field">
            <span class="lbl">Password</span>
            <input type="password" id="password" name="password" autocomplete="current-password" required>
        </label>

        <button type="submit" class="btn primary" style="width:100%; padding:10px" id="loginBtn">Sign in</button>

        <div class="login-note">
            <strong>Controlled environment only.</strong> This platform records assessments of a locally hosted target
            such as DVWA. It performs no scanning and no exploitation of its own, and sends nothing off this machine.
        </div>
    </form>
</div>

<script src="<?= $e($base) ?>/assets/js/login.js"></script>

<?php else: ?>
<!-- ===================== CONSOLE ===================== -->
<div class="shell" id="app"
     data-base="<?= $e($base) ?>"
     data-api="<?= $e($base) ?>/api/index.php"
     data-csrf="<?= $e(Csrf::token()) ?>"
     data-user="<?= $e(json_encode(Auth::user(), JSON_UNESCAPED_SLASHES)) ?>"
     data-can="<?= $e(json_encode(Auth::capabilityMap())) ?>"
     data-must-change="<?= $user['must_change'] ? '1' : '0' ?>">
    <aside class="sidebar">
        <div class="brand">
            <div class="mark sm">D&times;B</div>
            <div>
                <div class="name">DVWA &times; BURPSUITE</div>
                <div class="sub">Assessment console</div>
            </div>
        </div>

        <nav class="nav" id="nav">
            <div class="nav-label">Workspace</div>
            <a href="#/dashboard"   data-nav="dashboard"><span class="ic">&#9632;</span> Dashboard</a>
            <a href="#/assessments" data-nav="assessments"><span class="ic">&#9635;</span> Assessments</a>
            <a href="#/catalog"     data-nav="catalog"><span class="ic">&#9776;</span> Check catalogue</a>

            <div class="nav-label">Platform</div>
            <a href="#/ai"    data-nav="ai"><span class="ic">&#9673;</span> AI models</a>
            <?php if (in_array(Auth::role(), ['lead', 'admin'], true)): ?>
            <a href="#/audit" data-nav="audit"><span class="ic">&#9740;</span> Audit trail</a>
            <?php endif; ?>
            <?php if (Auth::role() === 'admin'): ?>
            <a href="#/admin" data-nav="admin"><span class="ic">&#9881;</span> Administration</a>
            <?php endif; ?>
            <a href="#/account" data-nav="account"><span class="ic">&#9737;</span> My account</a>
        </nav>

        <div class="user">
            <div class="avatar"><?= $e(strtoupper(mb_substr((string) $user['full_name'], 0, 1))) ?></div>
            <div class="who">
                <b class="truncate"><?= $e($user['full_name']) ?></b>
                <span><?= $e($user['role']) ?></span>
            </div>
            <button class="btn xs ghost" id="logoutBtn" title="Sign out">Exit</button>
        </div>
    </aside>

    <div class="main">
        <header class="topbar">
            <div>
                <div class="crumbs" id="crumbs"></div>
                <h1 id="pageTitle">Dashboard</h1>
            </div>
            <div class="spacer"></div>
            <div id="pageActions" class="btn-row"></div>
        </header>
        <main class="content" id="view">
            <div class="loading"><div class="spinner"></div> Loading console...</div>
        </main>
    </div>
</div>

<div id="toasts"></div>


<script src="<?= $e($base) ?>/assets/js/core.js"></script>
<script src="<?= $e($base) ?>/assets/js/charts.js"></script>
<script src="<?= $e($base) ?>/assets/js/view-dashboard.js"></script>
<script src="<?= $e($base) ?>/assets/js/view-assessments.js"></script>
<script src="<?= $e($base) ?>/assets/js/view-workspace.js"></script>
<script src="<?= $e($base) ?>/assets/js/tab-tests.js"></script>
<script src="<?= $e($base) ?>/assets/js/tab-findings.js"></script>
<script src="<?= $e($base) ?>/assets/js/tab-evidence.js"></script>
<script src="<?= $e($base) ?>/assets/js/tab-remediation.js"></script>
<script src="<?= $e($base) ?>/assets/js/tab-import.js"></script>
<script src="<?= $e($base) ?>/assets/js/tab-reports.js"></script>
<script src="<?= $e($base) ?>/assets/js/view-catalog.js"></script>
<script src="<?= $e($base) ?>/assets/js/view-admin.js"></script>
<script src="<?= $e($base) ?>/assets/js/app.js"></script>
<?php endif; ?>

</body>
</html>
