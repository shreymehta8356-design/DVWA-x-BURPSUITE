<?php

declare(strict_types=1);

namespace App\Core;

/**
 * Authentication, session lifecycle and role based access control.
 *
 * Roles, from least to most privileged:
 *   reviewer  read everything, sign off peer review
 *   analyst   run tests, record results and evidence, draft findings
 *   lead      own assessments, set severity, finalise reports, manage scope
 *   admin     everything, plus users, settings, risk model and AI configuration
 */
final class Auth
{
    public const ROLES = ['reviewer', 'analyst', 'lead', 'admin'];

    /** Capability -> roles allowed. Checked by Auth::can(). */
    private const CAPABILITIES = [
        'assessment.view'    => ['reviewer', 'analyst', 'lead', 'admin'],
        'assessment.create'  => ['lead', 'admin'],
        'assessment.edit'    => ['lead', 'admin'],
        'assessment.delete'  => ['admin'],
        'test.execute'       => ['analyst', 'lead', 'admin'],
        'test.review'        => ['reviewer', 'lead', 'admin'],
        'evidence.add'       => ['analyst', 'lead', 'admin'],
        'evidence.delete'    => ['lead', 'admin'],
        'finding.create'     => ['analyst', 'lead', 'admin'],
        'finding.edit'       => ['analyst', 'lead', 'admin'],
        'finding.severity'   => ['lead', 'admin'],
        'finding.delete'     => ['lead', 'admin'],
        'remediation.edit'   => ['analyst', 'lead', 'admin'],
        'retest.record'      => ['analyst', 'lead', 'admin'],
        'report.generate'    => ['analyst', 'lead', 'admin'],
        'report.finalise'    => ['lead', 'admin'],
        'import.burp'        => ['analyst', 'lead', 'admin'],
        'catalog.edit'       => ['lead', 'admin'],
        'ai.use'             => ['analyst', 'lead', 'admin'],
        'ai.train'           => ['admin'],
        'admin.users'        => ['admin'],
        'admin.settings'     => ['admin'],
        'admin.audit'        => ['lead', 'admin'],
    ];

    // -----------------------------------------------------------------------
    // Login / logout
    // -----------------------------------------------------------------------

    /**
     * @return array{ok:bool,error?:string,user?:array<string,mixed>}
     */
    public static function attempt(string $username, string $password): array
    {
        $ip = Http::clientIp();
        $maxAttempts   = max(3, Config::settingInt('login_max_attempts', 5));
        $lockoutMinutes = max(1, Config::settingInt('login_lockout_minutes', 15));

        // Per-IP throttle independent of the account, to blunt spraying.
        $recent = (int) Database::scalar(
            "SELECT COUNT(*) FROM login_attempts
             WHERE ip_address = ? AND successful = 0 AND created_at > " . self::minutesAgo($lockoutMinutes),
            [$ip]
        );
        if ($recent >= $maxAttempts * 4) {
            self::recordAttempt($username, $ip, false);
            return ['ok' => false, 'error' => 'Too many failed attempts from this address. Try again later.'];
        }

        $user = Database::one('SELECT * FROM users WHERE username = ?', [$username]);

        if ($user === null) {
            // Constant-ish work regardless of whether the account exists, so
            // response timing does not disclose valid usernames.
            password_verify($password, '$2y$12$usesomesillystringfoobarbazqux0123456789abcdefghijklmnopq');
            self::recordAttempt($username, $ip, false);
            return ['ok' => false, 'error' => 'Invalid username or password.'];
        }

        if ((int) $user['is_active'] !== 1) {
            self::recordAttempt($username, $ip, false);
            return ['ok' => false, 'error' => 'This account is disabled.'];
        }

        if (!empty($user['locked_until']) && strtotime((string) $user['locked_until']) > time()) {
            self::recordAttempt($username, $ip, false);
            return ['ok' => false, 'error' => 'Account locked. Try again after ' . $user['locked_until'] . '.'];
        }

        if (!password_verify($password, (string) $user['password_hash'])) {
            $failed = (int) $user['failed_attempts'] + 1;
            $update = ['failed_attempts' => $failed];
            if ($failed >= $maxAttempts) {
                $update['locked_until'] = date('Y-m-d H:i:s', time() + $lockoutMinutes * 60);
                $update['failed_attempts'] = 0;
            }
            Database::update('users', $update, 'id = ?', [$user['id']]);
            self::recordAttempt($username, $ip, false);
            Audit::log('auth.login_failed', 'user', (int) $user['id'], ['username' => $username], null, (int) $user['id'], $username);
            return ['ok' => false, 'error' => 'Invalid username or password.'];
        }

        // Success ------------------------------------------------------------
        if (password_needs_rehash((string) $user['password_hash'], PASSWORD_BCRYPT, ['cost' => 12])) {
            Database::update('users', ['password_hash' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12])], 'id = ?', [$user['id']]);
        }

        Database::update('users', [
            'failed_attempts' => 0,
            'locked_until'    => null,
            'last_login_at'   => date('Y-m-d H:i:s'),
            'last_login_ip'   => $ip,
        ], 'id = ?', [$user['id']]);

        self::recordAttempt($username, $ip, true);
        self::startSession($user);
        Audit::log('auth.login', 'user', (int) $user['id'], ['role' => $user['role']]);

        return ['ok' => true, 'user' => self::publicUser($user)];
    }

    /** @param array<string,mixed> $user */
    private static function startSession(array $user): void
    {
        session_regenerate_id(true);           // defeats session fixation
        $_SESSION['uid']        = (int) $user['id'];
        $_SESSION['username']   = (string) $user['username'];
        $_SESSION['full_name']  = (string) $user['full_name'];
        $_SESSION['role']       = (string) $user['role'];
        $_SESSION['must_change'] = (int) $user['must_change_password'] === 1;
        $_SESSION['started_at'] = time();
        $_SESSION['last_seen']  = time();
        $_SESSION['fingerprint'] = self::fingerprint();
        Csrf::rotate();
    }

    /**
     * Establishes an identity for command line tooling (the installer, the
     * demo seeder, the self test) so their actions are attributed to a real
     * account in the audit trail instead of to "system".
     *
     * Guarded to the CLI SAPI: it can never be reached over HTTP.
     */
    public static function impersonateCli(string $username): bool
    {
        if (PHP_SAPI !== 'cli') {
            throw new \RuntimeException('impersonateCli is available on the command line only.');
        }
        $user = Database::one('SELECT * FROM users WHERE username = ? AND is_active = 1', [$username]);
        if ($user === null) {
            return false;
        }
        $_SESSION['uid']         = (int) $user['id'];
        $_SESSION['username']    = (string) $user['username'];
        $_SESSION['full_name']   = (string) $user['full_name'];
        $_SESSION['role']        = (string) $user['role'];
        $_SESSION['must_change'] = false;
        $_SESSION['started_at']  = time();
        $_SESSION['last_seen']   = time();
        $_SESSION['fingerprint'] = self::fingerprint();
        return true;
    }

    public static function logout(): void
    {
        if (self::check()) {
            Audit::log('auth.logout', 'user', (int) $_SESSION['uid']);
        }
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], (bool) $p['secure'], (bool) $p['httponly']);
        }
        session_destroy();
    }

    // -----------------------------------------------------------------------
    // Session state
    // -----------------------------------------------------------------------

    public static function check(): bool
    {
        if (empty($_SESSION['uid'])) {
            return false;
        }
        if (($_SESSION['fingerprint'] ?? '') !== self::fingerprint()) {
            self::logout();
            return false;
        }
        $idle = max(5, Config::settingInt('session_idle_minutes', (int) Config::get('session.idle_minutes', 30))) * 60;
        $absolute = (int) Config::get('session.absolute_hours', 12) * 3600;
        $now = time();
        if ($now - (int) ($_SESSION['last_seen'] ?? 0) > $idle) {
            self::logout();
            return false;
        }
        if ($now - (int) ($_SESSION['started_at'] ?? 0) > $absolute) {
            self::logout();
            return false;
        }
        $_SESSION['last_seen'] = $now;
        return true;
    }

    /** @return array<string,mixed>|null */
    public static function user(): ?array
    {
        if (!self::check()) {
            return null;
        }
        return [
            'id'          => (int) $_SESSION['uid'],
            'username'    => (string) $_SESSION['username'],
            'full_name'   => (string) $_SESSION['full_name'],
            'role'        => (string) $_SESSION['role'],
            'must_change' => (bool) ($_SESSION['must_change'] ?? false),
        ];
    }

    public static function id(): ?int
    {
        return self::check() ? (int) $_SESSION['uid'] : null;
    }

    public static function username(): string
    {
        return self::check() ? (string) $_SESSION['username'] : 'anonymous';
    }

    public static function role(): string
    {
        return self::check() ? (string) $_SESSION['role'] : 'guest';
    }

    public static function requireLogin(): void
    {
        if (!self::check()) {
            Http::fail('Authentication required.', 401, ['code' => 'auth_required']);
        }
    }

    /** @param array<int,string> $roles */
    public static function requireRole(array $roles): void
    {
        self::requireLogin();
        if (!in_array(self::role(), $roles, true)) {
            Audit::log('authz.denied', 'route', null, ['path' => Http::path(), 'required' => $roles]);
            Http::fail('Your role does not permit this action.', 403, ['code' => 'forbidden']);
        }
    }

    public static function can(string $capability): bool
    {
        $allowed = self::CAPABILITIES[$capability] ?? null;
        if ($allowed === null) {
            return false;
        }
        return in_array(self::role(), $allowed, true);
    }

    /** Aborts with 403 unless the current role holds the capability. */
    public static function must(string $capability): void
    {
        self::requireLogin();
        if (!self::can($capability)) {
            Audit::log('authz.denied', 'capability', null, ['capability' => $capability, 'role' => self::role()]);
            Http::fail('Your role does not permit this action (' . $capability . ').', 403, ['code' => 'forbidden']);
        }
    }

    /** @return array<string,bool> */
    public static function capabilityMap(): array
    {
        $map = [];
        foreach (array_keys(self::CAPABILITIES) as $capability) {
            $map[$capability] = self::can($capability);
        }
        return $map;
    }

    // -----------------------------------------------------------------------
    // Password management
    // -----------------------------------------------------------------------

    /** @return array{ok:bool,error?:string} */
    public static function changePassword(int $userId, string $current, string $new): array
    {
        $user = Database::one('SELECT * FROM users WHERE id = ?', [$userId]);
        if ($user === null) {
            return ['ok' => false, 'error' => 'Account not found.'];
        }
        if (!password_verify($current, (string) $user['password_hash'])) {
            Audit::log('auth.password_change_failed', 'user', $userId);
            return ['ok' => false, 'error' => 'Current password is incorrect.'];
        }
        $problem = self::passwordPolicy($new, (string) $user['username']);
        if ($problem !== null) {
            return ['ok' => false, 'error' => $problem];
        }
        if (password_verify($new, (string) $user['password_hash'])) {
            return ['ok' => false, 'error' => 'The new password must be different from the current one.'];
        }
        Database::update('users', [
            'password_hash'        => password_hash($new, PASSWORD_BCRYPT, ['cost' => 12]),
            'must_change_password' => 0,
            'updated_at'           => date('Y-m-d H:i:s'),
        ], 'id = ?', [$userId]);
        $_SESSION['must_change'] = false;
        Audit::log('auth.password_changed', 'user', $userId);
        return ['ok' => true];
    }

    /** Returns null when the password is acceptable, otherwise the reason. */
    public static function passwordPolicy(string $password, string $username = ''): ?string
    {
        if (mb_strlen($password) < 12) {
            return 'Password must be at least 12 characters long.';
        }
        if (mb_strlen($password) > 200) {
            return 'Password must be 200 characters or fewer.';
        }
        $classes = 0;
        $classes += preg_match('/[a-z]/', $password) ? 1 : 0;
        $classes += preg_match('/[A-Z]/', $password) ? 1 : 0;
        $classes += preg_match('/[0-9]/', $password) ? 1 : 0;
        $classes += preg_match('/[^a-zA-Z0-9]/', $password) ? 1 : 0;
        if ($classes < 3) {
            return 'Password must combine at least three of: lowercase, uppercase, digits, symbols.';
        }
        if ($username !== '' && stripos($password, $username) !== false) {
            return 'Password must not contain the username.';
        }
        $common = ['password', 'welcome', '123456', 'qwerty', 'letmein', 'admin', 'dvwa', 'burp', 'iloveyou'];
        $lower = strtolower($password);
        foreach ($common as $bad) {
            if (str_contains($lower, $bad)) {
                return 'Password contains a commonly used word and would be guessed quickly.';
            }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * @param  array<string,mixed> $user
     * @return array<string,mixed>
     */
    public static function publicUser(array $user): array
    {
        return [
            'id'          => (int) $user['id'],
            'username'    => (string) $user['username'],
            'full_name'   => (string) $user['full_name'],
            'email'       => $user['email'] ?? null,
            'role'        => (string) $user['role'],
            'is_active'   => (int) ($user['is_active'] ?? 1) === 1,
            'must_change' => (int) ($user['must_change_password'] ?? 0) === 1,
            'last_login_at' => $user['last_login_at'] ?? null,
        ];
    }

    private static function fingerprint(): string
    {
        // Binds the session to the user agent. Deliberately excludes the IP so
        // a changing local address does not log analysts out mid-assessment.
        return hash('sha256', Http::userAgent() . '|' . (Config::get('app.name') ?? ''));
    }

    private static function recordAttempt(string $username, string $ip, bool $ok): void
    {
        Database::insert('login_attempts', [
            'username'   => mb_substr($username, 0, 64),
            'ip_address' => $ip,
            'successful' => $ok ? 1 : 0,
            'user_agent' => Http::userAgent(),
        ]);
    }

    private static function minutesAgo(int $minutes): string
    {
        return Database::driver() === 'sqlite'
            ? "datetime('now', '-" . $minutes . " minutes')"
            : 'DATE_SUB(NOW(), INTERVAL ' . $minutes . ' MINUTE)';
    }
}
