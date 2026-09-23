<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Auth;
use App\Core\Csrf;
use App\Core\Http;

final class AuthController
{
    public function login(): never
    {
        $username = Http::str('username', '', 64);
        $password = (string) (Http::body()['password'] ?? '');

        if ($username === '' || $password === '') {
            Http::fail('Enter both a username and a password.', 422);
        }

        $result = Auth::attempt($username, $password);
        if (!$result['ok']) {
            // Deliberately uniform: the message never distinguishes an unknown
            // account from a wrong password.
            Http::fail($result['error'] ?? 'Invalid username or password.', 401);
        }

        Http::ok([
            'user'         => $result['user'],
            'csrf'         => Csrf::token(),
            'capabilities' => Auth::capabilityMap(),
        ]);
    }

    public function me(): never
    {
        if (!Auth::check()) {
            Http::json(['ok' => true, 'data' => ['authenticated' => false]], 200);
        }
        Http::ok([
            'authenticated' => true,
            'user'          => Auth::user(),
            'csrf'          => Csrf::token(),
            'capabilities'  => Auth::capabilityMap(),
        ]);
    }

    public function logout(): never
    {
        Auth::logout();
        Http::ok(['message' => 'Signed out.']);
    }

    public function changePassword(): never
    {
        $userId = Auth::id();
        if ($userId === null) {
            Http::fail('Authentication required.', 401);
        }
        $body = Http::body();
        $result = Auth::changePassword(
            $userId,
            (string) ($body['current_password'] ?? ''),
            (string) ($body['new_password'] ?? '')
        );
        if (!$result['ok']) {
            Http::fail($result['error'] ?? 'Could not change the password.', 422);
        }
        Http::ok(['message' => 'Password changed.']);
    }
}
