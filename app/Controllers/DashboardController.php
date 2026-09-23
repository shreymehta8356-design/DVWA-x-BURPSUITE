<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Auth;
use App\Core\Http;
use App\Services\DashboardService;

final class DashboardController
{
    public function overview(): never
    {
        Auth::requireLogin();
        Http::ok(DashboardService::overview());
    }

    public function trend(): never
    {
        Auth::requireLogin();
        Http::ok(DashboardService::findingTrend(Http::int('days', 30)));
    }
}
