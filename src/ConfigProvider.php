<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;

final class ConfigProvider
{
    public function __invoke() : array
    {
        return [
            'dependencies' => [
                JwtAdapterInterface::class => '',
                CsrfTokenManagerInterface::class => '',
                CookieSettings::class => '',
                CsrfGuardMiddleware::class => '',
            ],
        ];
    }
}
