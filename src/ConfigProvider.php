<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Factory\CookieSettingsFactory;
use DASPRiD\CsrfGuard\Factory\CsrfGuardMiddlewareFactory;
use DASPRiD\CsrfGuard\Factory\JwtCsrfTokenManagerFactory;
use DASPRiD\CsrfGuard\Factory\LcobucciAdapterFactory;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;

final class ConfigProvider
{
    public function __invoke() : array
    {
        return [
            'dependencies' => [
                'factories' => [
                    JwtAdapterInterface::class => LcobucciAdapterFactory::class,
                    CsrfTokenManagerInterface::class => JwtCsrfTokenManagerFactory::class,
                    CookieSettings::class => CookieSettingsFactory::class,
                    CsrfGuardMiddleware::class => CsrfGuardMiddlewareFactory::class,
                ],
            ],
        ];
    }
}
