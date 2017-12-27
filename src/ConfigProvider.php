<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Factory\CsrfGuardMiddlewareFactory;
use DASPRiD\CsrfGuard\Factory\HmacCsrfTokenManagerFactory;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;

final class ConfigProvider
{
    public function __invoke() : array
    {
        return [
            'dependencies' => [
                'factories' => [
                    CsrfTokenManagerInterface::class => HmacCsrfTokenManagerFactory::class,
                    CsrfGuardMiddleware::class => CsrfGuardMiddlewareFactory::class,
                ],
            ],
        ];
    }
}
