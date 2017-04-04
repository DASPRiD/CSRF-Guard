<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use CultuurNet\Clock\SystemClock;
use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;
use Psr\Container\ContainerInterface;

final class CsrfGuardMiddlewareFactory
{
    public function __invoke(ContainerInterface $container) : CsrfGuardMiddleware
    {
        $config = $container->get('config')['csrf_guard']['middleware'];

        return new CsrfGuardMiddleware(
            $container->get(CookieSettings::class),
            $config['uuid_attribute_name'],
            $config['token_post_name'],
            $container->get(JwtAdapterInterface::class),
            $container->get(CsrfTokenManagerInterface::class),
            new SystemClock(),
            $container->get($config['failure_middleware'])
        );
    }
}
