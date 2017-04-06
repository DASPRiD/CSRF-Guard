<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Factory;

use CultuurNet\Clock\SystemClock;
use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;
use DASPRiD\TreeReader\TreeReader;
use DateTimeZone;
use Psr\Container\ContainerInterface;

final class CsrfGuardMiddlewareFactory
{
    public function __invoke(ContainerInterface $container) : CsrfGuardMiddleware
    {
        $reader = new TreeReader($container->get('config'), 'config');
        $config = $reader->getChildren('csrf_guard')->getChildren('middleware');

        return new CsrfGuardMiddleware(
            $container->get(CookieSettings::class),
            $config->getString('uuid_attribute_name'),
            $config->getString('token_post_name'),
            $container->get(JwtAdapterInterface::class),
            $container->get(CsrfTokenManagerInterface::class),
            new SystemClock(new DateTimeZone('UTC')),
            $container->get($config->getString('failure_middleware'))
        );
    }
}
