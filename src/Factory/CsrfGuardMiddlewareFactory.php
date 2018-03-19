<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Factory;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;
use DASPRiD\Pikkuleipa\CookieManagerInterface;
use DASPRiD\TreeReader\TreeReader;
use Psr\Container\ContainerInterface;

final class CsrfGuardMiddlewareFactory
{
    public function __invoke(ContainerInterface $container) : CsrfGuardMiddleware
    {
        $config = (new TreeReader($container->get('config'), 'config'))->getChildren('csrf_guard');
        $publicKeyProvider = null;

        if ($config->hasNonNullValue('public_key_provider')) {
            $publicKeyProvider = $container->get($config->getString('public_key_provider'));
        }

        return new CsrfGuardMiddleware(
            $container->get(CookieManagerInterface::class),
            $container->get(CsrfTokenManagerInterface::class),
            $container->get($config->getString('failure_handler')),
            $config->getString('cookie_name'),
            $config->getString('token_attribute_name'),
            $config->getString('request_token_name'),
            $publicKeyProvider
        );
    }
}
