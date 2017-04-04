<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use Psr\Container\ContainerInterface;

final class CookieSettingsFactory
{
    public function __invoke(ContainerInterface $container) : CookieSettings
    {
        $config = $container->get('config')['csrf_guard']['cookie'];

        return new CookieSettings(
            $config['name'],
            $config['path'],
            $config['secure'],
            $config['lifetime'],
            $config['refresh_time']
        );
    }
}
