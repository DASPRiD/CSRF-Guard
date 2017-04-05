<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use DASPRiD\TreeReader\TreeReader;
use Psr\Container\ContainerInterface;

final class CookieSettingsFactory
{
    public function __invoke(ContainerInterface $container) : CookieSettings
    {
        $reader = new TreeReader($container->get('config'));
        $config = $reader->getChildren('csrf_guard')->getChildren('cookie');

        return new CookieSettings(
            $config->getString('name'),
            $config->getString('path'),
            $config->getBool('secure'),
            $config->getInt('lifetime'),
            $config->getInt('refresh_time')
        );
    }
}
