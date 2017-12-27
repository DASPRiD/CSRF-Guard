<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Factory;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\CsrfToken\HmacCsrfTokenManager;
use DASPRiD\TreeReader\TreeReader;
use Psr\Container\ContainerInterface;

final class HmacCsrfTokenManagerFactory
{
    public function __invoke(ContainerInterface $container) : CsrfTokenManagerInterface
    {
        $config = (new TreeReader($container->get('config'), 'config'))->getChildren('csrf_guard');

        return new HmacCsrfTokenManager(
            $config->getString('private_key')
        );
    }
}
