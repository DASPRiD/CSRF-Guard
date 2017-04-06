<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Factory;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\CsrfToken\JwtCsrfTokenManager;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\TreeReader\TreeReader;
use Psr\Container\ContainerInterface;

final class JwtCsrfTokenManagerFactory
{
    public function __invoke(ContainerInterface $container) : CsrfTokenManagerInterface
    {
        $reader = new TreeReader($container->get('config'), 'config');
        $config = $reader->getChildren('csrf_guard')->getChildren('csrf');

        return new JwtCsrfTokenManager(
            $container->get(JwtAdapterInterface::class),
            $config->getInt('lifetime')
        );
    }
}
