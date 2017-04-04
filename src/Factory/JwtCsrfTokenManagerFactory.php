<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\CsrfToken\JwtCsrfTokenManager;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use Psr\Container\ContainerInterface;

final class JwtCsrfTokenManagerFactory
{
    public function __invoke(ContainerInterface $container) : CsrfTokenManagerInterface
    {
        $config = $container->get('config')['csrf_guard']['csrf'];

        return new JwtCsrfTokenManager(
            $container->get(JwtAdapterInterface::class),
            $config['lifetime']
        );
    }
}
