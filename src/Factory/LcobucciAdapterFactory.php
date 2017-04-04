<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard;

use CultuurNet\Clock\SystemClock;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use Lcobucci\JWT\Parser;
use Psr\Container\ContainerInterface;

final class LcobucciAdapterFactory
{
    public function __invoke(ContainerInterface $container) : JwtAdapterInterface
    {
        $config = $container->get('config')['csrf_guard']['jwt'];

        return new LcobucciAdapter(
            new Parser(),
            new $config['signer'](),
            $config['signature_key'],
            $config['verification_key'],
            new SystemClock()
        );
    }
}
