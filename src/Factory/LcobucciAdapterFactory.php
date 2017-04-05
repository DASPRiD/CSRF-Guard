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
        $reader = new TreeReader($container->get('config'));
        $config = $reader->getChildren('csrf_guard')->getChildren('csrf');
        $signer = $config->getString('signer');

        return new LcobucciAdapter(
            new Parser(),
            new $signer(),
            $config->getString('signature_key'),
            $config->getString('verification_key'),
            new SystemClock()
        );
    }
}
