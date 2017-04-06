<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Factory;

use CultuurNet\Clock\SystemClock;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Jwt\LcobucciAdapter;
use DASPRiD\TreeReader\TreeReader;
use DateTimeZone;
use Lcobucci\JWT\Parser;
use Psr\Container\ContainerInterface;

final class LcobucciAdapterFactory
{
    public function __invoke(ContainerInterface $container) : JwtAdapterInterface
    {
        $reader = new TreeReader($container->get('config'), 'config');
        $config = $reader->getChildren('csrf_guard')->getChildren('jwt');
        $signer = $config->getString('signer');

        return new LcobucciAdapter(
            new Parser(),
            new $signer(),
            $config->getString('signature_key'),
            $config->getString('verification_key'),
            new SystemClock(new DateTimeZone('UTC'))
        );
    }
}
