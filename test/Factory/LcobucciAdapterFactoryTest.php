<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Factory;

use CultuurNet\Clock\SystemClock;
use DASPRiD\CsrfGuard\Factory\LcobucciAdapterFactory;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class LcobucciAdapterFactoryTest extends TestCase
{
    public function testCreation()
    {
        $container = $this->prophesize(ContainerInterface::class);
        $container->get('config')->willReturn([
            'csrf_guard' => [
                'jwt' => [
                    'signer' => Sha256::class,
                    'signature_key' => 'foo',
                    'verification_key' => 'bar',
                ],
            ],
        ]);

        $adpater = (new LcobucciAdapterFactory())->__invoke($container->reveal());
        $this->assertAttributeInstanceOf(Parser::class, 'parser', $adpater);
        $this->assertAttributeInstanceOf(Sha256::class, 'signer', $adpater);
        $this->assertAttributeSame('foo', 'signatureKey', $adpater);
        $this->assertAttributeSame('bar', 'verificationKey', $adpater);
        $this->assertAttributeInstanceOf(SystemClock::class, 'clock', $adpater);
    }
}
