<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Factory;

use DASPRiD\CsrfGuard\Factory\HmacCsrfTokenManagerFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class HmacCsrfTokenManagerFactoryTest extends TestCase
{
    public function testCreation() : void
    {
        $container = $this->prophesize(ContainerInterface::class);
        $container->get('config')->willReturn([
            'csrf_guard' => [
                'private_key' => 'foo',
            ],
        ]);

        $tokenManager = (new HmacCsrfTokenManagerFactory())->__invoke($container->reveal());
        $this->assertAttributeSame('foo', 'privateKey', $tokenManager);
    }
}
