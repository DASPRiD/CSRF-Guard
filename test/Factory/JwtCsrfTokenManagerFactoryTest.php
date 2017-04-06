<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Factory;

use DASPRiD\CsrfGuard\Factory\JwtCsrfTokenManagerFactory;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class JwtCsrfTokenManagerFactoryTest extends TestCase
{
    public function testCreation()
    {
        $container = $this->prophesize(ContainerInterface::class);
        $container->get('config')->willReturn([
            'csrf_guard' => [
                'csrf' => [
                    'lifetime' => 100,
                ],
            ],
        ]);

        $jwtAdapter = $this->prophesize(JwtAdapterInterface::class)->reveal();
        $container->get(JwtAdapterInterface::class)->willReturn($jwtAdapter);

        $tokenManager = (new JwtCsrfTokenManagerFactory())->__invoke($container->reveal());
        $this->assertAttributeSame($jwtAdapter, 'jwtAdapter', $tokenManager);
        $this->assertAttributeSame(100, 'lifetime', $tokenManager);
    }
}
