<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Factory;

use DASPRiD\CsrfGuard\Factory\CookieSettingsFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class CookieSettingsFactoryTest extends TestCase
{
    public function testCreation()
    {
        $container = $this->prophesize(ContainerInterface::class);
        $container->get('config')->willReturn([
            'csrf_guard' => [
                'cookie' => [
                    'name' => 'foo',
                    'path' => '/bar',
                    'secure' => true,
                    'lifetime' => 100,
                    'refresh_time' => 10,
                ],
            ],
        ]);

        $cookieSettings = (new CookieSettingsFactory())->__invoke($container->reveal());
        $this->assertSame('foo', $cookieSettings->getName());
        $this->assertSame('/bar', $cookieSettings->getPath());
        $this->assertTrue($cookieSettings->getSecure());
        $this->assertSame(100, $cookieSettings->getLifetime());
        $this->assertSame(10, $cookieSettings->getRefreshTime());
    }
}
