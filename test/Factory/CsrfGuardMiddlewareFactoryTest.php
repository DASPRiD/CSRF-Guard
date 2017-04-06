<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Factory;

use CultuurNet\Clock\SystemClock;
use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Factory\CsrfGuardMiddlewareFactory;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class CsrfGuardMiddlewareFactoryTest extends TestCase
{
    public function testCreation()
    {
        $container = $this->prophesize(ContainerInterface::class);
        $container->get('config')->willReturn([
            'csrf_guard' => [
                'middleware' => [
                    'uuid_attribute_name' => 'foo',
                    'token_post_name' => 'bar',
                    'failure_middleware' => 'fmw',
                ],
            ],
        ]);

        $cookieSettings = new CookieSettings('', '', false, 0, 0);
        $container->get(CookieSettings::class)->willReturn($cookieSettings);

        $csrfTokenManager = $this->prophesize(CsrfTokenManagerInterface::class)->reveal();
        $container->get(CsrfTokenManagerInterface::class)->willReturn($csrfTokenManager);

        $jwtAdapter = $this->prophesize(JwtAdapterInterface::class)->reveal();
        $container->get(JwtAdapterInterface::class)->willReturn($jwtAdapter);

        $failureMiddleware = $this->prophesize(MiddlewareInterface::class)->reveal();
        $container->get('fmw')->willReturn($failureMiddleware);

        $middleware = (new CsrfGuardMiddlewareFactory())->__invoke($container->reveal());
        $this->assertAttributeSame('foo', 'uuidAttributeName', $middleware);
        $this->assertAttributeSame('bar', 'tokenPostName', $middleware);
        $this->assertAttributeSame($jwtAdapter, 'jwtAdapter', $middleware);
        $this->assertAttributeSame($csrfTokenManager, 'csrfTokenManager', $middleware);
        $this->assertAttributeInstanceOf(SystemClock::class, 'clock', $middleware);
        $this->assertAttributeSame($failureMiddleware, 'failureMiddleware', $middleware);
    }
}
