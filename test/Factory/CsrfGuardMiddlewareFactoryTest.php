<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Factory;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Factory\CsrfGuardMiddlewareFactory;
use DASPRiD\CsrfGuard\Middleware\PublicKeyProviderInterface;
use DASPRiD\Pikkuleipa\CookieManagerInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class CsrfGuardMiddlewareFactoryTest extends TestCase
{
    public function testCreation() : void
    {
        $container = $this->prophesize(ContainerInterface::class);
        $container->get('config')->willReturn([
            'csrf_guard' => [
                'cookie_name' => 'csrf_guard',
                'token_attribute_name' => 'csrf_token',
                'request_token_name' => 'csrf_token',
                'failure_middleware' => 'fmw',
                'public_key_provider' => 'pkp',
            ],
        ]);

        $cookieManager = $this->prophesize(CookieManagerInterface::class)->reveal();
        $container->get(CookieManagerInterface::class)->willReturn($cookieManager);

        $csrfTokenManager = $this->prophesize(CsrfTokenManagerInterface::class)->reveal();
        $container->get(CsrfTokenManagerInterface::class)->willReturn($csrfTokenManager);

        $failureMiddleware = $this->prophesize(MiddlewareInterface::class)->reveal();
        $container->get('fmw')->willReturn($failureMiddleware);

        $publicKeyProvider = $this->prophesize(PublicKeyProviderInterface::class)->reveal();
        $container->get('pkp')->willReturn($publicKeyProvider);

        $middleware = (new CsrfGuardMiddlewareFactory())->__invoke($container->reveal());
        $this->assertAttributeSame('csrf_guard', 'cookieName', $middleware);
        $this->assertAttributeSame('csrf_token', 'tokenAttributeName', $middleware);
        $this->assertAttributeSame('csrf_token', 'requestTokenName', $middleware);
        $this->assertAttributeSame($cookieManager, 'cookieManager', $middleware);
        $this->assertAttributeSame($csrfTokenManager, 'csrfTokenManager', $middleware);
        $this->assertAttributeSame($failureMiddleware, 'failureMiddleware', $middleware);
        $this->assertAttributeSame($publicKeyProvider, 'publicKeyProvider', $middleware);
    }
}
