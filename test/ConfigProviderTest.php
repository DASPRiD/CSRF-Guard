<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest;

use DASPRiD\CsrfGuard\ConfigProvider;
use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;
use PHPUnit\Framework\TestCase;

final class ConfigProviderTest extends TestCase
{
    public function testInvoke()
    {
        $provider = new ConfigProvider();
        $config = $provider();

        $this->assertArrayHasKey('dependencies', $config);
        $dependencies = $config['dependencies'];

        $this->assertArrayHasKey(JwtAdapterInterface::class, $dependencies);
        $this->assertTrue(class_exists($dependencies[JwtAdapterInterface::class]));

        $this->assertArrayHasKey(CsrfTokenManagerInterface::class, $dependencies);
        $this->assertTrue(class_exists($dependencies[CsrfTokenManagerInterface::class]));

        $this->assertArrayHasKey(CookieSettings::class, $dependencies);
        $this->assertTrue(class_exists($dependencies[CookieSettings::class]));

        $this->assertArrayHasKey(CsrfGuardMiddleware::class, $dependencies);
        $this->assertTrue(class_exists($dependencies[CsrfGuardMiddleware::class]));
    }
}
