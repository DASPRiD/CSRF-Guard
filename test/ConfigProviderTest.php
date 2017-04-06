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

        $this->assertArrayHasKey('factories', $dependencies);
        $factories = $dependencies['factories'];

        $this->assertArrayHasKey(JwtAdapterInterface::class, $factories);
        $this->assertTrue(class_exists($factories[JwtAdapterInterface::class]));

        $this->assertArrayHasKey(CsrfTokenManagerInterface::class, $factories);
        $this->assertTrue(class_exists($factories[CsrfTokenManagerInterface::class]));

        $this->assertArrayHasKey(CookieSettings::class, $factories);
        $this->assertTrue(class_exists($factories[CookieSettings::class]));

        $this->assertArrayHasKey(CsrfGuardMiddleware::class, $factories);
        $this->assertTrue(class_exists($factories[CsrfGuardMiddleware::class]));
    }
}
