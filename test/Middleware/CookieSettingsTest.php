<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Middleware;

use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use PHPUnit\Framework\TestCase;

final class CookieSettingsTest extends TestCase
{
    public function testGetters()
    {
        $settings = new CookieSettings('name', 'path', true, 1, 2);

        $this->assertSame('name', $settings->getName());
        $this->assertSame('path', $settings->getPath());
        $this->assertTrue($settings->getSecure());
        $this->assertSame(1, $settings->getLifetime());
        $this->assertSame(2, $settings->getRefreshTime());
    }
}
