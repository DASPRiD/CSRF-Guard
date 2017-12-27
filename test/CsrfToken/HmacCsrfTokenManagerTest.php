<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\CsrfToken;

use DASPRiD\CsrfGuard\CsrfToken\HmacCsrfTokenManager;
use PHPUnit\Framework\TestCase;

final class HmacCsrfTokenManagerTest extends TestCase
{
    public function testGenerateToken() : void
    {
        $manager = new HmacCsrfTokenManager('foo');
        $this->assertSame(
            'f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317',
            $manager->generateToken('bar')
        );
    }

    public function testVerifyTokenWithInvalidToken() : void
    {
        $manager = new HmacCsrfTokenManager('foo');
        $this->assertFalse(
            $manager->verifyToken(
                'f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317',
                'baz'
            )
        );
    }

    public function testVerifyTokenWithValidToken() : void
    {
        $manager = new HmacCsrfTokenManager('foo');
        $this->assertTrue(
            $manager->verifyToken(
                'f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317',
                'bar'
            )
        );
    }
}
