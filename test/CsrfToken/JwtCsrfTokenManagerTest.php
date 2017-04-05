<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\CsrfToken;

use DASPRiD\CsrfGuard\CsrfToken\JwtCsrfTokenManager;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\UuidInterface;

final class JwtCsrfTokenManagerTest extends TestCase
{
    public function testGenerateToken()
    {
        $uuid = $this->prophesize(UuidInterface::class);
        $uuid->toString()->willReturn('foobar');

        $adapter = $this->prophesize(JwtAdapterInterface::class);
        $adapter->createToken(['uuid' => 'foobar'], 10)->willReturn('bazbat');

        $manager = new JwtCsrfTokenManager($adapter->reveal(), 10);
        $this->assertSame('bazbat', $manager->generateToken($uuid->reveal()));
    }

    public function testVerifyTokenWithInvalidToken()
    {
        $uuid = $this->prophesize(UuidInterface::class);
        $uuid->toString()->willReturn('foobar');

        $adapter = $this->prophesize(JwtAdapterInterface::class);
        $adapter->validateToken('bazbat')->willReturn(false);

        $manager = new JwtCsrfTokenManager($adapter->reveal(), 10);
        $this->assertFalse($manager->verifyToken('bazbat', $uuid->reveal()));
    }

    public function testVerifyTokenWithNonMatchingUuid()
    {
        $uuid = $this->prophesize(UuidInterface::class);
        $uuid->toString()->willReturn('foobar');

        $adapter = $this->prophesize(JwtAdapterInterface::class);
        $adapter->validateToken('bazbat')->willReturn(true);
        $adapter->getClaims('bazbat')->willReturn(['uuid' => 'nope']);

        $manager = new JwtCsrfTokenManager($adapter->reveal(), 10);
        $this->assertFalse($manager->verifyToken('bazbat', $uuid->reveal()));
    }

    public function testVerifyTokenWithMatchingUuid()
    {
        $uuid = $this->prophesize(UuidInterface::class);
        $uuid->toString()->willReturn('foobar');

        $adapter = $this->prophesize(JwtAdapterInterface::class);
        $adapter->validateToken('bazbat')->willReturn(true);
        $adapter->getClaims('bazbat')->willReturn(['uuid' => 'foobar']);

        $manager = new JwtCsrfTokenManager($adapter->reveal(), 10);
        $this->assertTrue($manager->verifyToken('bazbat', $uuid->reveal()));
    }
}
