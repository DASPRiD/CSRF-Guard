<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Jwt;

use CultuurNet\Clock\FrozenClock;
use DASPRiD\CsrfGuard\Jwt\Exception\InvalidTokenException;
use DASPRiD\CsrfGuard\Jwt\LcobucciAdapter;
use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\JWT\Claim\GreaterOrEqualsTo;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;

final class LcobucciAdapterTest extends TestCase
{
    public function testCreateToken()
    {
        $parser = $this->prophesize(Parser::class);

        $signer = $this->prophesize(Signer::class);
        $signer->modifyHeader(Argument::any())->willReturn();
        $signer->sign(Argument::any(), 'foo')->willReturn(new Signature('foo_signature'));

        $dateTime = new DateTimeImmutable('2017-01-01 00:00:00 UTC');

        $adapter = new LcobucciAdapter(
            $parser->reveal(),
            $signer->reveal(),
            'foo',
            'bar',
            new FrozenClock($dateTime)
        );

        $tokenData = explode('.', $adapter->createToken(['baz' => 'bat'], 10));
        $this->assertCount(3, $tokenData);

        $this->assertSame('foo_signature', base64_decode($tokenData[2]));
        $claims = json_decode(base64_decode($tokenData[1]), true);

        $this->assertArrayHasKey('iat', $claims);
        $this->assertSame($dateTime->getTimestamp(), $claims['iat']);

        $this->assertArrayHasKey('exp', $claims);
        $this->assertSame($dateTime->getTimestamp() + 10, $claims['exp']);

        $this->assertArrayHasKey('baz', $claims);
        $this->assertSame('bat', $claims['baz']);
    }

    public function testValidateTokenWithInvalidToken()
    {
        $parser = $this->prophesize(Parser::class);
        $parser->parse('foobar')->willThrow(new InvalidArgumentException());

        $signer = $this->prophesize(Signer::class);

        $adapter = new LcobucciAdapter(
            $parser->reveal(),
            $signer->reveal(),
            'foo',
            'bar',
            new FrozenClock(new DateTimeImmutable('2017-01-01 00:00:00 UTC'))
        );

        $this->assertFalse($adapter->validateToken('foobar'));
    }

    public function testValidateTokenWithExpiredToken()
    {
        $parser = $this->prophesize(Parser::class);
        $parser->parse('foobar')->willReturn(new Token(
            ['typ' => 'JWT', 'alg' => 'cst'],
            [
                'exp' => new GreaterOrEqualsTo(
                    'exp',
                    (new DateTimeImmutable('2016-01-01 00:00:00 UTC'))->getTimestamp()
                ),
            ],
            new Signature('foo_signature')
        ));

        $signer = $this->prophesize(Signer::class);
        $signer->getAlgorithmId()->willReturn('cst');
        $signer->verify('foo_signature', Argument::any(), 'bar')->willReturn(true);

        $adapter = new LcobucciAdapter(
            $parser->reveal(),
            $signer->reveal(),
            'foo',
            'bar',
            new FrozenClock(new DateTimeImmutable('2017-01-01 00:00:00 UTC'))
        );

        $this->assertFalse($adapter->validateToken('foobar'));
    }

    public function testValidateTokenWithInvalidSignature()
    {
        $parser = $this->prophesize(Parser::class);
        $parser->parse('foobar')->willReturn(new Token(
            ['typ' => 'JWT', 'alg' => 'cst'],
            [
                'exp' => new GreaterOrEqualsTo(
                    'exp',
                    (new DateTimeImmutable('2018-01-01 00:00:00 UTC'))->getTimestamp()
                ),
            ],
            new Signature('foo_signature')
        ));

        $signer = $this->prophesize(Signer::class);
        $signer->getAlgorithmId()->willReturn('cst');
        $signer->verify('foo_signature', Argument::any(), 'bar')->willReturn(false);

        $adapter = new LcobucciAdapter(
            $parser->reveal(),
            $signer->reveal(),
            'foo',
            'bar',
            new FrozenClock(new DateTimeImmutable('2017-01-01 00:00:00 UTC'))
        );

        $this->assertFalse($adapter->validateToken('foobar'));
    }

    public function testValidateTokenWithValidToken()
    {
        $parser = $this->prophesize(Parser::class);
        $parser->parse('foobar')->willReturn(new Token(
            ['typ' => 'JWT', 'alg' => 'cst'],
            [
                'exp' => new GreaterOrEqualsTo(
                    'exp',
                    (new DateTimeImmutable('2018-01-01 00:00:00 UTC'))->getTimestamp()
                ),
            ],
            new Signature('foo_signature')
        ));

        $signer = $this->prophesize(Signer::class);
        $signer->getAlgorithmId()->willReturn('cst');
        $signer->verify('foo_signature', Argument::any(), 'bar')->willReturn(true);

        $adapter = new LcobucciAdapter(
            $parser->reveal(),
            $signer->reveal(),
            'foo',
            'bar',
            new FrozenClock(new DateTimeImmutable('2017-01-01 00:00:00 UTC'))
        );

        $this->assertTrue($adapter->validateToken('foobar'));
    }

    public function testGetClaimsWithInvalidToken()
    {
        $parser = $this->prophesize(Parser::class);
        $parser->parse('foobar')->willThrow(new InvalidArgumentException());

        $signer = $this->prophesize(Signer::class);

        $adapter = new LcobucciAdapter(
            $parser->reveal(),
            $signer->reveal(),
            'foo',
            'bar',
            new FrozenClock(new DateTimeImmutable('2017-01-01 00:00:00 UTC'))
        );

        $this->expectException(InvalidTokenException::class);
        $adapter->getClaims('foobar');
    }

    public function testGetClaimsWithValidToken()
    {
        $parser = $this->prophesize(Parser::class);
        $parser->parse('foobar')->willReturn(new Token(
            ['typ' => 'JWT', 'alg' => 'cst'],
            [
                'exp' => new GreaterOrEqualsTo(
                    'exp',
                    (new DateTimeImmutable('2018-01-01 00:00:00 UTC'))->getTimestamp()
                ),
                'baz' => 'bat',
            ],
            new Signature('foo_signature')
        ));

        $signer = $this->prophesize(Signer::class);
        $signer->getAlgorithmId()->willReturn('cst');
        $signer->verify('foo_signature', Argument::any(), 'bar')->willReturn(true);

        $adapter = new LcobucciAdapter(
            $parser->reveal(),
            $signer->reveal(),
            'foo',
            'bar',
            new FrozenClock(new DateTimeImmutable('2017-01-01 00:00:00 UTC'))
        );

        $claims = $adapter->getClaims('foobar');
        $this->assertArrayHasKey('baz', $claims);
        $this->assertSame('bat', $claims['baz']);
    }
}
