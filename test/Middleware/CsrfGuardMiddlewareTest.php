<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Middleware;

use CultuurNet\Clock\FrozenClock;
use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use DASPRiD\CsrfGuard\Middleware\CookieSettings;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;
use DateTimeImmutable;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Zend\Diactoros\Response\EmptyResponse;
use Zend\Diactoros\ServerRequest;

final class CsrfGuardMiddlewareTest extends TestCase
{
    public function testNewUuidCookieIsSetIfCookieIsNotPresent()
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(null, false),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSetCookieHeader($response);
    }

    public function testNewUuidCookieIsSetIfCookieContainsInvalidToken()
    {
        $response = $this->createCsrfGuardMiddleware(false)->process(
            $this->createServerRequest(),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSetCookieHeader($response);
    }

    public function testNewUuidCookieIsSetAfterRefreshTime()
    {
        $response = $this->createCsrfGuardMiddleware(true, true)->process(
            $this->createServerRequest(),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSetCookieHeader($response);
    }

    public function testNewUuidCookieIsNotSetBeforeRefreshTime()
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Set-Cookie'));
    }

    public function testFailureMiddlewareIsCalledWithoutCsrfToken()
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest([]),
            $this->createDelegate()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsCalledWithNonStringCsrfToken()
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['test_csrf_token' => 1]),
            $this->createDelegate()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsCalledWithInvalidCsrfToken()
    {
        $response = $this->createCsrfGuardMiddleware(true, false, false)->process(
            $this->createServerRequest(['test_csrf_token' => 'csrf_token_value']),
            $this->createDelegate()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsNotCalledWithValidCsrfToken()
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['test_csrf_token' => 'csrf_token_value']),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
    }

    private function createCsrfGuardMiddleware(
        bool $validUuidToken = true,
        bool $expiredUuidToken = false,
        bool $validCsrfToken = true
    ) : CsrfGuardMiddleware {
        $jwtAdapter = $this->prophesize(JwtAdapterInterface::class);
        $jwtAdapter->createToken(Argument::that(function (array $claims) : bool {
            if (!array_key_exists('uuid', $claims)) {
                return false;
            }

            try {
                Uuid::fromString($claims['uuid']);
            } catch (InvalidArgumentException $e) {
                return false;
            }

            return true;
        }), 100)->willReturn('jwt_token');

        $jwtAdapter->validateToken('foobar')->willReturn($validUuidToken);
        $jwtAdapter->getClaims('foobar')->willReturn([
            'iat' => (
                new DateTimeImmutable(sprintf('201%d-01-01 00:00:00 UTC', $expiredUuidToken ? 6 : 8))
            )->getTimestamp(),
            'uuid' => '5ab45c38-ea1b-4e9f-9a8e-00898a4d262f',
        ]);

        $csrfTokenManager = $this->prophesize(CsrfTokenManagerInterface::class);
        $csrfTokenManager->verifyToken('csrf_token_value', Argument::that(function (UuidInterface $uuid) : bool {
            return $uuid->toString() === '5ab45c38-ea1b-4e9f-9a8e-00898a4d262f';
        }))->willReturn($validCsrfToken);

        $failureMiddleware = $this->prophesize(MiddlewareInterface::class);
        $failureMiddleware->process(Argument::that(function (ServerRequestInterface $request) : bool {
            return $request->getAttribute('test_uuid') instanceof UuidInterface;
        }), Argument::type(DelegateInterface::class))->willReturn(new EmptyResponse(400));

        return new CsrfGuardMiddleware(
            new CookieSettings('test_uuid', '/test', false, 100, 10),
            'test_uuid',
            'test_csrf_token',
            $jwtAdapter->reveal(),
            $csrfTokenManager->reveal(),
            new FrozenClock(new DateTimeImmutable('2017-01-01 00:00:00 UTC')),
            $failureMiddleware->reveal()
        );
    }

    private function createServerRequest(array $postData = null, bool $setCookie = true) : ServerRequestInterface
    {
        return new ServerRequest(
            [],
            [],
            null,
            null === $postData ? 'GET' : 'POST',
            'php://input',
            $setCookie ? ['Cookie' => 'test_uuid=foobar'] : [],
            $setCookie ? ['test_uuid' => 'foobar'] : [],
            [],
            $postData
        );
    }

    private function createDelegate() : DelegateInterface
    {
        $delegate = $this->prophesize(DelegateInterface::class);
        $delegate->process(Argument::that(function (ServerRequestInterface $request) : bool {
            return $request->getAttribute('test_uuid') instanceof UuidInterface;
        }))->willReturn(new EmptyResponse(200));

        return $delegate->reveal();
    }

    private function assertSetCookieHeader(ResponseInterface $response)
    {
        $this->assertSame(
            'test_uuid=jwt_token; Path=/test; Expires=Sun, 01 Jan 2017 00:01:40 GMT; HttpOnly',
            $response->getHeaderLine('Set-Cookie')
        );
    }
}
