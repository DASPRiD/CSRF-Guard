<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Middleware;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;
use DASPRiD\CsrfGuard\Middleware\PublicKeyProviderInterface;
use DASPRiD\Pikkuleipa\Cookie;
use DASPRiD\Pikkuleipa\CookieManagerInterface;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\EmptyResponse;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Stream;

final class CsrfGuardMiddlewareTest extends TestCase
{
    public function testNewPublicKeyCookieIsSetWithoutPublicKeyProvider() : void
    {
        $response = $this->createCsrfGuardMiddleware(true, true)->process(
            $this->createServerRequest(),
            $this->createFinalHandler()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertRegExp('([a-z0-9]{64})', $response->getHeaderLine('cookie'));
    }

    public function testExistingPublicKeyCookieIsSetWithoutPublicKeyProvider() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(),
            $this->createFinalHandler()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('public_key', $response->getHeaderLine('cookie'));
    }

    public function testNewPublicKeyCookieIsSetWithPublicKeyProviderReturningNull() : void
    {
        $publicKeyProvider = $this->prophesize(PublicKeyProviderInterface::class);
        $publicKeyProvider->__invoke()->willReturn(null);

        $response = $this->createCsrfGuardMiddleware(true, true, $publicKeyProvider->reveal())->process(
            $this->createServerRequest(),
            $this->createFinalHandler()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertRegExp('([a-z0-9]{64})', $response->getHeaderLine('cookie'));
    }

    public function testNewPublicKeyCookieIsNotSetWithPublicKeyProviderReturningKey() : void
    {
        $publicKeyProvider = $this->prophesize(PublicKeyProviderInterface::class);
        $publicKeyProvider->__invoke()->willReturn('public_key');

        $response = $this->createCsrfGuardMiddleware(true, true, $publicKeyProvider->reveal())->process(
            $this->createServerRequest(),
            $this->createFinalHandler()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('cookie'));
    }

    public function testFailureMiddlewareIsCalledWithoutCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest([]),
            $this->createFinalHandler()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsCalledWithNonStringCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['csrf_token' => 1]),
            $this->createFinalHandler()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsCalledWithInvalidCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware(false)->process(
            $this->createServerRequest(['csrf_token' => 'csrf_token']),
            $this->createFinalHandler()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsNotCalledWithValidCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['csrf_token' => 'csrf_token']),
            $this->createFinalHandler()
        );
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testValidTokenFromJsonRequest() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['csrf_token' => 'csrf_token'], true),
            $this->createFinalHandler()
        );
        $this->assertSame(200, $response->getStatusCode());
    }

    public function excludePathProvider() : array
    {
        return [
            ['/foo', true],
            ['/foobar', true],
            ['/bar/foobar', false],
        ];
    }

    /**
     * @dataProvider excludePathProvider
     */
    public function testExcludePath(string $excludePath, bool $success) : void
    {
        $response = $this->createCsrfGuardMiddleware(false, false, null, $excludePath)->process(
            $this->createServerRequest(['csrf_token' => 'csrf_token']),
            $this->createFinalHandler(false)
        );

        $this->assertSame($success ? 200 : 400, $response->getStatusCode());
    }

    private function createCsrfGuardMiddleware(
        bool $validCsrfToken = true,
        bool $newPublicKey = false,
        ?PublicKeyProviderInterface $publicKeyProvider = null,
        ?string $excludePath = null
    ) : CsrfGuardMiddleware {
        $cookie = new Cookie('csrf_guard');

        if (! $newPublicKey) {
            $cookie->set('publicKey', 'public_key');
        }

        $cookieManager = $this->prophesize(CookieManagerInterface::class);
        $cookieManager->setCookie(Argument::any(), Argument::that(function (Cookie $cookie) use ($newPublicKey) : bool {
            if ($newPublicKey) {
                return 1 === preg_match('(^[a-z0-9]{64}$)', $cookie->get('publicKey'));
            }

            return 'public_key' === $cookie->get('publicKey');
        }))->will(function (array $arguments) {
            return $arguments[0]->withHeader('cookie', $arguments[1]->get('publicKey'));
        });
        $cookieManager->getCookie(Argument::any(), 'csrf_guard')->willReturn($cookie);

        $csrfTokenManager = $this->prophesize(CsrfTokenManagerInterface::class);
        $csrfTokenManager->generateToken(Argument::that(function (string $publicKey) : bool {
            return 1 === preg_match('(^[a-z0-9]{64}$)', $publicKey) || 'public_key' === $publicKey;
        }))->willReturn('csrf_token');
        $csrfTokenManager->verifyToken('csrf_token', 'public_key')->willReturn($validCsrfToken);

        $failureHandler = $this->prophesize(RequestHandlerInterface::class);
        $failureHandler->handle(Argument::that(function (ServerRequestInterface $request) : bool {
            return $request->getAttribute('csrf_token') === 'csrf_token';
        }))->willReturn(new EmptyResponse(400));

        return new CsrfGuardMiddleware(
            $cookieManager->reveal(),
            $csrfTokenManager->reveal(),
            $failureHandler->reveal(),
            'csrf_guard',
            'csrf_token',
            'csrf_token',
            $publicKeyProvider,
            null !== $excludePath ? [$excludePath] : []
        );
    }

    private function createServerRequest(array $postData = null, bool $json = false) : ServerRequestInterface
    {
        $body = 'php://memory';

        if ($json) {
            $body = new Stream('php://memory', 'w+');
            $body->write(json_encode($postData));
        }

        return new ServerRequest(
            [],
            [],
            '/foobar',
            null === $postData ? 'GET' : 'POST',
            $body,
            $json ? ['content-type' => 'application/json'] : [],
            [],
            [],
            $json ? null : $postData
        );
    }

    private function createFinalHandler(bool $expectToken = true) : RequestHandlerInterface
    {
        $handler = $this->prophesize(RequestHandlerInterface::class);
        $handler->handle(Argument::that(function (ServerRequestInterface $request) use ($expectToken) : bool {
            if ($expectToken) {
                return $request->getAttribute('csrf_token') === 'csrf_token';
            }

            return null === $request->getAttribute('csrf_token');
        }))->willReturn(new EmptyResponse(200));

        return $handler->reveal();
    }
}
