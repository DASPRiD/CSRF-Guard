<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuardTest\Middleware;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Middleware\CsrfGuardMiddleware;
use DASPRiD\CsrfGuard\Middleware\PublicKeyProviderInterface;
use DASPRiD\Pikkuleipa\Cookie;
use DASPRiD\Pikkuleipa\CookieManagerInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\EmptyResponse;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Stream;

final class CsrfGuardMiddlewareTest extends TestCase
{
    public function testNewPublicKeyCookieIsSetWithoutPublicKeyProvider() : void
    {
        $response = $this->createCsrfGuardMiddleware(true, true)->process(
            $this->createServerRequest(),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertRegExp('([a-z0-9]{64})', $response->getHeaderLine('cookie'));
    }

    public function testExistingPublicKeyCookieIsSetWithoutPublicKeyProvider() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(),
            $this->createDelegate()
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
            $this->createDelegate()
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
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('cookie'));
    }

    public function testFailureMiddlewareIsCalledWithoutCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest([]),
            $this->createDelegate()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsCalledWithNonStringCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['csrf_token' => 1]),
            $this->createDelegate()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsCalledWithInvalidCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware(false)->process(
            $this->createServerRequest(['csrf_token' => 'csrf_token']),
            $this->createDelegate()
        );
        $this->assertSame(400, $response->getStatusCode());
    }

    public function testFailureMiddlewareIsNotCalledWithValidCsrfToken() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['csrf_token' => 'csrf_token']),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testValidTokenFromJsonRequest() : void
    {
        $response = $this->createCsrfGuardMiddleware()->process(
            $this->createServerRequest(['csrf_token' => 'csrf_token'], true),
            $this->createDelegate()
        );
        $this->assertSame(200, $response->getStatusCode());
    }

    private function createCsrfGuardMiddleware(
        bool $validCsrfToken = true,
        bool $newPublicKey = false,
        ?PublicKeyProviderInterface $publicKeyProvider = null
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

        $failureMiddleware = $this->prophesize(MiddlewareInterface::class);
        $failureMiddleware->process(Argument::that(function (ServerRequestInterface $request) : bool {
            return $request->getAttribute('csrf_token') === 'csrf_token';
        }), Argument::type(DelegateInterface::class))->willReturn(new EmptyResponse(400));

        return new CsrfGuardMiddleware(
            $cookieManager->reveal(),
            $csrfTokenManager->reveal(),
            $failureMiddleware->reveal(),
            'csrf_guard',
            'csrf_token',
            'csrf_token',
            $publicKeyProvider
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
            null,
            null === $postData ? 'GET' : 'POST',
            $body,
            $json ? ['content-type' => 'application/json'] : [],
            [],
            [],
            $json ? null : $postData
        );
    }

    private function createDelegate() : DelegateInterface
    {
        $delegate = $this->prophesize(DelegateInterface::class);
        $delegate->process(Argument::that(function (ServerRequestInterface $request) : bool {
            return $request->getAttribute('csrf_token') === 'csrf_token';
        }))->willReturn(new EmptyResponse(200));

        return $delegate->reveal();
    }
}
