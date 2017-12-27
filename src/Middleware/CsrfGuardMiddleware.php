<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Middleware;

use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\Pikkuleipa\Cookie;
use DASPRiD\Pikkuleipa\CookieManagerInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CsrfGuardMiddleware implements MiddlewareInterface
{
    /**
     * @var CookieManagerInterface
     */
    private $cookieManager;

    /**
     * @var CsrfTokenManagerInterface
     */
    private $csrfTokenManager;

    /**
     * @var MiddlewareInterface
     */
    private $failureMiddleware;

    /**
     * @var string
     */
    private $cookieName;

    /**
     * @var string
     */
    private $tokenAttributeName;

    /**
     * @var string
     */
    private $requestTokenName;

    /**
     * @var PublicKeyProviderInterface|null
     */
    private $publicKeyProvider;

    public function __construct(
        CookieManagerInterface $cookieManager,
        CsrfTokenManagerInterface $csrfTokenManager,
        MiddlewareInterface $failureMiddleware,
        string $cookieName,
        string $tokenAttributeName,
        string $requestTokenName,
        ?PublicKeyProviderInterface $publicKeyProvider = null
    ) {
        $this->cookieManager = $cookieManager;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->failureMiddleware = $failureMiddleware;
        $this->cookieName = $cookieName;
        $this->tokenAttributeName = $tokenAttributeName;
        $this->requestTokenName = $requestTokenName;
        $this->publicKeyProvider = $publicKeyProvider;
    }

    public function process(ServerRequestInterface $request, DelegateInterface $delegate) : ResponseInterface
    {
        $publicKey = null;
        $providerKeyUsed = true;

        if (null !== $this->publicKeyProvider) {
            $publicKey = $this->publicKeyProvider->__invoke();
        }

        if (null === $publicKey) {
            $providerKeyUsed = false;
            $cookie = $this->cookieManager->getCookie($request, $this->cookieName);
            $publicKey = $cookie->get('publicKey');

            if (! is_string($publicKey)) {
                $publicKey = bin2hex(random_bytes(32));
            }
        }

        $token = $this->csrfTokenManager->generateToken($publicKey);
        $requestWithToken = $request->withAttribute($this->tokenAttributeName, $token);

        if (! in_array($request->getMethod(), ['POST', 'PUT', 'DELETE'])) {
            return $this->decorateResponse(
                $delegate->process($requestWithToken),
                $publicKey,
                $providerKeyUsed
            );
        }

        $requestToken = null;

        if ('application/json' === $request->getHeaderLine('content-type')) {
            $data = json_decode((string) $request->getBody(), true);

            if (is_array($data) && is_string($data[$this->requestTokenName] ?? null)) {
                $requestToken = $data[$this->requestTokenName];
            }
        } else {
            $data = $request->getParsedBody();

            if (is_array($data) && is_string($data[$this->requestTokenName] ?? null)) {
                $requestToken = $data[$this->requestTokenName];
            }
        }

        if (! is_string($requestToken) || ! $this->csrfTokenManager->verifyToken($requestToken, $publicKey)) {
            return $this->decorateResponse(
                $this->failureMiddleware->process($requestWithToken, $delegate),
                $publicKey,
                $providerKeyUsed
            );
        }

        return $this->decorateResponse(
            $delegate->process($requestWithToken),
            $publicKey,
            $providerKeyUsed
        );
    }

    private function decorateResponse(
        ResponseInterface $response,
        string $publicKey,
        bool $providerKeyUsed
    ) : ResponseInterface {
        if ($providerKeyUsed) {
            return $response;
        }

        $cookie = new Cookie($this->cookieName);
        $cookie->set('publicKey', $publicKey);

        return $this->cookieManager->setCookie($response, $cookie);
    }
}
