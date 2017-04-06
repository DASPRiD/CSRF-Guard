<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Middleware;

use CultuurNet\Clock\Clock;
use DASPRiD\CsrfGuard\CsrfToken\CsrfTokenManagerInterface;
use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use Dflydev\FigCookies\FigRequestCookies;
use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\SetCookie;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;

final class CsrfGuardMiddleware implements MiddlewareInterface
{
    /**
     * @var CookieSettings
     */
    private $cookieSettings;

    /**
     * @var string
     */
    private $uuidAttributeName;

    /**
     * @var string
     */
    private $tokenPostName;

    /**
     * @var JwtAdapterInterface
     */
    private $jwtAdapter;

    /**
     * @var CsrfTokenManagerInterface
     */
    private $csrfTokenManager;

    /**
     * @var Clock
     */
    private $clock;

    /**
     * @var MiddlewareInterface
     */
    private $failureMiddleware;

    public function __construct(
        CookieSettings $cookieSettings,
        string $uuidAttributeName,
        string $tokenPostName,
        JwtAdapterInterface $jwtAdapter,
        CsrfTokenManagerInterface $csrfTokenManager,
        Clock $clock,
        MiddlewareInterface $failureMiddleware
    ) {
        $this->cookieSettings = $cookieSettings;
        $this->uuidAttributeName = $uuidAttributeName;
        $this->tokenPostName = $tokenPostName;
        $this->jwtAdapter = $jwtAdapter;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->clock = $clock;
        $this->failureMiddleware = $failureMiddleware;
    }

    public function process(ServerRequestInterface $request, DelegateInterface $delegate) : ResponseInterface
    {
        $requestCookie = FigRequestCookies::get($request, $this->cookieSettings->getName());
        $uuidToken = $requestCookie->getValue($this->cookieSettings->getName());
        $setCookie = false;

        if (is_string($uuidToken) && $this->jwtAdapter->validateToken($uuidToken)) {
            $claims = $this->jwtAdapter->getClaims($uuidToken);
            $uuid = Uuid::fromString($claims['uuid']);

            if ($claims['iat'] + $this->cookieSettings->getRefreshTime()
                < $this->clock->getDateTime()->getTimestamp()
            ) {
                $setCookie = true;
            }
        } else {
            $uuid = Uuid::uuid4();
            $setCookie = true;
        }

        $requestWithUuid = $request->withAttribute($this->uuidAttributeName, $uuid);

        if ('POST' !== $request->getMethod()) {
            return $this->decorateResponse(
                $delegate->process($requestWithUuid),
                $uuid,
                $setCookie
            );
        }

        $postData = $request->getParsedBody();

        if (!array_key_exists($this->tokenPostName, $postData)
            || !is_string($postData[$this->tokenPostName])
            || !$this->csrfTokenManager->verifyToken($postData[$this->tokenPostName], $uuid)
        ) {
            return $this->decorateResponse(
                $this->failureMiddleware->process($requestWithUuid, $delegate),
                $uuid,
                $setCookie
            );
        }

        return $this->decorateResponse($delegate->process($requestWithUuid), $uuid, $setCookie);
    }

    private function decorateResponse(
        ResponseInterface $response,
        UuidInterface $uuid,
        bool $setCookie
    ) : ResponseInterface {
        if (!$setCookie) {
            return $response;
        }

        $token = $this->jwtAdapter->createToken(['uuid' => $uuid->toString()], $this->cookieSettings->getLifetime());

        $responseCookie = SetCookie::create($this->cookieSettings->getName())
            ->withPath($this->cookieSettings->getPath())
            ->withSecure($this->cookieSettings->getSecure())
            ->withHttpOnly(true)
            ->withValue($token)
            ->withExpires($this->clock->getDateTime()->getTimestamp() + $this->cookieSettings->getLifetime())
        ;

        return FigResponseCookies::set(
            $response,
            $responseCookie
        );
    }
}
