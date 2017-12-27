<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Middleware;

interface PublicKeyProviderInterface
{
    /**
     * Returns a public key based on session information or null, if no user session is available.
     *
     * If null is returned, the `CsrfGuardMiddleware` will generate a public key on its own and store it in a cookie.
     */
    public function __invoke() : ?string;
}
