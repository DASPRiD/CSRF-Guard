<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\CsrfToken;

final class HmacCsrfTokenManager implements CsrfTokenManagerInterface
{
    /**
     * @var string
     */
    private $privateKey;

    public function __construct(string $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    public function generateToken(string $publicKey) : string
    {
        return hash_hmac('sha256', $publicKey, $this->privateKey);
    }

    public function verifyToken(string $token, string $publicKey) : bool
    {
        return $this->generateToken($publicKey) === $token;
    }
}
