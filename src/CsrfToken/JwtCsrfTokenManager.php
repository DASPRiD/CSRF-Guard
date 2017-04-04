<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\CsrfToken;

use DASPRiD\CsrfGuard\Jwt\JwtAdapterInterface;
use Ramsey\Uuid\UuidInterface;

final class JwtCsrfTokenManager implements CsrfTokenManagerInterface
{
    /**
     * @var JwtAdapterInterface
     */
    private $jwtAdapter;

    /**
     * @var int
     */
    private $lifetime;

    public function __construct(JwtAdapterInterface $jwtAdapter, int $lifetime)
    {
        $this->jwtAdapter = $jwtAdapter;
        $this->lifetime = $lifetime;
    }

    public function generateToken(UuidInterface $uuid) : string
    {
        return $this->jwtAdapter->createToken(['uuid' => $uuid->toString()], $this->lifetime);
    }

    public function verifyToken(string $token, UuidInterface $uuid) : bool
    {
        if (!$this->jwtAdapter->validateToken($token)) {
            return false;
        }

        return $this->jwtAdapter->getClaims($token)['uuid'] === $uuid->toString();
    }
}
