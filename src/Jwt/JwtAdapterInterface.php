<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Jwt;

interface JwtAdapterInterface
{
    public function createToken(array $data, int $lifetime) : string;

    public function validateToken(string $token) : bool;

    public function getClaims(string $token) : array;
}
