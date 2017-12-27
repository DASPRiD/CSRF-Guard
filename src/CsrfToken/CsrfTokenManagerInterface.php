<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\CsrfToken;

interface CsrfTokenManagerInterface
{
    public function generateToken(string $publicKey) : string;

    public function verifyToken(string $token, string $publicKey) : bool;
}
