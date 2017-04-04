<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\CsrfToken;

use Ramsey\Uuid\UuidInterface;

interface CsrfTokenManagerInterface
{
    public function generateToken(UuidInterface $uuid) : string;

    public function verifyToken(string $serializedToken, UuidInterface $uuid) : bool;
}
