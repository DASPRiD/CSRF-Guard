<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Jwt\Exception;

use DomainException;

final class InvalidTokenException extends DomainException implements ExceptionInterface
{
    public static function fromInvalidToken(string $token) : self
    {
        return new self(sprintf('Invalid token "%s" provided', $token));
    }
}
