<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Jwt;

use CultuurNet\Clock\Clock;
use DASPRiD\CsrfGuard\Jwt\Exception\InvalidTokenException;
use InvalidArgumentException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

final class LcobucciAdapter implements JwtAdapterInterface
{
    /**
     * @var Parser
     */
    private $parser;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var string
     */
    private $signatureKey;

    /**
     * @var string
     */
    private $verificationKey;

    /**
     * @var Clock
     */
    private $clock;

    public function __construct(
        Parser $parser,
        Signer $signer,
        string $signatureKey,
        string $verificationKey,
        Clock $clock
    ) {
        $this->parser = $parser;
        $this->signer = $signer;
        $this->signatureKey = $signatureKey;
        $this->verificationKey = $verificationKey;
        $this->clock = $clock;
    }

    public function createToken(array $data, int $lifetime) : string
    {
        $currentTimestamp = $this->clock->getDateTime()->getTimestamp();

        $builder = new Builder();
        $builder->setIssuedAt($currentTimestamp);
        $builder->setExpiration($currentTimestamp + $lifetime);

        foreach ($data as $key => $value) {
            $builder->set($key, $value);
        }

        return (string) $builder->sign($this->signer, $this->signatureKey)->getToken();
    }

    public function validateToken(string $token) : bool
    {
        return null !== $this->getTokenInstance($token);
    }

    public function getClaims(string $token) : array
    {
        $tokenInstance = $this->getTokenInstance($token);

        if (null === $tokenInstance) {
            throw InvalidTokenException::fromInvalidToken($token);
        }

        $claims = [];

        foreach ($tokenInstance->getClaims() as $key => $claim) {
            $claims[$key] = $claim->getValue();
        }

        return $claims;
    }

    private function getTokenInstance(string $token) : ?Token
    {
        try {
            $tokenInstance = $this->parser->parse($token);
        } catch (InvalidArgumentException $e) {
            return null;
        }

        if (!$tokenInstance->validate(new ValidationData($this->clock->getDateTime()->getTimestamp()))) {
            return null;
        }

        if (!$tokenInstance->verify($this->signer, $this->verificationKey)) {
            return null;
        }

        return $tokenInstance;
    }
}
