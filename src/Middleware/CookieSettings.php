<?php
declare(strict_types = 1);

namespace DASPRiD\CsrfGuard\Middleware;

final class CookieSettings
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $path;

    /**
     * @var bool
     */
    private $secure;

    /**
     * @var int
     */
    private $lifetime;

    /**
     * @var int
     */
    private $refreshTime;

    public function __construct(string $name, string $path, bool $secure, int $lifetime, int $refreshTime)
    {
        $this->name = $name;
        $this->path = $path;
        $this->secure = $secure;
        $this->lifetime = $lifetime;
        $this->refreshTime = $refreshTime;
    }

    public function getName() : string
    {
        return $this->name;
    }

    public function getPath() : string
    {
        return $this->path;
    }

    public function getSecure() : bool
    {
        return $this->secure;
    }

    public function getLifetime() : int
    {
        return $this->lifetime;
    }

    public function getRefreshTime() : int
    {
        return $this->refreshTime;
    }
}
