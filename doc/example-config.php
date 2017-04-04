<?php
return [
    'csrf_guard' => [
        'cookie' => [
            'name' => 'csrf-uuid',
            'path' => '/',
            'secure' => false,
            'lifetime' => 3600 * 24,
            'refresh_time' => 3600,
        ],
        'csrf' => [
            'lifetime' => 3600,
        ],
        'jwt' => [
            'signer' => Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'signature_key' => 'foobar',
            'verification_key' => 'foobar',
        ],
        'middleware' => [
            'uuid_attribute_name' => 'csrf_uuid',
            'token_post_name' => 'csrf_token',
            'failure_middleware' => Some\Csrf\FailureMiddleware::class,
        ],
    ],
];
