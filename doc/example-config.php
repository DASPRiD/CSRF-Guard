<?php
return [
    'pikkuleipa' => [
        'cookie_settings' => [
            'csrf_guard' => [
                'path' => '/',
                'secure' => false,
                'lifetime' => 2592000,
            ],
        ],
    ],
    'csrf_guard' => [
        'private_key' => 'some_private_key',
        'cookie_name' => 'csrf_guard',
        'token_attribute_name' => 'csrf_token',
        'request_token_name' => 'csrf_token',
        'failure_handler' => Some\Csrf\FailureMiddleware::class,
        'public_key_provider' => Some\PublicKey\Provider::class, // or null
    ],
];
