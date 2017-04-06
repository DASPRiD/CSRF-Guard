# CSRF Guard

[![Build Status](https://travis-ci.org/DASPRiD/CSRF-Guard.svg?branch=master)](https://travis-ci.org/DASPRiD/CSRF-Guard)
[![Coverage Status](https://coveralls.io/repos/github/DASPRiD/CSRF-Guard/badge.svg?branch=master)](https://coveralls.io/github/DASPRiD/CSRF-Guard?branch=master)
[![Latest Stable Version](https://poser.pugx.org/dasprid/csrf-guard/v/stable)](https://packagist.org/packages/dasprid/csrf-guard)
[![Total Downloads](https://poser.pugx.org/dasprid/csrf-guard/downloads)](https://packagist.org/packages/dasprid/csrf-guard)
[![License](https://poser.pugx.org/dasprid/csrf-guard/license)](https://packagist.org/packages/dasprid/csrf-guard)

CSRF Guard is a library which helps to protect against CSRF attacks.

## Installation

Install via composer:

```bash
$ composer require dasprid/csrf-guard
```

## Usage

CSRF Guard is usable with any library implementing the interop middleware or PSR-15 standard. It comes with some
pre-defined factories which utilize the PSR-11 container standard and a config provider which can be used with container
implementations like Zend\ServiceManager. If you are using that or a similar containerimplementation together with
Zend\Expressive, you can register your factories by simply having an autoloaded config file looking like this:

```php
<?php
return (new DASPRiD\CsrfGuard\ConfigProvider())->__invoke();
```

Alternatively, you can register the factories manually in your container. After that, you need to have a `config` entry
in your container, which should return a config array. Again, when using Zend\Expressive, it should be enough to copy
the `example-config.php` file from the `doc` directory to your autoload folder.

The config example contains some sane defaults, yet you need to adjust at least the `signature_key` and
`verification_key` in the `jwt` section. For the `Hmac` algorithm, those two values must be the same. You must also
adjust the `failure_middleware` in the `middleware` section to point to a container key containing the middleware
responsible for creating a response when the CSRF validation fails. That middleware could, for instance, display an
error page or redirect the user somewhere else.

Finally, you need to add an CSRF token to every `POST` request you are sending to the server. When you have all
factories registered, you can access the CSRF token manager via the
`DASPRiD\CsrfGuard\CsrfToken\JwtCsrfTokenManager::class` key. The token manager has a method
```generateToken($uuid)```, which takes the UUID which you can find as attribute in the server request object. If you
haven't adjusted the config, it will be available through the `csrf_uuid` key. The method will return a string which
you can then put into a hidden input, with the name `csrf_token`, if you haven't changed the name in the config.

To ease the creation of those hidden inputs, you may want to create a template extension or view helper (depending on
the templating engine you use), which takes the UUID and passes it down to the token manager and then just returns the
hidden input.
