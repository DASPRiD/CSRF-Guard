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
implementations like Zend\ServiceManager. If you are using that or a similar container implementation together with
Zend\Expressive, you can register your factories by simply having an autoloaded config file looking like this:

```php
<?php
return (new DASPRiD\CsrfGuard\ConfigProvider())->__invoke();
```

Alternatively, you can register the factories manually in your container. After that, you need to have a `config` entry
in your container, which should return a config array. Again, when using Zend\Expressive, it should be enough to copy
the `example-config.php` file from the `doc` directory to your autoload folder.

The config example contains some sane defaults, yet you need to adjust at least the `private_key`. You must also
adjust the `failure_middleware` to point to a container key containing the middleware responsible for creating a
response when the CSRF validation fails. That middleware could, for instance, display an error page or redirect the user
somewhere else.

Finally, you need to add a CSRF token to every `POST`, `PUT` or `DELETE` request you are sending to the server. When you
have all factories registered, you can access get the CSRF token through the request object through the key defiend in
the config.

## Public key providers

As CSRF tokens are always created with both a public and a private key, the public key is, by default, generated for you
automatically with a given lifetime. You can supply your own public key provider though, which could, for instance,
return user ID as the public key. When your provider returns `null` instead of a string, the CSRF middleware will fall
back to using a cookie. This is useful if you need CSRF tokens for users who aren't authenticated yet.
