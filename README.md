# Authentiq Flask examples

This repository contains two examples showing how to integrate [Authentiq Connect](https://www.authentiq.com/) into your Python applications, allowing people to sign in using their [Authentiq ID](https://itunes.apple.com/gb/app/authentiq-id/id964932341).

> We'll add another example soon that shows how to connect Authentiq to your user database to easily add two-step verification (through any [TOTP](https://tools.ietf.org/html/rfc6238)-compatible app, e.g. Google Authenticator) and passwordless logins on top of your existing username & password database.

## Installation

Assuming you have cloned this repository already, on Ubuntu 16.04, install the following packages:

    sudo apt-get install python-tox python3-flask python3-requests python3-requests-oauthlib

Or using a virtual environment:

    virtualenv -p /usr/bin/python3 env
    pip install tox flask requests requests-oauthlib


## Example 1: Plain OAuth 2.0 — `example_basic.py`

This example demonstrates how to use Authentiq Connect with an existing 3rd-party OAuth 2.0 client library — the wonderful [requests-oauthlib](https://requests-oauthlib.readthedocs.org/en/latest/) in this case. It simply signs in using Authentiq and displays the retrieved user information.

    python3 example_basic.py

## Example 2: Native Authentiq JS — `example_native.py`

This example uses the [AuthentiqJS](https://github.com/AuthentiqID/authentiq-js) snippet for a richer authentication experience. In particular it shows the following features:

- A faster authentication flow using an OpenID Connect ID Token
- Instant sign-out from phone using the Authentiq ID app

    python3 example_native.py

### Tests

Simply run tox to run tests on Python 2 and Python 3.

    tox

## Contributing

Please help us improve these examples by opening an issue or a pull request.

