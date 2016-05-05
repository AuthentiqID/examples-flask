#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Flask + Requests-OAuthlib example.

This example demonstrates how to integrate a server application with
Authentiq Connect, using standard OAuth 2.0. It uses the popular
requests-oauthlib module to make this trivial in Flask.

As with all plain OAuth 2.0 integrations, we use the UserInfo endpoint to
retrieve the user profile after authorization. Check out our native
AuthentiqJS snippet or an OpenID Connect library to optimise this.
"""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import oauthlib
import requests

from flask import Flask, abort, jsonify, redirect, request, session, url_for
from requests_oauthlib import OAuth2Session


class Config(object):
    """
    Flask configuration container.
    """
    DEBUG = True
    TESTING = False
    SECRET_KEY = "aicahquohzieRah5ZooLoo3a"

AUTHENTIQ_BASE = "https://connect.authentiq.io/"
AUTHORIZE_URL = AUTHENTIQ_BASE + "authorize"
TOKEN_URL = AUTHENTIQ_BASE + "token"
USERINFO_URL = AUTHENTIQ_BASE + "userinfo"

# The following app is registered at Authentiq Connect.
CLIENT_ID = "examples-flask-basic"
CLIENT_SECRET = "ed25519"

# Personal details requested from the user. See the "scopes_supported" key in
# the following JSON document for an up to date list of supported scopes:
#
#   https://connect.authentiq.io/.well-known/openid-configuration
#
REQUESTED_SCOPES = ["aq:name", "email", "aq:push"]

PORT = 8000
REDIRECT_URL = "http://localhost:%d/authorized" % PORT

app = Flask(__name__)
app.config.from_object(Config)


@app.route("/")
def index():

    # Check if redirect_uri matches with the one registered with the
    # example client.
    assert url_for("authorized", _external=True) == REDIRECT_URL, (
        "For this demo to work correctly, please make sure it is hosted on "
        "localhost, so that the redirect URL is exactly " + REDIRECT_URL + "."
    )

    # Initialise an authentication session. Here we pass in scope and
    # redirect_uri explicitly, though when omitted defaults will be taken
    # from the registered client.
    authentiq = OAuth2Session(
        CLIENT_ID,
        scope=REQUESTED_SCOPES,
        redirect_uri=url_for("authorized", _external=True),
    )

    # Build the authorization URL and retrieve some client state.
    authorization_url, state = authentiq.authorization_url(AUTHORIZE_URL)

    # Save state to match it in the response.
    session["state"] = state

    # Redirect to the Authentiq Connect authentication endpoint.
    return redirect(authorization_url)


@app.route("/authorized")
def authorized():
    """
    OAuth 2.0 redirection point.
    """
    # Pass in our client side crypto state; requests-oauthlib will
    # take care of matching it in the OAuth2 response.
    authentiq = OAuth2Session(CLIENT_ID, state=session.get("state"))

    try:
        error = request.args["error"]
        oauthlib.oauth2.raise_from_error(error, request.args)
    except KeyError:
        pass
    except oauthlib.oauth2.OAuth2Error as e:
        code = e.status_code or 400
        description = "Provider returned: " + (e.description or e.error)
        abort(code, description=description)

    try:

        # Use our client_secret to exchange the authorization code for a
        # token. Requests-oauthlib parses the redirected URL for us.
        # The token will contain the access_token, a refresh_token, and the
        # scope the end-user consented to.
        token = authentiq.fetch_token(TOKEN_URL,
                                      client_secret=CLIENT_SECRET,
                                      authorization_response=request.url)

        app.logger.info("Received token: %s" % token)

    # The incoming request looks flaky, let's not handle it further.
    except oauthlib.oauth2.OAuth2Error as e:
        description = "Request to token endpoint failed: " + \
                      (e.description or e.error)
        abort(code=e.status_code or 400, description=description)

    # The HTTP request to the token endpoint failed.
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code or 502
        description = "Request to token endpoint failed: " + e.response.reason
        abort(code, description=description)

    # Now we can use the access_token to retrieve an OpenID Connect
    # compatible UserInfo structure from the provider. Once again,
    # requests-oauthlib adds a valid Authorization header for us.
    #
    # Note that this request can be optimized out if using an OIDC or
    # native Authentiq Connect client.
    try:
        userinfo = authentiq.get(USERINFO_URL).json()

    # The HTTP request to the UserInfo endpoint failed.
    except requests.exceptions.HTTPError as e:
        abort(code=e.response.status_code or 502,
              description="Request to userinfo endpoint failed: " +
                          e.response.reason)
    except ValueError as e:
        abort(code=502,
              description="Could not decode userinfo response: " + e.message)

    # Here you would save the identity information in database or session
    # and sign the user in. For now just display the USerInfo structure.
    # Use userinfo["sub"] as the user's UUID within a single sign-on sector.
    return jsonify(userinfo)


if __name__ == "__main__":

    if app.debug:
        import os
        # Allow insecure oauth2 when debugging
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # Explicitly set `host=localhost` in order to get the correct redirect_uri.
    app.run(host="localhost", port=PORT)
