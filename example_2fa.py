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

import datetime
import random

import jwt
import oauthlib.oauth2.rfc6749.errors as oauth2_errors
import requests
from flask import Flask, abort, jsonify, redirect, request, session, url_for, \
    make_response
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
REQUESTED_SCOPES = ["openid", "aq:name", "email", "aq:push"]

PORT = 8000
REDIRECT_URL = "http://localhost:%d/authorized" % PORT

app = Flask(__name__)
app.config.from_object(Config)


def authenticate_user(username, password):
    """
    Authenticate a user in your database, and return a UserInfo dictionary.
    """
    if username == "nobody":
        return None

    if password != "1234":
        return False

    return {
        # http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        "sub": username,
        "given_name": random.choice(["Jan", "Robin", "Peter"]),
        "family_name": random.choice(["Donga", "Smith", "van Straten"]),
        "email": username + "@company.tld",
        "preferred_username": username,
    }


@app.route("/")
def index():
    # Check if redirect_uri matches with the one registered with the
    # example client.
    assert url_for("authorized", _external=True) == REDIRECT_URL, (
            "For this demo to work correctly, please make sure it is hosted "
            "on localhost, so that the redirect URL is exactly " +
            REDIRECT_URL + "."
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
        oauth2_errors.raise_from_error(error, request.args)
    except KeyError:
        pass
    except oauth2_errors.OAuth2Error as e:
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
    except oauth2_errors.OAuth2Error as e:
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


@app.route("/authenticate", methods=["POST"])
def authenticate():
    """
    Verify user/pass for Authentiq in 2FA mode, return accreditation token.

    The response MUST include a Content-Type header with value
    "application/jwt". Response codes are interpreted as follows:

        200: User authenticated
        400: Invalid request
        403: Incorrect password
        404: Unknown user
        429: Rate limited (will retry)
        500: Server error
        503: Over capacity (will retry)

    We plan to support application/problem+json error responses too, by
    which you will be able to determine the exact message shown to the end user
    through the value of the "detail" field.

    You may want to rate limit this endpoint using e.g. Flask-Limiter in
    real world systems.
    """
    grant_type = request.form.get("grant_type", "password")
    if grant_type != "password":
        abort(400, "Invalid grant type")

    username = password = state = authorized_party = None

    try:
        username = request.form["username"]
        password = request.form["password"]
        state = request.form["state"]
        authorized_party = request.form.get("azp", None)
    except KeyError:
        abort(400, "Invalid parameters")

    # Avoid CSRF attacks
    if not state or state != session["state"]:
        abort(400, "Invalid state")

    user_info = authenticate_user(username, password)

    if not user_info:
        # Indicate to Authentiq Connect that we haven't been able to
        # authenticate this user locally. Note that you
        if user_info is None:
            abort(404, "User not found")

        abort(403, "Authentication failed")

    now = datetime.datetime.utcnow()

    token = {
        # Token type
        "token": "login_token",
        # Local user account ID
        "sub": username,
        # Issued by ourselves
        "iss": CLIENT_ID,
        # The Authentiq Connect instance that is to consume this token
        "aud": [AUTHENTIQ_BASE.lower()],
        # When issued
        "iat": now,
        # Not valid in the past
        "nbf": now,
        # Valid just to sign in
        "exp": now + datetime.timedelta(minutes=5),
    }

    # Merge in user information from our "backend".
    token.update(user_info)

    # Authentiq Connect can request to bind the token to an Authentiq ID
    # enabling that user to sign in without a password in the future.
    if authorized_party:
        # Mark the token as a link token.
        token["token"] = "link_token"

        # Add the requested Authentiq ID as the authorised party.
        token["azp"] = authorized_party
        token["aud"].append(authorized_party)

        # Remove the expiry time claim. You could also set this to e.g. a month
        # if you require your users to re-link their accounts once in a while.
        del token["exp"]

    # Sign the token with HS256 and your client secret.
    # We plan to support different algorithms soon, keep an eye on
    # https://connect.authentiq.io/.well-known/openid-configuration
    token_jwt = jwt.encode(token, key=app.config["AQ_CLIENT_SECRET"],
                           algorithm="HS256")

    resp = make_response(token_jwt)
    resp.status_code = 200
    resp.mimetype = "application/jwt"
    resp.cache_control.private = True
    resp.cache_control.no_cache = True

    return resp


if __name__ == "__main__":

    if app.debug:
        import os

        # Allow insecure oauth2 when debugging
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # Explicitly set `host=localhost` in order to get the correct redirect_uri.
    app.run(host="localhost", port=PORT)
