#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Flask-Dance example.

This example demonstrates how to integrate a server application with
Authentiq Connect. It uses the popular Flask-Dance package to make
this trivial in Flask.
"""
from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals
)

import os

from flask import Flask, redirect, url_for
from flask_dance.contrib.authentiq import make_authentiq_blueprint, authentiq
from werkzeug.contrib.fixers import ProxyFix


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
CLIENT_ID = os.environ.get("CLIENT_ID", "examples-flask-basic")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "ed25519")

# Personal details requested from the user. See the "scopes_supported" key in
# the following JSON document for an up to date list of supported scopes:
#
#   https://connect.authentiq.io/.well-known/openid-configuration
#
REQUESTED_SCOPES = ["openid", "aq:name", "email~s", "aq:push", "userinfo"]

PORT = 8000
REDIRECT_URL = "http://localhost:%d/authorized" % PORT

app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = "supersekrit"
blueprint = make_authentiq_blueprint(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    scope=" ".join(REQUESTED_SCOPES),
)
app.register_blueprint(blueprint, url_prefix="/login")


@app.route("/")
def index():
    if not authentiq.authorized:
        return redirect(url_for("authentiq.login"))
    resp = authentiq.get("/userinfo")
    assert resp.ok
    data = resp.json()
    return "You are {name} on Authentiq!".format(
        name=data.get("name") or data.get("email") or "anonymous")


if __name__ == "__main__":

    if app.debug:
        import os

        # Allow insecure oauth2 when debugging
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    app.run()
