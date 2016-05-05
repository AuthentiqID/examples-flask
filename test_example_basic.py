#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import io
import json
import os
import pytest
import requests

from flask import url_for

from example_basic import app

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


@pytest.yield_fixture(scope="session")
def test_app():
    """
    Create test context for app and yield test client.
    """
    app.config.update({
        "SERVER_NAME": "localhost:8000",
        "TESTING": True,
        "DEBUG": False
    })

    with app.test_request_context():
        yield app.test_client()


@pytest.fixture
def mocked_token_endpoint(monkeypatch):
    """
    Mocked Token endpoint.
    """
    def fetch_token(self, token_url, code=None, authorization_response=None,
                    body='', auth=None, username=None, password=None,
                    method='POST', timeout=None, headers=None, verify=True,
                    **kwargs):
        app.logger.info("Token endpoint called at %s", token_url)
        return {"Foo": "Bar"}

    monkeypatch.setattr(
        "requests_oauthlib.OAuth2Session.fetch_token", fetch_token)


@pytest.fixture
def mocked_userinfo_endpoint(monkeypatch):
    """
    Mocked UserInfo endpoint.
    """
    def mock_request(self, method, url, *args, **kwargs):
        app.logger.info("UserInfo endpoint called at %s", url)
        userinfo = {"name": "Demo User"}
        response = requests.Response()
        response.status_code = 200
        response.raw = io.BytesIO(json.dumps(userinfo).encode("utf-8"))
        return response

    monkeypatch.setattr("requests.sessions.Session.request", mock_request)


def test_index(test_app):
    """
    Test if index redirects to provider correctly.
    """
    # check we are redirected to provider
    res = test_app.get(url_for("index"))
    assert res.status_code == 302

    # load provider authorization page without an error
    url = res.headers.get("Location")
    res = requests.get(url, allow_redirects=1)
    assert res.status_code == 200
    assert res.headers["Aq-Session-Uri"]


def test_authorized(test_app, mocked_token_endpoint, mocked_userinfo_endpoint):
    """
    Test if app displays the user information after authorization.
    """
    url = url_for("authorized", code="1234")
    res = test_app.get(url)
    assert res.status_code == 200
    data = json.loads(res.data.decode("utf-8"))
    assert data["name"] == "Demo User"
