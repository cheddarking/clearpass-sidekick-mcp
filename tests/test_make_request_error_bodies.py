"""Regression tests: ``_make_request`` must hand the structured error body to callers.

The handler used to raise ``ClearPassAPIError(msg, status, error_data)`` from
*inside* its own ``try:``; the following ``except Exception as parse_error``
caught that very exception and re-raised a copy without ``response_data``. Every
structured error body the appliance returned was therefore lost, which is why
callers resorted to re-parsing JSON out of the exception *message*.

These tests pin:
  * ``response_data`` carries the parsed body (and ``status_code`` the status),
  * the historical message format is unchanged,
  * non-JSON bodies (HTML error pages, plain text, empty) are normalised into a
    dict, and an HTML body never reaches a caller as raw markup.
"""

import httpx
import pytest

from src.clearpass_client import ClearPassClient
from src.exceptions import ClearPassAPIError


def _response(status, body, content_type):
    request = httpx.Request("POST", "https://appliance/api/report/1/run")
    return httpx.Response(
        status, content=body, headers={"content-type": content_type},
        request=request,
    )


def _client(response):
    client = ClearPassClient.__new__(ClearPassClient)
    client.base_url = "https://appliance/api"

    async def authenticate():
        return None

    async def request(**_kwargs):
        response.raise_for_status()

    class _Transport:
        pass

    transport = _Transport()
    transport.request = request

    client.authenticate = authenticate
    client.client = transport
    client._log_api_operation = lambda **kwargs: None
    client._extract_request_metadata = lambda *args, **kwargs: {}
    return client


async def _raise(response):
    with pytest.raises(ClearPassAPIError) as excinfo:
        await _client(response)._make_request("POST", "report/1/run", data={})
    return excinfo.value


@pytest.mark.asyncio
async def test_json_error_body_reaches_the_caller():
    body = {
        "detail": "Invalid role_id",
        "validation_messages": {
            "role_id": {"error": "Invalid role_id",
                        "_options": {"1": "[Contractor]", "2": "[Guest]"}}
        },
    }
    error = await _raise(_response(422, __import__("json").dumps(body).encode(),
                                   "application/json"))

    assert error.status_code == 422
    assert error.response_data == body
    # Message format is unchanged -- code and tests match on it.
    assert error.message == (
        "API request failed: POST report/1/run - 422 - Invalid role_id")


@pytest.mark.asyncio
async def test_html_error_body_is_structured_not_raw_html():
    html = (b"<html><head><title>500 Internal Server Error</title></head>"
            b"<body><h1>Server Error</h1><p>Report engine failed</p></body></html>")
    error = await _raise(_response(500, html, "text/html; charset=utf-8"))

    assert error.status_code == 500
    assert isinstance(error.response_data, dict)
    assert error.response_data["body_format"] == "html"
    assert error.response_data["title"] == "500 Internal Server Error"
    assert error.response_data["message"] == "Server Error Report engine failed"
    # No raw markup anywhere a caller can see it.
    assert "<" not in error.message
    assert "<" not in str(error.response_data)


@pytest.mark.asyncio
async def test_empty_body_is_reported_as_empty():
    error = await _raise(_response(405, b"", "text/html"))

    assert error.status_code == 405
    assert error.response_data["body_format"] == "empty"
    assert error.response_data["message"] == ""


@pytest.mark.asyncio
async def test_plain_text_body_is_preserved_verbatim():
    error = await _raise(_response(404, b"Not found", "text/plain"))

    assert error.response_data["body_format"] == "text"
    assert error.response_data["message"] == "Not found"
    assert error.message == "API request failed: POST report/1/run - 404 - Not found"


@pytest.mark.asyncio
async def test_non_object_json_body_is_carried_through():
    error = await _raise(_response(400, b'[{"x": 1}]', "application/json"))

    assert error.response_data["body_format"] == "json"
    assert error.response_data["body"] == [{"x": 1}]
