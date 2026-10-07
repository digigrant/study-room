"""Minimal JSON/form HTTP client used by trusted host code.

Requests go through a ``Transport`` so tests substitute ``FakeTransport`` and
never touch the network. Bodies and headers that carry secrets stay inside
this process; nothing is passed on a command line.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Mapping

from . import redact
from .errors import Failure, fail


@dataclass
class Response:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> object:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None


class Transport:
    def send(self, request: Request, timeout: float) -> Response:
        req = urllib.request.Request(request.url, data=request.body, method=request.method)
        for key, value in request.headers.items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoints
                return Response(resp.status, resp.read(), dict(resp.headers.items()))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, exc.read() or b"", dict(exc.headers.items()) if exc.headers else {})
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            host = urllib.parse.urlsplit(request.url).hostname or "?"
            raise fail(
                Failure.EXTERNAL_SERVICE_UNAVAILABLE,
                f"could not reach {host}: {getattr(exc, 'reason', exc)}",
            ) from None


class Client:
    def __init__(self, transport: Transport | None = None, *, timeout: float = 30.0):
        self.transport = transport or Transport()
        self.timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: object = None,
        form: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response:
        if not url.startswith("https://") and not url.startswith("http://127.0.0.1"):
            raise fail(Failure.INTERNAL, f"refusing non-HTTPS request to {urllib.parse.urlsplit(url).hostname}")
        hdrs = {"Accept": "application/json", "User-Agent": "study-room"}
        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            hdrs["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(dict(form)).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if headers:
            hdrs.update(headers)
        return self.transport.send(Request(method, url, hdrs, body), timeout or self.timeout)


Route = Callable[[Request], Response]


@dataclass
class FakeTransport(Transport):
    routes: list[tuple[str, str, Route]] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)

    def on(self, method: str, url_prefix: str, route: Route | Response | object) -> "FakeTransport":
        if isinstance(route, Response):
            fixed = route
            fn: Route = lambda _req: Response(fixed.status, fixed.body, dict(fixed.headers))
        elif callable(route):
            fn = route  # type: ignore[assignment]
        else:
            payload = json.dumps(route).encode()
            fn = lambda _req: Response(200, payload, {"Content-Type": "application/json"})
        self.routes.insert(0, (method.upper(), url_prefix, fn))
        return self

    def send(self, request: Request, timeout: float) -> Response:
        self.requests.append(request)
        for method, prefix, fn in self.routes:
            if request.method.upper() == method and request.url.startswith(prefix):
                return fn(request)
        raise fail(
            Failure.EXTERNAL_SERVICE_UNAVAILABLE,
            f"no fake route for {request.method} {redact.redact_text(request.url)}",
        )


def json_response(data: object, status: int = 200) -> Response:
    return Response(status, json.dumps(data).encode(), {"Content-Type": "application/json"})
