import collections.abc
import typing

import asgiless.type.http as type_http


class ASGIHTTPMessage:
    class Request(typing.TypedDict):
        type: typing.Literal["http.request"]
        body: bytes | None  # default: b""
        more_body: bool  # default: False

    class ResponseStart(typing.TypedDict):
        type: typing.Literal["http.response.start"]
        status: int
        headers: collections.abc.Iterable[tuple[bytes, bytes]]  # default: []
        trailers: typing.NotRequired[bool]  # default: False

    class ResponseBody(typing.TypedDict):
        type: typing.Literal["http.response.body"]
        body: bytes | None  # default: b""
        more_body: bool  # default: False

    class Disconnect(typing.TypedDict):
        type: typing.Literal["http.disconnect"]

    SendType = Request | Disconnect
    ResponseType = ResponseStart | ResponseBody
    Type = SendType | ResponseType


class ASGILifespanMessage:
    class Receive:
        class Startup(typing.TypedDict):
            type: typing.Literal["lifespan.startup"]

        class Shutdown(typing.TypedDict):
            type: typing.Literal["lifespan.shutdown"]

        STARTUP = Startup(type="lifespan.startup")
        SHUTDOWN = Shutdown(type="lifespan.shutdown")

    class Send:
        class StartupComplete(typing.TypedDict):
            type: typing.Literal["lifespan.startup.complete"]

        class StartupFailed(typing.TypedDict):
            type: typing.Literal["lifespan.startup.failed"]
            message: typing.NotRequired[str]

        class ShutdownComplete(typing.TypedDict):
            type: typing.Literal["lifespan.shutdown.complete"]

        class ShutdownFailed(typing.TypedDict):
            type: typing.Literal["lifespan.shutdown.failed"]
            message: typing.NotRequired[str]

        STARTUP_COMPLETE = StartupComplete(type="lifespan.startup.complete")
        STARTUP_FAILED = StartupFailed(type="lifespan.startup.failed")
        SHUTDOWN_COMPLETE = ShutdownComplete(type="lifespan.shutdown.complete")
        SHUTDOWN_FAILED = ShutdownFailed(type="lifespan.shutdown.failed")

    ReceiveType = Receive.Startup | Receive.Shutdown
    SendType = Send.StartupComplete | Send.StartupFailed | Send.ShutdownComplete | Send.ShutdownFailed
    Type = ReceiveType | SendType


class ASGIHTTPScopeVersion(typing.TypedDict):
    version: typing.Literal["2.0", "3.0"]
    spec_version: typing.Literal["2.0"]


class ASGIHTTPScope(typing.TypedDict):
    type: typing.Literal["http"]
    asgi: ASGIHTTPScopeVersion

    scheme: typing.Literal["http", "https"]
    http_version: typing.Literal["1.1"]

    server: tuple[str, int]
    client: tuple[str, int]

    headers: list[tuple[bytes, bytes]]
    method: type_http.HTTPMethodType
    path: str
    raw_path: bytes | None
    root_path: str
    query_string: bytes

    additional_context: dict[str, typing.Any] | None


class ASGILifespanScopeVersion(typing.TypedDict):
    version: typing.Literal["3.0"]
    spec_version: typing.Literal["2.0"]


class ASGILifespanScope(typing.TypedDict):
    type: typing.Literal["lifespan"]
    asgi: ASGILifespanScopeVersion

    state: typing.NotRequired[dict[str, typing.Any]]


class ASGIResponse(typing.TypedDict):
    status: int
    headers: collections.abc.Iterable[tuple[bytes, bytes]]
    body: bytes


class ASGIApp(typing.Protocol):
    async def __call__(
        self,
        scope: ASGIHTTPScope | ASGILifespanScope,
        recv: collections.abc.Callable[[], collections.abc.Awaitable[ASGIHTTPScope | ASGILifespanScope]],
        send: collections.abc.Callable[[ASGIHTTPScope | ASGILifespanScope], collections.abc.Awaitable[None]],
    ) -> None: ...
