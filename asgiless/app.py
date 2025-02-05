import asyncio
import io
import signal
import typing

import asgiless.const.asgi as const_asgi
import asgiless.model.aws as model_aws
import asgiless.type.asgi as type_asgi
import asgiless.type.aws as type_aws
import asgiless.type.config as type_config

NOT_ALLOWED_CASES = [("http.response.start", True), ("http.response.body", False)]


class ASGIServerless:
    """https://asgi.readthedocs.io/en/latest/specs/main.html"""

    app: type_asgi.ASGIApp
    config: type_config.ASGIServerConfig

    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue[type_asgi.ASGILifespanMessage.Type | type_asgi.ASGIHTTPMessage.Type | None]
    lifespan_state: dict[str, typing.Any]

    def __init__(self, app: type_asgi.ASGIApp, config: type_config.ASGIServerConfig | None = None) -> None:
        self.app = app
        self.config = config or type_config.ASGIServerConfig()

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.queue = asyncio.Queue()
        self.lifespan_state = {}

        # AWS Lambda will send SIGTERM to the process to indicate that it should shut down
        # https://github.com/aws-samples/graceful-shutdown-with-aws-lambda/blob/main/README.md
        self.loop.add_signal_handler(signal.SIGTERM, lambda: self.loop.run_until_complete(self._lifespan_shutdown()))
        self.loop.add_signal_handler(signal.SIGINT, lambda: self.loop.run_until_complete(self._lifespan_shutdown()))
        self.loop.run_until_complete(self._lifespan_startup())

    async def _app_lifespan_call(
        self, message: type_asgi.ASGILifespanMessage.ReceiveType
    ) -> list[type_asgi.ASGILifespanMessage.SendType]:
        response_queue: list[type_asgi.ASGILifespanMessage.SendType] = []

        async def get() -> type_asgi.ASGILifespanMessage.ReceiveType:
            return message

        async def put(message: type_asgi.ASGILifespanMessage.SendType) -> None:
            response_queue.append(message)

        # I hate this, but I had to do this for mypy to stop complaining
        # https://github.com/python/mypy/issues/4976
        await self.app(
            type_asgi.ASGILifespanScope(
                type="lifespan",
                asgi=type_asgi.ASGILifespanScopeVersion(version="3.0", spec_version="2.0"),
                state=self.lifespan_state,
            ),
            get,  # type: ignore[arg-type]
            put,  # type: ignore[arg-type]
        )
        return response_queue

    async def _lifespan_startup(self) -> None:
        messages = await self._app_lifespan_call(type_asgi.ASGILifespanMessage.Receive.STARTUP)
        if not (messages and messages[0].get("type") == "lifespan.startup.complete"):
            raise RuntimeError("Lifespan startup failed", messages[0])

    async def _lifespan_shutdown(self) -> None:
        messages = await self._app_lifespan_call(type_asgi.ASGILifespanMessage.Receive.SHUTDOWN)
        if not (messages and messages[0].get("type") == "lifespan.shutdown.complete"):
            raise RuntimeError("Lifespan shutdown failed", messages[0])

    async def _app_http_call(
        self, scope: type_asgi.ASGIHTTPScope, body: bytes
    ) -> list[type_asgi.ASGIHTTPMessage.ResponseType]:
        response_queue: list[type_asgi.ASGIHTTPMessage.ResponseType] = []

        async def get() -> type_asgi.ASGIHTTPMessage.SendType:
            return type_asgi.ASGIHTTPMessage.Request(type="http.request", body=body, more_body=False)

        async def put(message: type_asgi.ASGIHTTPMessage.ResponseType) -> None:
            response_queue.append(message)

        await self.app(scope | {"state": self.lifespan_state}, get, put)  # type: ignore[arg-type]

        return response_queue

    def _http_run(self, scope: type_asgi.ASGIHTTPScope, body: bytes) -> type_asgi.ASGIResponse:
        return self.loop.run_until_complete(self._http_async_run(scope, body))

    async def _http_async_run(self, scope: type_asgi.ASGIHTTPScope, body: bytes) -> type_asgi.ASGIResponse:
        response_started = False
        response_body_buffer = io.BytesIO()
        response = const_asgi.ERROR_RESP.copy()

        try:
            messages = await self._app_http_call(scope, body)

            for message in messages:
                # message = await self.queue.get()
                if not (message and message["type"].startswith("http.response")):
                    raise ValueError("Invalid ASGI message type", message)
                if (message["type"], response_started) in NOT_ALLOWED_CASES:
                    raise ValueError("Invalid ASGI message type", message)

                response_started = True
                if message["type"] == "http.response.start":
                    response = type_asgi.ASGIResponse(
                        status=message.get("status", response["status"]),
                        headers=message.get("headers", response["headers"]),
                        body=b"",
                    )
                elif message["type"] == "http.response.body":
                    response_body_buffer.write(message.get("body") or b"")

                    if not message.get("more_body", False):
                        response["body"] = response_body_buffer.getvalue()
                        response_body_buffer.close()
                        await self.queue.put(type_asgi.ASGIHTTPMessage.Disconnect(type="http.disconnect"))
                        break
                else:
                    raise ValueError("Invalid ASGI message type", message)

        except Exception as err:
            print(err)
            response = const_asgi.ERROR_RESP

        return response

    def aws_lambda_handler(
        self, event: dict[str, typing.Any], context: type_aws.LambdaContextType
    ) -> type_aws.LambdaResponseType:
        parsed_event = model_aws.parse_aws_event(self.config, event, context)
        return parsed_event.convert_asgi_response_to_lambda_response(
            self._http_run(parsed_event.asgi_scope, parsed_event.body)
        )
