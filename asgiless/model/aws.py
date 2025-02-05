import base64
import collections
import collections.abc
import contextlib
import functools
import itertools
import typing
import urllib.parse

import pydantic
import pydantic_core

import asgiless.type.asgi as type_asgi
import asgiless.type.aws as type_aws
import asgiless.type.config as type_config
import asgiless.type.http as type_http


def all_casings(input_string: str) -> collections.abc.Generator[str, None, None]:
    """https://stackoverflow.com/a/6792898"""
    if not input_string:
        yield ""
    else:
        first = input_string[:1]
        if first.lower() == first.upper():
            for sub_casing in all_casings(input_string[1:]):
                yield first + sub_casing
        else:
            for sub_casing in all_casings(input_string[1:]):
                yield first.lower() + sub_casing
                yield first.upper() + sub_casing


class LambdaEventModel(pydantic.BaseModel):
    class Response(pydantic.BaseModel):
        isBase64Encoded: bool = False
        statusCode: int
        headers: dict[str, list[str]]
        body: bytes

        config: type_config.ASGIServerConfig = pydantic.Field(default_factory=type_config.ASGIServerConfig)

        @pydantic.field_validator("headers", mode="after")
        @classmethod
        def validate_header(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
            headers = collections.defaultdict(list)

            for k, v in value.items():
                headers[k.lower()].extend(v)

            return dict(headers)

        @pydantic.model_validator(mode="after")
        def validate_model(self) -> typing.Self:
            # isBase64Encoded
            if not self.body:
                self.isBase64Encoded = False
            elif not self.is_text_content_type:
                self.isBase64Encoded = True
            else:
                try:
                    self.body.decode()
                except UnicodeDecodeError:
                    self.isBase64Encoded = True

            exclude_headers = {k.lower() for k in self.config.exclude_header_keys}
            self.headers = {k: v for k, v in self.headers.items() if k not in exclude_headers}

            return self

        @functools.cached_property
        def is_text_content_type(self) -> bool:
            if not self.headers:
                return False

            if not (content_type := self.headers.get("content-type", [""])[0]):
                return False

            return any(prefix in content_type for prefix in self.config.text_content_types)

        @property
        def serialized_body(self) -> str:
            if not self.body:
                return ""
            return base64.b64encode(self.body).decode() if self.isBase64Encoded else self.body.decode()

        @property
        def all_cased_headers(self) -> dict[str, str]:
            result = {}
            for k, vs in self.headers.items():
                if not vs:
                    continue
                if len(vs) == 1:
                    result[k] = vs[0]
                    continue
                for cased_key, v in zip(all_casings(k), vs):
                    result[cased_key] = v
            return result

        @pydantic.model_serializer(mode="plain")
        def to_representation(self) -> type_aws.LambdaResponseType:
            # As each event model has different ways to handle headers with multi-values, we need to handle them differently.
            raise NotImplementedError

    context: type_aws.LambdaContextType | None = None

    isBase64Encoded: bool = False
    body: bytes

    config: type_config.ASGIServerConfig = pydantic.Field(default_factory=type_config.ASGIServerConfig)
    __pydantic_extra__: dict[str, typing.Any]

    model_config = pydantic.ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
    )

    @pydantic.field_validator("body", mode="before")
    @classmethod
    def validate_body(cls, value: bytes | None) -> bytes:
        return value or b""

    @pydantic.model_validator(mode="after")
    def validate_model(self) -> typing.Self:
        if self.body and self.isBase64Encoded:
            self.body = base64.b64decode(self.body)

        return self

    @property
    def _parsed_multi_headers(self) -> dict[str, list[str]]:
        raise NotImplementedError

    @property
    def _server(self) -> tuple[str, int]:
        if not (server_names := self._parsed_multi_headers.get("host", ["backend"])):
            return "localhost", 80
        server_name = server_names[0]

        if ":" not in server_name:
            if server_ports := self._parsed_multi_headers.get("x-forwarded-port", ["80"]):
                return server_name, int(server_ports[0])
            return server_name, 80

        server_name, server_port = server_name.split(":")
        return server_name, int(server_port)

    @property
    def _client(self) -> tuple[str, int]:
        raise NotImplementedError

    @property
    def _scheme(self) -> typing.Literal["http", "https"]:
        if schemes := self._parsed_multi_headers.get("x-forwarded-proto", ["https"]):
            return typing.cast(typing.Literal["http", "https"], schemes[0])
        return "https"

    @property
    def _method(self) -> type_http.HTTPMethodType:
        raise NotImplementedError

    @property
    def _event_path(self) -> str:
        raise NotImplementedError

    @property
    def _query_string(self) -> bytes:
        raise NotImplementedError

    @property
    def asgi_scope(self) -> type_asgi.ASGIHTTPScope:  # type: ignore[misc]
        path = self._event_path

        if (base_path := self.config.base_path) and base_path != "/":
            path = path.removeprefix(base_path)

        return type_asgi.ASGIHTTPScope(
            type="http",
            asgi=type_asgi.ASGIHTTPScopeVersion(version="3.0", spec_version="2.0"),
            scheme=self._scheme,
            http_version="1.1",
            server=self._server,
            client=self._client,
            headers=list(
                itertools.chain.from_iterable(
                    [(k.encode(), v.encode()) for v in vs] for k, vs in self._parsed_multi_headers.items()
                )
            ),
            method=self._method,
            path=urllib.parse.unquote(path),
            raw_path=None,
            root_path="",
            query_string=self._query_string,
            additional_context={"aws": {"parsed_event": self.model_dump(), "context": self.context}},
        )

    def convert_asgi_response_to_lambda_response(self, response: type_asgi.ASGIResponse) -> type_aws.LambdaResponseType:
        parsed_headers = collections.defaultdict[str, list[str]](list)
        for k, v in response["headers"]:
            parsed_headers[k.decode()].append(v.decode())

        return self.Response(
            statusCode=response["status"],
            headers=dict(parsed_headers),
            body=response["body"],
            config=self.config,
        ).to_representation()


class ELBEventModel(LambdaEventModel):
    """https://docs.aws.amazon.com/elasticloadbalancing/latest/application/lambda-functions.html"""

    class Response(LambdaEventModel.Response):
        @pydantic.model_serializer(mode="plain")
        def to_representation(self) -> type_aws.LambdaResponseType:
            result = {
                "isBase64Encoded": self.isBase64Encoded,
                "statusCode": self.statusCode,
                "body": self.serialized_body or None,
                "headers": self.all_cased_headers or None,
                "multiValueHeaders": self.headers or None,
            }
            return {k: v for k, v in result.items() if v is not None}

    class ELBRequestContext(pydantic.BaseModel):
        class ELB(pydantic.BaseModel):
            targetGroupArn: str

        elb: ELB

    requestContext: ELBRequestContext  # Signature for ALB event

    httpMethod: type_http.HTTPMethodType
    path: str
    queryStringParameters: dict[str, str] | None = None
    multiValueQueryStringParameters: dict[str, list[str]] | None = None
    headers: dict[str, str] | None = None
    multiValueHeaders: dict[str, list[str]] | None = None

    @property
    def _parsed_multi_headers(self) -> dict[str, list[str]]:
        return {
            k.lower(): vs if isinstance(vs, list) else [vs]
            for k, vs in ((self.multiValueHeaders or {}) | (self.headers or {})).items()
        }

    @property
    def _client(self) -> tuple[str, int]:
        if not (source_ips := self._parsed_multi_headers.get("x-forwarded-for", ["localhost"])):
            return "localhost", 0
        return source_ips[0], 0

    @property
    def _method(self) -> type_http.HTTPMethodType:
        return self.httpMethod

    @property
    def _event_path(self) -> str:
        return self.path or "/"

    @property
    def _query_string(self) -> bytes:
        if not (parameters := (self.multiValueQueryStringParameters or {}) | (self.queryStringParameters or {})):
            return b""

        unquoted_parameters: list[tuple[str, str]] = []
        for key, value in parameters.items():
            if isinstance(value, str):
                unquoted_parameters.append((key, urllib.parse.unquote_plus(value)))
            else:
                unquoted_parameters.extend((key, urllib.parse.unquote_plus(element)) for element in value)
        return urllib.parse.urlencode(unquoted_parameters, doseq=True).encode()


class APIGatewayProxyEventV1Model(LambdaEventModel):
    class Response(LambdaEventModel.Response):
        @pydantic.model_serializer(mode="plain")
        def to_representation(self) -> type_aws.LambdaResponseType:
            return {
                "isBase64Encoded": self.isBase64Encoded,
                "statusCode": self.statusCode,
                "body": self.serialized_body,
                "headers": self.all_cased_headers,
                "multiValueHeaders": self.headers,
            }

    class RequestContextV1(pydantic.BaseModel):
        class RequestContextIdentity(pydantic.BaseModel):
            sourceIp: str

        httpMethod: str
        identity: RequestContextIdentity

    """
    https://docs.aws.amazon.com/lambda/latest/dg/services-apigateway.html
    https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """

    requestContext: RequestContextV1  # Signature for API Gateway V1 event

    version: typing.Literal["1.0"] = "1.0"
    path: str
    httpMethod: type_http.HTTPMethodType
    headers: dict[str, str] | None = None
    multiValueHeaders: dict[str, list[str]] | None = None
    queryStringParameters: dict[str, str] | None = None
    multiValueQueryStringParameters: dict[str, list[str]] | None = None

    @property
    def _parsed_multi_headers(self) -> dict[str, list[str]]:
        return {
            k.lower(): vs if isinstance(vs, list) else [vs]
            for k, vs in ((self.multiValueHeaders or {}) | (self.headers or {})).items()
        }

    @property
    def _client(self) -> tuple[str, int]:
        return self.requestContext.identity.sourceIp, 0

    @property
    def _method(self) -> type_http.HTTPMethodType:
        return self.httpMethod

    @property
    def _event_path(self) -> str:
        return self.path or "/"

    @property
    def _query_string(self) -> bytes:
        if not (parameters := (self.multiValueQueryStringParameters or {}) | (self.queryStringParameters or {})):
            return b""

        unquoted_parameters: list[tuple[str, str]] = []
        for key, value in parameters.items():
            if isinstance(value, str):
                unquoted_parameters.append((key, urllib.parse.unquote_plus(value)))
            else:
                unquoted_parameters.extend((key, urllib.parse.unquote_plus(element)) for element in value)
        return urllib.parse.urlencode(unquoted_parameters, doseq=True).encode()


class APIGatewayProxyEventV2Model(LambdaEventModel):
    class Response(LambdaEventModel.Response):
        @pydantic.model_serializer(mode="plain")
        def to_representation(self) -> type_aws.LambdaResponseType:
            headers = {
                k: ",".join(v) if len(v) > 1 else v for k, v in self.headers.items() if k and v and k != "set-cookie"
            }
            cookies = list(itertools.chain.from_iterable([v for k, v in self.headers.items() if k == "set-cookie"]))
            return {
                "cookies": cookies,
                "isBase64Encoded": self.isBase64Encoded,
                "statusCode": self.statusCode,
                "headers": headers,
                "body": self.serialized_body,
            }

    class RequestContextV2(pydantic.BaseModel):
        class HTTP(pydantic.BaseModel):
            method: type_http.HTTPMethodType
            path: str
            sourceIp: str

        http: HTTP
        requestId: str
        time: str
        timeEpoch: int

    """
    https://docs.aws.amazon.com/lambda/latest/dg/services-apigateway.html
    https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """

    requestContext: RequestContextV2  # Signature for API Gateway V2 event

    version: typing.Literal["2.0"] = "2.0"
    rawQueryString: str
    cookies: list[str] | None = None
    headers: dict[str, str] | None = None

    @property
    def _parsed_multi_headers(self) -> dict[str, list[str]]:
        return {k.lower(): v.split(",") for k, v in (self.headers or {}).items()}

    @property
    def _client(self) -> tuple[str, int]:
        return self.requestContext.http.sourceIp, 0

    @property
    def _method(self) -> type_http.HTTPMethodType:
        return self.requestContext.http.method

    @property
    def _event_path(self) -> str:
        return self.requestContext.http.path or "/"

    @property
    def _query_string(self) -> bytes:
        return self.rawQueryString.encode()


EVENT_MODELS: list[type[ELBEventModel | APIGatewayProxyEventV1Model | APIGatewayProxyEventV2Model]] = [
    ELBEventModel,
    APIGatewayProxyEventV1Model,
    APIGatewayProxyEventV2Model,
]


def parse_aws_event(
    config: type_config.ASGIServerConfig,
    event: dict[str, typing.Any],
    context: type_aws.LambdaContextType | None = None,
) -> LambdaEventModel:
    payloads = event | {"context": context, "config": config}

    for model in EVENT_MODELS:
        with contextlib.suppress(pydantic_core.ValidationError):
            return model.model_validate(payloads)

    raise ValueError("Invalid event payload")
