import asgiless.type.asgi

ERROR_CODE = 500
ERROR_HEADERS = [(b"content-type", b"application/json; charset=utf-8")]
ERROR_PAYLOAD = '{"detail": "Internal Server Error"}'.encode()

ERROR_RESP_START = asgiless.type.asgi.ASGIHTTPMessage.ResponseStart(
    type="http.response.start",
    status=ERROR_CODE,
    headers=ERROR_HEADERS,
)
ERROR_RESP_BODY = asgiless.type.asgi.ASGIHTTPMessage.ResponseBody(
    type="http.response.body",
    body=ERROR_PAYLOAD,
    more_body=False,
)
ERROR_RESP = asgiless.type.asgi.ASGIResponse(
    status=ERROR_CODE,
    headers=ERROR_HEADERS,
    body=ERROR_PAYLOAD,
)
