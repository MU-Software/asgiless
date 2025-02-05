import typing

LambdaContextType = typing.Any
LambdaResponseType = dict[
    str, bool | int | str | dict[str, str] | dict[str, list[str]] | dict[str, str | list[str]] | list[str]
]
