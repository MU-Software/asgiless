import dataclasses

import asgiless.const.http as const_http


@dataclasses.dataclass(frozen=True, slots=True)
class ASGIServerConfig:
    base_path: str = "/"
    text_content_types: set[str] = dataclasses.field(default_factory=lambda: const_http.TEXT_CONTENT_TYPES)
    exclude_header_keys: set[str] = dataclasses.field(default_factory=set)
