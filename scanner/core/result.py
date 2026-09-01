from typing import Any

from pydantic import BaseModel


class HttpRequestResult(BaseModel):
    identity_name: str
    method: str
    path: str
    status_code: int
    request_json: dict[str, Any] | list[Any] | None = None
    response_json: dict[str, Any] | list[Any] | None = None
    response_text: str | None = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300
