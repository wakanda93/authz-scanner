from typing import Any

import httpx

from scanner.core.identity import AuthenticatedIdentity
from scanner.core.result import HttpRequestResult


class HttpExecutor:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client

    def request(
        self,
        identity: AuthenticatedIdentity,
        method: str,
        path: str,
        json: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpRequestResult:
        request_headers = {
            **identity.authorization_header,
            **(headers or {}),
        }
        response = self.client.request(
            method=method,
            url=path,
            json=json,
            headers=request_headers,
        )

        response_json: dict[str, Any] | list[Any] | None = None
        response_text: str | None = None
        try:
            parsed_body = response.json()
        except ValueError:
            response_text = response.text
        else:
            if isinstance(parsed_body, dict | list):
                response_json = parsed_body
            else:
                response_text = str(parsed_body)

        return HttpRequestResult(
            identity_name=identity.name,
            method=method.upper(),
            path=path,
            status_code=response.status_code,
            request_json=json,
            response_json=response_json,
            response_text=response_text,
        )
