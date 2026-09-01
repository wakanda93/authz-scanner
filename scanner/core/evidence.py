from pydantic import BaseModel

from scanner.core.result import HttpRequestResult


class HttpEvidence(BaseModel):
    observed: HttpRequestResult
    expected_status_code: int
    description: str

    @property
    def status_mismatch(self) -> bool:
        return self.observed.status_code != self.expected_status_code
