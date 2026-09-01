import argparse
from pathlib import Path

import httpx
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

from scanner.core.config import ScannerConfig, load_config
from scanner.core.identity import AuthenticatedIdentity, login_all_identities


class SmokeScanResult(BaseModel):
    target_name: str
    base_url: str
    identities: dict[str, AuthenticatedIdentity]
    health_status_code: int
    openapi_status_code: int
    openapi_title: str | None = None

    @property
    def health_ok(self) -> bool:
        return self.health_status_code == 200

    @property
    def openapi_ok(self) -> bool:
        return self.openapi_status_code == 200


def run_smoke_scan(config: ScannerConfig) -> SmokeScanResult:
    with httpx.Client(base_url=config.target.base_url, timeout=10.0) as client:
        identities = login_all_identities(client, config)
        health_response = client.get("/health")
        openapi_response = client.get("/openapi.json")

    openapi_title = None
    if openapi_response.status_code == 200:
        openapi_body = openapi_response.json()
        if isinstance(openapi_body, dict):
            info = openapi_body.get("info", {})
            if isinstance(info, dict):
                title = info.get("title")
                if isinstance(title, str):
                    openapi_title = title

    return SmokeScanResult(
        target_name=config.target.name,
        base_url=config.target.base_url,
        identities=identities,
        health_status_code=health_response.status_code,
        openapi_status_code=openapi_response.status_code,
        openapi_title=openapi_title,
    )


def print_smoke_result(result: SmokeScanResult) -> None:
    console = Console()
    table = Table(title=f"Scanner Smoke Check: {result.target_name}")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Detail")

    table.add_row("Target", "loaded", result.base_url)
    table.add_row("Identities", str(len(result.identities)), ", ".join(result.identities))
    table.add_row("Health", "ok" if result.health_ok else "failed", str(result.health_status_code))
    table.add_row(
        "OpenAPI",
        "ok" if result.openapi_ok else "failed",
        result.openapi_title or str(result.openapi_status_code),
    )
    console.print(table)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AuthZ Scanner")
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Path to scanner YAML config.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    result = run_smoke_scan(config)
    print_smoke_result(result)


if __name__ == "__main__":
    main()
