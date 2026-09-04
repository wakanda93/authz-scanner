from apps.hardened_api import models as hardened_models
from apps.hardened_api.database import SessionLocal as HardenedSessionLocal
from apps.hardened_api.database import engine as hardened_engine
from apps.hardened_api.seed import reset_database as reset_hardened_database
from apps.vulnerable_api import models as vulnerable_models
from apps.vulnerable_api.database import SessionLocal as VulnerableSessionLocal
from apps.vulnerable_api.database import engine as vulnerable_engine
from apps.vulnerable_api.seed import reset_database as reset_vulnerable_database


def reset_demo_databases() -> list[str]:
    vulnerable_models.Base.metadata.create_all(bind=vulnerable_engine)
    hardened_models.Base.metadata.create_all(bind=hardened_engine)

    with VulnerableSessionLocal() as db:
        reset_vulnerable_database(db)

    with HardenedSessionLocal() as db:
        reset_hardened_database(db)

    return ["vulnerable", "hardened"]


def main() -> None:
    targets = reset_demo_databases()
    print(f"Reset demo data for: {', '.join(targets)}")


if __name__ == "__main__":
    main()
