from apps.hardened_api.models import Order as HardenedOrder
from apps.hardened_api.models import OrderItem as HardenedOrderItem
from apps.hardened_api.models import User as HardenedUser
from apps.vulnerable_api.models import Order as VulnerableOrder
from apps.vulnerable_api.models import OrderItem as VulnerableOrderItem
from apps.vulnerable_api.models import User as VulnerableUser


def test_vulnerable_api_models_have_expected_tables() -> None:
    assert VulnerableUser.__tablename__ == "users"
    assert VulnerableOrder.__tablename__ == "orders"
    assert VulnerableOrderItem.__tablename__ == "order_items"


def test_hardened_api_models_have_expected_tables() -> None:
    assert HardenedUser.__tablename__ == "users"
    assert HardenedOrder.__tablename__ == "orders"
    assert HardenedOrderItem.__tablename__ == "order_items"
