from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.hardened_api.auth import get_password_hash
from apps.hardened_api.models import Order, OrderItem, OrderStatus, User, UserRole


SEED_PASSWORD = "Password123!"

USER_A_ID = "00000000-0000-4000-8000-000000000001"
USER_B_ID = "00000000-0000-4000-8000-000000000002"
ADMIN_ID = "00000000-0000-4000-8000-000000000003"

USER_A_ORDER_ID = "10000000-0000-4000-8000-000000000001"
USER_B_ORDER_ID = "10000000-0000-4000-8000-000000000002"

USER_A_KEYBOARD_ITEM_ID = "20000000-0000-4000-8000-000000000001"
USER_A_HUB_ITEM_ID = "20000000-0000-4000-8000-000000000002"
USER_B_EARBUDS_ITEM_ID = "20000000-0000-4000-8000-000000000003"


def seed_database(db: Session) -> None:
    existing_user = db.scalar(select(User).where(User.email == "userA@example.com"))
    if existing_user is not None:
        return

    user_a = User(
        id=USER_A_ID,
        email="userA@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.USER,
    )
    user_b = User(
        id=USER_B_ID,
        email="userB@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.USER,
    )
    admin = User(
        id=ADMIN_ID,
        email="admin1@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.ADMIN,
    )

    db.add_all([user_a, user_b, admin])
    db.flush()

    user_a_order = Order(
        id=USER_A_ORDER_ID,
        owner_id=user_a.id,
        status=OrderStatus.PENDING,
        total_amount=Decimal("149.98"),
    )
    user_b_order = Order(
        id=USER_B_ORDER_ID,
        owner_id=user_b.id,
        status=OrderStatus.APPROVED,
        total_amount=Decimal("89.50"),
    )

    db.add_all([user_a_order, user_b_order])
    db.flush()

    db.add_all(
        [
            OrderItem(
                id=USER_A_KEYBOARD_ITEM_ID,
                order_id=user_a_order.id,
                product_name="Wireless Keyboard",
                quantity=1,
                unit_price=Decimal("79.99"),
            ),
            OrderItem(
                id=USER_A_HUB_ITEM_ID,
                order_id=user_a_order.id,
                product_name="USB-C Hub",
                quantity=1,
                unit_price=Decimal("69.99"),
            ),
            OrderItem(
                id=USER_B_EARBUDS_ITEM_ID,
                order_id=user_b_order.id,
                product_name="Noise Cancelling Earbuds",
                quantity=1,
                unit_price=Decimal("89.50"),
            ),
        ]
    )
    db.commit()
