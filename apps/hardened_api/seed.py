from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.hardened_api.auth import get_password_hash
from apps.hardened_api.models import Order, OrderItem, OrderStatus, User, UserRole


SEED_PASSWORD = "Password123!"


def seed_database(db: Session) -> None:
    existing_user = db.scalar(select(User).where(User.email == "userA@example.com"))
    if existing_user is not None:
        return

    user_a = User(
        email="userA@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.USER,
    )
    user_b = User(
        email="userB@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.USER,
    )
    admin = User(
        email="admin1@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.ADMIN,
    )

    db.add_all([user_a, user_b, admin])
    db.flush()

    user_a_order = Order(
        owner_id=user_a.id,
        status=OrderStatus.PENDING,
        total_amount=Decimal("149.98"),
    )
    user_b_order = Order(
        owner_id=user_b.id,
        status=OrderStatus.APPROVED,
        total_amount=Decimal("89.50"),
    )

    db.add_all([user_a_order, user_b_order])
    db.flush()

    db.add_all(
        [
            OrderItem(
                order_id=user_a_order.id,
                product_name="Wireless Keyboard",
                quantity=1,
                unit_price=Decimal("79.99"),
            ),
            OrderItem(
                order_id=user_a_order.id,
                product_name="USB-C Hub",
                quantity=1,
                unit_price=Decimal("69.99"),
            ),
            OrderItem(
                order_id=user_b_order.id,
                product_name="Noise Cancelling Earbuds",
                quantity=1,
                unit_price=Decimal("89.50"),
            ),
        ]
    )
    db.commit()
