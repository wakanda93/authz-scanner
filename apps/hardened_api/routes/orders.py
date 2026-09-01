from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from apps.hardened_api.auth import get_current_user
from apps.hardened_api.database import get_db
from apps.hardened_api.models import Order, OrderItem, OrderStatus, User, UserRole
from apps.hardened_api.schemas import OrderCreate, OrderItemPublic, OrderPublic, OrderUpdate


router = APIRouter(prefix="/orders", tags=["orders"])


def get_order_or_404(db: Session, order_id: str) -> Order:
    order = db.scalar(
        select(Order).options(selectinload(Order.items)).where(Order.id == order_id)
    )
    if order is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    return order


def require_order_access(order: Order, current_user: User) -> None:
    if current_user.role == UserRole.ADMIN:
        return
    if order.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def require_admin(current_user: User) -> None:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


@router.get("", response_model=list[OrderPublic])
def list_orders(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Order]:
    query = select(Order).options(selectinload(Order.items))
    if current_user.role != UserRole.ADMIN:
        query = query.where(Order.owner_id == current_user.id)
    return list(db.scalars(query).all())


@router.post("", response_model=OrderPublic, status_code=status.HTTP_201_CREATED)
def create_order(
    payload: OrderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Order:
    total_amount = sum(
        (item.unit_price * item.quantity for item in payload.items),
        Decimal("0.00"),
    )
    order = Order(
        owner_id=current_user.id,
        status=OrderStatus.PENDING,
        total_amount=total_amount,
    )
    db.add(order)
    db.flush()

    for item in payload.items:
        db.add(
            OrderItem(
                order_id=order.id,
                product_name=item.product_name,
                quantity=item.quantity,
                unit_price=item.unit_price,
            )
        )

    db.commit()
    db.refresh(order)
    return get_order_or_404(db, order.id)


@router.get("/{order_id}", response_model=OrderPublic)
def get_order(
    order_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Order:
    order = get_order_or_404(db, order_id)
    require_order_access(order, current_user)
    return order


@router.put("/{order_id}", response_model=OrderPublic)
def update_order(
    order_id: str,
    payload: OrderUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Order:
    order = get_order_or_404(db, order_id)
    require_order_access(order, current_user)

    if payload.total_amount is not None:
        order.total_amount = payload.total_amount
    db.commit()
    return get_order_or_404(db, order.id)


@router.delete("/{order_id}", response_model=OrderPublic)
def cancel_order(
    order_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Order:
    order = get_order_or_404(db, order_id)
    require_order_access(order, current_user)
    order.status = OrderStatus.CANCELLED
    db.commit()
    return get_order_or_404(db, order.id)


@router.get("/{order_id}/items", response_model=list[OrderItemPublic])
def list_order_items(
    order_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[OrderItem]:
    order = get_order_or_404(db, order_id)
    require_order_access(order, current_user)
    return order.items


@router.get("/{order_id}/items/{item_id}", response_model=OrderItemPublic)
def get_order_item(
    order_id: str,
    item_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrderItem:
    order = get_order_or_404(db, order_id)
    require_order_access(order, current_user)

    item = db.scalar(
        select(OrderItem).where(OrderItem.id == item_id, OrderItem.order_id == order_id)
    )
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order item not found")
    return item


@router.post("/{order_id}/refund", response_model=OrderPublic)
def refund_order(
    order_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Order:
    require_admin(current_user)
    order = get_order_or_404(db, order_id)
    order.status = OrderStatus.REFUNDED
    db.commit()
    return get_order_or_404(db, order.id)


@router.post("/{order_id}/approve", response_model=OrderPublic)
def approve_order(
    order_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Order:
    require_admin(current_user)
    order = get_order_or_404(db, order_id)
    order.status = OrderStatus.APPROVED
    db.commit()
    return get_order_or_404(db, order.id)
