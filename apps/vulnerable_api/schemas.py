from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel

from apps.vulnerable_api.models import OrderStatus, UserRole


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserPublic(BaseModel):
    id: str
    email: str
    role: UserRole

    model_config = {"from_attributes": True}


class UserWithPasswordHash(UserPublic):
    password_hash: str


class OrderItemPublic(BaseModel):
    id: str
    order_id: str
    product_name: str
    quantity: int
    unit_price: Decimal

    model_config = {"from_attributes": True}


class OrderItemCreate(BaseModel):
    product_name: str
    quantity: int
    unit_price: Decimal


class OrderPublic(BaseModel):
    id: str
    owner_id: str
    status: OrderStatus
    total_amount: Decimal
    created_at: datetime
    items: list[OrderItemPublic] = []

    model_config = {"from_attributes": True}


class OrderCreate(BaseModel):
    items: list[OrderItemCreate] = []
    status: OrderStatus = OrderStatus.PENDING
    total_amount: Decimal = Decimal("0.00")


class OrderUpdate(BaseModel):
    status: OrderStatus | None = None
    total_amount: Decimal | None = None
