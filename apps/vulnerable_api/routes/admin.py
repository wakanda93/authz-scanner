from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.vulnerable_api.auth import get_current_user
from apps.vulnerable_api.database import get_db
from apps.vulnerable_api.models import User
from apps.vulnerable_api.schemas import UserWithPasswordHash


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserWithPasswordHash])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[User]:
    return list(db.scalars(select(User)).all())
