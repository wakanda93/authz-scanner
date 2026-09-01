from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from apps.hardened_api.auth import get_current_user
from apps.hardened_api.database import get_db
from apps.hardened_api.models import User, UserRole
from apps.hardened_api.schemas import UserPublic, UserUpdate


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserPublic)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.put("/{user_id}", response_model=UserPublic)
def update_user(
    user_id: str,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if current_user.role != UserRole.ADMIN and current_user.id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if payload.email is not None:
        user.email = payload.email

    db.commit()
    db.refresh(user)
    return user
