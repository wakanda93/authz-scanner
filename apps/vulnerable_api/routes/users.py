from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from apps.vulnerable_api.auth import get_current_user
from apps.vulnerable_api.database import get_db
from apps.vulnerable_api.models import User
from apps.vulnerable_api.schemas import UserUpdate, UserWithPasswordHash


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserWithPasswordHash)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.put("/{user_id}", response_model=UserWithPasswordHash)
def update_user(
    user_id: str,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.email is not None:
        user.email = payload.email
    if payload.role is not None:
        user.role = payload.role

    db.commit()
    db.refresh(user)
    return user
