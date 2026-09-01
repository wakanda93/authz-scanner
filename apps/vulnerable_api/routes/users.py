from fastapi import APIRouter, Depends

from apps.vulnerable_api.auth import get_current_user
from apps.vulnerable_api.models import User
from apps.vulnerable_api.schemas import UserWithPasswordHash


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserWithPasswordHash)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
