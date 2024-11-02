from typing import Annotated, Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import RedirectResponse
from jwt import InvalidTokenError

from authentication.authentication import get_current_active_user, get_current_user, oauth2_scheme, SECRET_KEY, \
    ALGORITHM, get_user
from authentication.models import UserInDB
from db_connections import db
from user_profile.serializers import UserResponse

user_router = APIRouter()
@user_router.get("/me", response_model=UserResponse)
async def read_users_me(
        current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    return UserResponse(
        username=current_user.username,
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
    )

async def get_current_user_if_exists(token: Optional[str] = None):
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return await get_user(username)
    except InvalidTokenError:
        return None

@user_router.get("/{username}")
async def get_user_by_username(
        username: str,
        current_user: Optional[UserInDB] = Depends(get_current_user_if_exists)
):
    obj_user = await db["users"].find_one({"username": {"$regex": f"^{username}$", "$options": "i"}})
    if obj_user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    if current_user and current_user.username.lower() == username.lower():
        return RedirectResponse(url="/user/me")

    return UserResponse(
        username=obj_user["username"],
        email=obj_user["email"],
        first_name=obj_user["first_name"],
        last_name=obj_user["last_name"],
    )

@user_router.patch("/me/update")
async def update_user_profile(
        profile_data: UserResponse,
        current_user: Annotated[UserInDB, Depends(get_current_active_user)]
):
    print("user: ", profile_data)
    update_data = profile_data.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No data provided to update"
        )

    if "username" in update_data:
        update_data.pop("username")

    update_data_encoded = jsonable_encoder(update_data)
    await db["users"].update_one(
        {"username": current_user.username},
        {"$set": update_data_encoded}
    )

    return RedirectResponse(url="/user/me")