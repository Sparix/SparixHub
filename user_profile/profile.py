from datetime import datetime
from typing import Annotated, Optional

import jwt
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.encoders import jsonable_encoder
from fastapi.responses import RedirectResponse
from jwt import InvalidTokenError

from authentication.authentication import (
    get_current_active_user,
    SECRET_KEY,
    ALGORITHM,
    get_user
)
from authentication.models import UserInDB
from db_connections import db
from user_profile.models import FriendRequestDB
from user_profile.schemas import UserResponse, FriendRequestSchema, FriendResponse, UserResponseFriends

user_router = APIRouter()


@user_router.get("/me", response_model=UserResponseFriends)
async def read_users_me(
        current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    return UserResponseFriends(
        username=current_user.username,
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        friend_list=current_user.friend_list,
    )


async def get_current_user_if_exists(token: Optional[str] = Header(None, alias="Authorization")):
    if not token:
        return None
    try:
        payload = jwt.decode(token.split()[1], SECRET_KEY, algorithms=[ALGORITHM])
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

    return UserResponseFriends(
        username=obj_user["username"],
        email=obj_user["email"],
        first_name=obj_user["first_name"],
        last_name=obj_user["last_name"],
        friend_list=obj_user["friend_list"],
    )


@user_router.patch("/me/update")
async def update_user_profile(
        profile_data: UserResponse,
        current_user: Annotated[UserInDB, Depends(get_current_active_user)]
):
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


@user_router.post("/friends/request/")
async def send_friend_request(
    friend_request: FriendRequestSchema,
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    receiver_username = friend_request.friend_username
    existing_request = await db["friend_requests"].find_one({
        "sender_username": current_user.username,
        "receiver_username": receiver_username
    })
    if existing_request:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Friend request already sent"
        )

    if receiver_username in current_user.friend_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You already connected with this friend"
        )

    friend_request_in_db = {
        "sender_username": current_user.username,
        "receiver_username": receiver_username,
        "status": "pending",
        "created_at": datetime.utcnow()
    }

    await db["friend_requests"].insert_one(friend_request_in_db)
    return {"message": "Friend request sent!"}

@user_router.post("/friends/accept/")
async def accept_friend_request(
    friend_request: FriendRequestSchema,
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    sender_username = friend_request.friend_username

    friend_request_db = await db["friend_requests"].find_one({
        "sender_username": sender_username,
        "receiver_username": current_user.username
    })
    if not friend_request_db:
        raise HTTPException(status_code=404, detail="Friend request not found")

    await db["friend_requests"].update_one(
        {"sender_username": sender_username, "receiver_username": current_user.username},
        {"$set": {"status": "accepted"}}
    )

    await db["users"].update_one(
        {"username": sender_username},
        {"$addToSet": {"friend_list": current_user.username}}
    )
    await db["users"].update_one(
        {"username": current_user.username},
        {"$addToSet": {"friend_list": sender_username}}
    )

    return {"message": "Friend request accepted!"}

@user_router.get("/friends/request/list/")
async def list_friend_requests(
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    obj_friend_requests = await db["friend_requests"].find({
        "receiver_username": current_user.username,
        "status": "pending"
    }).sort("created_at", 1).to_list(length=None)

    if not obj_friend_requests:
        return {"message": "You don't have any friend request!"}

    friend_requests = list()

    for obj_friend_request in obj_friend_requests:
        sender_username = obj_friend_request["sender_username"]
        receiver_username = obj_friend_request["receiver_username"]

        sender = await db["users"].find_one({"username": sender_username})
        receiver = await db["users"].find_one({"username": receiver_username})

        if not sender or not receiver:
            continue

        sender_response = UserResponse(
            username=sender["username"],
            email=sender.get("email"),
            first_name=sender.get("first_name"),
            last_name=sender.get("last_name")
        )

        receiver_response = UserResponse(
            username=receiver["username"],
            email=receiver.get("email"),
            first_name=receiver.get("first_name"),
            last_name=receiver.get("last_name")
        )

        friend_requests.append(FriendResponse(
            sender=sender_response,
            receiver=receiver_response,
            created_at=obj_friend_request["created_at"],
        ))

    return friend_requests
