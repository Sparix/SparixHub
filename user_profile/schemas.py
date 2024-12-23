from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class UserResponse(BaseModel):
    username: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class UserResponseFriends(UserResponse):
    friend_list: Optional[list] = None

class FriendRequestSchema(BaseModel):
    friend_username: str

class FriendResponse(BaseModel):
    sender: UserResponse
    receiver: UserResponse
    created_at: datetime = Field(default_factory=datetime.utcnow)