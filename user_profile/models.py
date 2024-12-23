from datetime import datetime

from pydantic import BaseModel, Field


class FriendRequestDB(BaseModel):
    sender_username: str
    receiver_username: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.now)