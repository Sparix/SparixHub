from datetime import datetime

from bson import ObjectId
from pydantic import BaseModel, Field
from typing import Optional, List

from user_profile.schemas import UserResponse


class PostInDB(BaseModel):
    id: str = Field(default_factory=lambda: str(ObjectId()))
    author: str
    content: Optional[str]
    image: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    count_like: int = Field(default=0)
    count_dislike: int = Field(default=0)
    comments_count: int = Field(default=0)
    is_published: bool = Field(default=True)
    tags: Optional[List[str]] = Field(default_factory=list)

    class Config:
        arbitrary_types_allowed = True
