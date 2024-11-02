from bson import ObjectId
from pydantic import BaseModel, Field
from typing import Optional


class UserInDB(BaseModel):
    id: ObjectId = Field(default_factory=ObjectId)
    username: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    hashed_password: str

    class Config:
        arbitrary_types_allowed = True
