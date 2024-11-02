from typing import Optional
from pydantic import BaseModel


class UserResponse(BaseModel):
    username: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
