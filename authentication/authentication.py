import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

import jwt
from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from dotenv import load_dotenv

from authentication.models import UserInDB
from authentication.schemas import User, Token, TokenData, RefreshToken
from db_connections import db

load_dotenv()

auth_router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAY = 1
REFRESH_TOKEN_EXPIRE_DAY = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(username: str) -> UserInDB | None:
    user_dict = await db["users"].find_one({"username": username})
    if user_dict:
        user_dict["hashed_password"] = user_dict.pop("hashed_password")
        return UserInDB(**user_dict)
    return None


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None


def create_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=1))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_and_validate_token(token: str, secret_key: str, algorithm: str) -> TokenData:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        return TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    token_data = decode_and_validate_token(token, SECRET_KEY, ALGORITHM)

    user = await get_user(token_data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    return current_user


@auth_router.post("/token", response_model=RefreshToken)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAY)
    access_token = create_token(data={"sub": user.username}, expires_delta=access_token_expires)

    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAY)
    refresh_token = create_token(data={"sub": user.username}, expires_delta=refresh_token_expires)

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@auth_router.post("/refresh_token", response_model=Token)
async def refresh_access_token(refresh_token: str):
    token_data = decode_and_validate_token(refresh_token, SECRET_KEY, ALGORITHM)

    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAY)
    new_access_token = create_token(data={"sub": token_data.username}, expires_delta=access_token_expires)

    return {"access_token": new_access_token, "token_type": "bearer"}

async def check_existing_user(email: str, username: str):
    users = db["users"]
    existing_user = await users.find_one(
        {"username": {"$regex": f"^{username}$", "$options": "i"}}
    )
    existing_email = await users.find_one(
        {"email": {"$regex": f"^{email}$", "$options": "i"}}
    )

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: User):
    users = db["users"]
    await check_existing_user(user.email, user.username)

    hashed_password = get_password_hash(user.password)
    user_data = user.dict()
    user_data["hashed_password"] = hashed_password
    del user_data["password"]

    try:
        await users.insert_one(user_data)
        return {
            "username": user.username,
            "message": "User registered successfully"
        }
    except Exception as exc:
        print("Exception", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occurred during registration."
        )
