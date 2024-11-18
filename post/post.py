from typing import Annotated, List

from fastapi import APIRouter, Depends, HTTPException, status

from authentication.authentication import (
    get_current_active_user,
)
from authentication.models import UserInDB
from db_connections import db
from post.models import PostInDB
from post.schemas import PostForm, PostModelResponse
from user_profile.schemas import UserResponse

post_router = APIRouter()

@post_router.post("/create")
async def create_post(
        postData: PostForm,
        current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    post_data = postData.dict()
    post_data["author"] = current_user.username
    if not post_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No data provided to create post"
        )

    post_in_db = PostInDB(**post_data)

    try:
        await db["posts"].insert_one(post_in_db.dict(exclude={"id"}))
        return {
            "message": "Post successfully created",
        }
    except Exception as exc:
        print(exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occurred during created post."
        )


@post_router.get("/view", response_model=List[PostModelResponse])
async def view_post():
    posts_cursor = db["posts"].find()
    posts = await posts_cursor.to_list(length=None)

    enriched_posts = []
    for post in posts:
        author_username = post["author"]
        user = await db["users"].find_one({"username": author_username})

        if user:
            author_data = UserResponse(
                username=user["username"],
                email=user.get("email"),
                first_name=user.get("first_name"),
                last_name=user.get("last_name")
            )

            post_data = {
                **post,
                "id": str(post["_id"]),
                "author": author_data
            }

            enriched_posts.append(PostModelResponse(**post_data))

    return enriched_posts

