from datetime import datetime
from typing import Annotated, List, Dict

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.encoders import jsonable_encoder
from starlette.responses import RedirectResponse

from authentication.authentication import (
    get_current_active_user,
)
from authentication.models import UserInDB
from db_connections import db
from post.models import PostInDB, LikeDislikeInDB
from post.schemas import PostForm, PostModelResponse, TypeLike
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


@post_router.patch("/edit/{id_post}")
async def edit_post(
        id_post: str,
        post_data: PostForm,
        current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    edit_post_data = post_data.dict(exclude_unset=True)
    if not edit_post_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No data provided to update"
        )

    updated_post = await db["posts"].find_one_and_update(
        {
            "_id": ObjectId(id_post),
            "author": current_user.username
        },
        {
            "$set": {
                **jsonable_encoder(edit_post_data),
                "updated_at": datetime.utcnow()
            }
        },
        return_document=True
    )

    if not updated_post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found or you are not the author."
        )

    return RedirectResponse(url="/view", status_code=status.HTTP_303_SEE_OTHER)

@post_router.get("/detail/{id_post}")
async def detail_post(
        id_post: str,
):
      post = await db["posts"].find_one({"_id": ObjectId(id_post)})
      if not post:
          raise HTTPException(
              status_code=status.HTTP_404_NOT_FOUND,
              detail="Post not found."
          )
      author_data = await db["users"].find_one({"username": post["author"]})
      post_data = {
          **post,
          "id": str(post["_id"]),
          "author": author_data
      }
      return PostModelResponse(**post_data)

@post_router.post("/like-dislike/create/{id_post}")
async def like_dislike_post(
    id_post: str,
    type_like: TypeLike,
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    post = await db["posts"].find_one({"_id": ObjectId(id_post)})
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found."
        )

    existing_reaction = await db["post_reactions"].find_one({
        "post_id": id_post,
        "user_username": current_user.username
    })

    if existing_reaction:
        await db["post_reactions"].update_one(
            {"_id": existing_reaction["_id"]},
            {
                "$set": {
                    "type": type_like.type,
                    "updated_at": datetime.utcnow(),
                }
            }
        )
        message = "Reaction updated."
    else:
        new_reaction = LikeDislikeInDB(**{
            "post_id": id_post,
            "user_username": current_user.username,
            "type": type_like.type,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })

        await db["post_reactions"].insert_one(new_reaction.dict())
        message = "Reaction created."

    return {"message": message}


@post_router.get("/{post_id}/likes-dislikes")
async def get_likes_dislikes_count(post_id: str) -> Dict[str, int]:
    like = await db["post_reactions"].count_documents({"post_id": post_id, "type": "like"})
    dislike = await db["post_reactions"].count_documents({"post_id": post_id, "type": "dislike"})
    return {"likes": like, "dislikes": dislike}
