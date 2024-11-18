from fastapi import FastAPI

from db_connections import lifespan
from authentication.authentication import auth_router
from post.post import post_router
from user_profile.profile import user_router

app = FastAPI(lifespan=lifespan)
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(user_router, prefix="/user", tags=["user"])
app.include_router(post_router, prefix="/post", tags=["post"])


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}
