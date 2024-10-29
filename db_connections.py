import os

from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

mongodb_url = os.getenv("MONGO_URL")
client = AsyncIOMotorClient(mongodb_url)
db = client["SparixHub"]

@asynccontextmanager
async def lifespan(app):
    await startup_db_client(app)
    yield
    await shutdown_db_client(app)


async def startup_db_client(app):
    app.mongodb_client = AsyncIOMotorClient(
        os.getenv("MONGO_URL")
    )
    app.mongodb = app.mongodb_client.get_database("college")


async def shutdown_db_client(app):
    app.mongodb_client.close()
