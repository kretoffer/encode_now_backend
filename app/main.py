from fastapi import FastAPI, Request, Header, HTTPException
from contextlib import asynccontextmanager
from .db import database, users, messages, check_and_create_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code that runs on startup
    check_and_create_tables()
    await database.connect()
    yield
    # Code that runs on shutdown
    await database.disconnect()


app = FastAPI(lifespan=lifespan)


async def get_or_create_user(public_key: str) -> int:
    """
    Retrieves a user's ID by their public key.
    If the user does not exist, it creates a new one.
    """
    query = users.select().where(users.c.public_key == public_key)
    user = await database.fetch_one(query)
    if user:
        return user["id"]
    else:
        query = users.insert().values(public_key=public_key)
        user_id = await database.execute(query)
        return user_id


@app.post("/messages/")
async def save_message(
    request: Request,
    x_recipient_public_key: str = Header(...),
    x_sender_public_key: str = Header(...),
):
    """
    Saves an encrypted message to the database.
    """
    ciphertext = await request.body()
    if not ciphertext:
        raise HTTPException(status_code=400, detail="Request body cannot be empty.")

    try:
        # Get or create sender and recipient
        sender_id = await get_or_create_user(x_sender_public_key)
        recipient_id = await get_or_create_user(x_recipient_public_key)

        # Insert the message
        query = messages.insert().values(
            sender_id=sender_id,
            recipient_id=recipient_id,
            ciphertext=ciphertext,
        )
        message_id = await database.execute(query)

        return {"message_id": message_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save message: {e}")
