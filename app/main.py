from fastapi import FastAPI, Request, Header, HTTPException, Query
from contextlib import asynccontextmanager
from typing import Optional
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


async def get_user(public_key: str) -> Optional[int]:
    """Retrieves a user's ID by their public key."""
    query = users.select().where(users.c.public_key == public_key)
    user = await database.fetch_one(query)
    if user:
        return user["id"]
    return None


async def get_or_create_user(public_key: str) -> int:
    """
    Retrieves a user's ID by their public key.
    If the user does not exist, it creates a new one.
    """
    user_id = await get_user(public_key)
    if user_id:
        return user_id
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


@app.get("/messages/")
async def get_messages(
    public_key: str,
    since_id: Optional[int] = Query(None, description="Get messages with ID greater than this."),
    until_id: Optional[int] = Query(None, description="Get messages with ID less than this (for reverse order)."),
    limit: int = Query(100, description="Number of messages to retrieve."),
):
    """
    Retrieves messages for a given public key.
    Can be used for forward and reverse chronological order.
    """
    if since_id is not None and until_id is not None:
        raise HTTPException(status_code=400, detail="Cannot use 'since_id' and 'until_id' at the same time.")

    user_id = await get_user(public_key)
    if not user_id:
        return []  # No user, no messages

    # Base query
    query = messages.select().where(
        (messages.c.sender_id == user_id) | (messages.c.recipient_id == user_id)
    )

    if since_id is not None:
        # Forward chronological order (older to newer)
        query = query.where(messages.c.id > since_id).order_by(messages.c.id.asc())
    elif until_id is not None:
        # Reverse chronological order (newer to older)
        query = query.where(messages.c.id < until_id).order_by(messages.c.id.desc())
    else:
        # Default: most recent messages
        query = query.order_by(messages.c.id.desc())

    query = query.limit(limit)

    results = await database.fetch_all(query)

    # If we fetched in reverse, reverse the results back to chronological order for consistency
    if until_id is not None or (since_id is None and until_id is None):
        return list(reversed(results))

    return results
