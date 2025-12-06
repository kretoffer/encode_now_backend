import hashlib
import sqlalchemy
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Header, HTTPException, Query

from .db import database, users, messages, message_hashes, check_and_create_tables

# --- Constants ---
REPLAY_ATTACK_HASH_COUNT = 50


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles application startup and shutdown events."""
    check_and_create_tables()
    await database.connect()
    yield
    await database.disconnect()


app = FastAPI(lifespan=lifespan)


async def get_user(public_key: str) -> Optional[int]:
    """Retrieves a user's ID by their public key."""
    query = users.select().where(users.c.public_key == public_key)
    user = await database.fetch_one(query)
    return user["id"] if user else None


async def get_or_create_user(public_key: str) -> int:
    """Retrieves a user's ID by their public key, creating one if not found."""
    user_id = await get_user(public_key)
    if user_id:
        return user_id
    query = users.insert().values(public_key=public_key)
    return await database.execute(query)


@app.post("/messages/")
async def save_message(
    request: Request,
    x_recipient_public_key: str = Header(...),
    x_sender_public_key: str = Header(...),
):
    """
    Saves an encrypted message and protects against replay attacks.
    """
    ciphertext = await request.body()
    if not ciphertext:
        raise HTTPException(status_code=400, detail="Request body cannot be empty.")

    message_hash = hashlib.sha256(ciphertext).hexdigest()

    try:
        sender_id = await get_or_create_user(x_sender_public_key)
        recipient_id = await get_or_create_user(x_recipient_public_key)

        # Replay attack check
        query = message_hashes.select().where(
            (message_hashes.c.recipient_id == recipient_id) &
            (message_hashes.c.message_hash == message_hash)
        )
        if await database.fetch_one(query):
            raise HTTPException(status_code=409, detail="Duplicate message detected.")

        async with database.transaction():
            # 1. Insert the message
            query = messages.insert().values(
                sender_id=sender_id,
                recipient_id=recipient_id,
                ciphertext=ciphertext,
            )
            message_id = await database.execute(query)

            # 2. Add the new hash for replay protection
            query = message_hashes.insert().values(
                recipient_id=recipient_id, message_hash=message_hash
            )
            await database.execute(query)

            # 3. Clean up old hashes
            count_query = sqlalchemy.select(sqlalchemy.func.count()).select_from(message_hashes).where(
                message_hashes.c.recipient_id == recipient_id
            )
            hash_count = await database.fetch_val(count_query)
            if hash_count > REPLAY_ATTACK_HASH_COUNT:
                oldest_hash_id_query = sqlalchemy.select(message_hashes.c.id).where(
                    message_hashes.c.recipient_id == recipient_id
                ).order_by(message_hashes.c.created_at.asc()).limit(1)
                oldest_hash_id = await database.fetch_val(oldest_hash_id_query)
                if oldest_hash_id:
                    await database.execute(
                        message_hashes.delete().where(message_hashes.c.id == oldest_hash_id)
                    )
        
        return {"message_id": message_id}

    except HTTPException as e:
        raise e  # Re-raise to preserve status code and detail
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save message: {e}")


@app.get("/messages/")
async def get_messages(
    public_key: str,
    since_id: Optional[int] = Query(None, description="Get messages with ID greater than this."),
    until_id: Optional[int] = Query(None, description="Get messages with ID less than this."),
    limit: int = Query(100, description="Number of messages to retrieve."),
):
    """
    Retrieves historical messages for a given public key.
    """
    if since_id is not None and until_id is not None:
        raise HTTPException(status_code=400, detail="Cannot use 'since_id' and 'until_id' at the same time.")

    user_id = await get_user(public_key)
    if not user_id:
        return []

    query = messages.select().where(
        (messages.c.sender_id == user_id) | (messages.c.recipient_id == user_id)
    )

    if since_id is not None:
        query = query.where(messages.c.id > since_id).order_by(messages.c.id.asc())
    elif until_id is not None:
        query = query.where(messages.c.id < until_id).order_by(messages.c.id.desc())
    else:
        query = query.order_by(messages.c.id.desc())

    query = query.limit(limit)
    results = await database.fetch_all(query)

    # Reverse results if needed to maintain chronological order
    if until_id is not None or (since_id is None and until_id is None):
        return [dict(row) for row in reversed(results)]

    return [dict(row) for row in results]
