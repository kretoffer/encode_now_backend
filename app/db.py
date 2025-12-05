import sqlalchemy
from sqlalchemy import inspect
from databases import Database
from decouple import config


DATABASE_URL = config("DATABASE_URL")


database = Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()


users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("public_key", sqlalchemy.Text, unique=True, nullable=False),
)


messages = sqlalchemy.Table(
    "messages",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.BigInteger, primary_key=True),
    sqlalchemy.Column("sender_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False),
    sqlalchemy.Column("recipient_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False),
    sqlalchemy.Column("ciphertext", sqlalchemy.LargeBinary, nullable=False),
)


# Engine for creating tables
engine = sqlalchemy.create_engine(DATABASE_URL)


def check_and_create_tables():
    """Checks if the required tables exist and creates them if they don't."""
    inspector = inspect(engine)
    required_tables = {"users", "messages"}
    existing_tables = set(inspector.get_table_names())

    if not required_tables.issubset(existing_tables):
        print("One or more tables are missing. Creating all tables...")
        metadata.create_all(bind=engine)
        print("Tables created successfully.")
    else:
        print("Tables already exist.")
