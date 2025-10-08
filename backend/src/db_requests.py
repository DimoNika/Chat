from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from sqlalchemy import select, func
from models import Chat, user_chat_association


# environment variables block
from dotenv import load_dotenv
import os
from pathlib import Path

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)


postgre_user = os.getenv("POSTGRES_USER")
postgre_password = os.getenv("POSTGRES_PASSWORD")
postgres_db = os.getenv("POSTGRES_DB")

engine = create_engine(f"postgresql+psycopg2://{postgre_user}:{postgre_password}@db/{postgres_db}", echo=True)




def get_chat_between_users(user1_id: int, user2_id: int):
    """
    This function returnes Chat model if two User's have chat, otherwise None
    """
    with Session(engine) as session:

        subquery = (
            select(user_chat_association.c.chat_id)
            .where(user_chat_association.c.user_id.in_([user1_id, user2_id]))
            .group_by(user_chat_association.c.chat_id)
            .having(func.count(user_chat_association.c.user_id) == 2)
        ).subquery()

        # query to Get Chat
        chat = session.execute(
            select(Chat).where(Chat.id.in_(subquery))
        ).scalars().first()

        return chat

