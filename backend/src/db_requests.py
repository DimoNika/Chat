from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
# from sqlalchemy.orm import Session
# from sqlalchemy.orm import Session
from sqlalchemy import select, func
from models import Chat, user_chat_association  # твой файл с моделями

engine = create_engine(f"postgresql+psycopg2://myuser:mypassword@db/mydatabase", echo=True)
# Session = sessionmaker(engine)
# session = Session()


# def get_chat_between_users(session: Session, user1_id: int, user2_id: int):
def get_chat_between_users(user1_id: int, user2_id: int):
    # Составляем подзапрос: chat_id, у которых участвуют оба пользователя
    with Session(engine) as session:

        subquery = (
            select(user_chat_association.c.chat_id)
            .where(user_chat_association.c.user_id.in_([user1_id, user2_id]))
            .group_by(user_chat_association.c.chat_id)
            .having(func.count(user_chat_association.c.user_id) == 2)
        ).subquery()

        # Основной запрос: получить сам объект Chat
        chat = session.execute(
            select(Chat).where(Chat.id.in_(subquery))
        ).scalars().first()  # .first() вернёт первый найденный чат или None

        return chat

# def get_chat_between_users(session: Session, user1_id: int, user2_id: int) -> Chat | None:
#     """
#     Возвращает чат между двумя пользователями.
#     Если такого чата нет, возвращает None.
#     """

#     # Подзапрос: chat_id, где участвуют оба пользователя
#     subquery = (
#         select(user_chat_association.c.chat_id)
#         .where(user_chat_association.c.user_id.in_([user1_id, user2_id]))
#         .group_by(user_chat_association.c.chat_id)
#         .having(func.count(user_chat_association.c.user_id) == 2)
#     ).subquery()

#     # Основной запрос: получить объект Chat
#     chat = session.execute(
#         select(Chat).where(Chat.id.in_(subquery))
#     ).scalars().first()

#     return chat