from sqlalchemy import Column, DateTime, String, Integer, func, ForeignKey, Boolean, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base



Base = declarative_base()
metadata = Base.metadata


#  === User-service models ===

user_chat_association = Table(
    "user_chat_association",
    Base.metadata,
    Column("user_id", ForeignKey("user.id"), primary_key=True),
    Column("chat_id", ForeignKey("chat.id"), primary_key=True),
)


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    user_tag = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=func.now())
    password = Column(String(256), nullable=False)  # hashed password

    chats = relationship(
        "Chat",
        secondary=user_chat_association,
        back_populates="users"
    )

    
    def __init__(self, username: str, user_tag: str, password: str):
        self.username = username
        self.user_tag = user_tag.lower()
        self.password = password


    def __repr__(self):
        return f"Username: {self.username}, created_at: {self.created_at}"


class Chat(Base):
    __tablename__ = "chat"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=func.now())

    
    users = relationship(
        "User",
        secondary=user_chat_association,
        back_populates="chats"
    )


class Message(Base):
    __tablename__ = "message"
    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey("chat.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    sent_at = Column(DateTime, default=func.now())
    text = Column(String(4096), nullable=True)
    is_deleted = Column(Boolean, default=False)
    edited_at = Column(DateTime, default=None)

    # Message type: "text" | "file"
    message_type = Column(String, default="text")

    # File
    file_url = Column(String, nullable=True, default=None)   # path /uploads/file.pdf
    file_name = Column(String, nullable=True, default=None)  # filename
    file_type = Column(String, nullable=True, default=None)  # file type .pdf
    file_size = Column(Integer, nullable=True, default=None) # size in bytes

    def __init__(self, chat_id, sender_id, text):
        self.chat_id = chat_id
        self.sender_id = sender_id
        self.text = text
    
    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "type":         self.message_type,
            "chat_id":      self.chat_id,
            "sender_id":    self.sender_id,
            "sent_at":      str(self.sent_at),
            "text":         self.text,
            "is_deleted":   self.is_deleted,
            "edited_at":    str(self.edited_at) if self.edited_at else "",
        }
