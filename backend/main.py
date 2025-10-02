from models import User, Message, Chat


from fastapi import FastAPI

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine(f"postgresql+psycopg2://myuser:mypassword@localhost/mydatabase", echo=True)
Session = sessionmaker(engine)
session = Session()

app = FastAPI()

@app.get("/test")
async def main():
    return "hello world hehe"



