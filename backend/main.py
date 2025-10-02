from models import User, Message, Chat

from src.token_managment import create_refresh_token, create_access_token, auth
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from schemas import UserLogin, UserSignup
from pydantic import ValidationError

from passlib.hash import pbkdf2_sha256

engine = create_engine(f"postgresql+psycopg2://myuser:mypassword@db/mydatabase", echo=True)
Session = sessionmaker(engine)
session = Session()

app = FastAPI()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Игнорируем авторизацию для публичных роутов
    if request.url.path in ["/login", "/signup", "/test"]:
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    print(request.headers)
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Missing token"})

    token = auth_header.split(" ")[1]
    print(token)
    print(auth(token))

    if not auth(token):
        return JSONResponse(status_code=401, content={"detail": "Invalid token"})

    response = await call_next(request)
    return response


@app.get("/test")
async def main():
    return "hello world hehe"


@app.post("/login")
async def login(request: Request):

    return await request.body()


@app.post("/signup")
async def signup(request: Request):

    try:
        body = await request.json()
        user = UserSignup(**body)  # Serialize manulally
        if user.password1 != user.password2:
            return JSONResponse(status_code=400, content={"detail": "Passwords do not match"})
    
    except ValidationError as validation_error:
        validation_error : ValidationError
        return JSONResponse(status_code=422, content={"detail": "Invalid credentials"})
    
    if session.query(User).where(User.username==user.username).first():
        return JSONResponse(status_code=409, content={"detail": "Username already taken"})
    else:
        # tokens...
        new_user = User(user.username, pbkdf2_sha256.hash(user.password1))
        session.add(new_user)
        session.commit()


        refresh_token = create_refresh_token({"username": new_user.username})
        access_token = create_access_token({"username": new_user.username})
        #  Set-Cookie in response
        response = JSONResponse(content={"access_token": access_token})
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            max_age=4_320_000,
            samesite="Strict",
            secure=True
        )

    return response

@app.get("/auth")
async def auth_endpoint():
    return True