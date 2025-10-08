from models import User, Message, Chat

from src.token_managment import create_refresh_token, create_access_token, auth, decode
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile, Form
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, Session

from schemas import UserLogin, UserSignup
from pydantic import ValidationError

from passlib.hash import pbkdf2_sha256

from src.db_requests import get_chat_between_users

from datetime import datetime

import os

from uuid import uuid4

from pathlib import Path
from dotenv import load_dotenv


env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(env_path)

# environment variables block
postgre_user = os.getenv("POSTGRES_USER")
postgre_password = os.getenv("POSTGRES_PASSWORD")
postgres_db = os.getenv("POSTGRES_DB")

engine = create_engine(f"postgresql+psycopg2://{postgre_user}:{postgre_password}@db/{postgres_db}", echo=True)

app = FastAPI()


UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class ConnectionManager:
    """This manager stores all websockets that connected"""
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    def add(self, user_id, websocket: WebSocket):
        self.active_connections.update({user_id: websocket})


    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except AttributeError as e:
            # If AttributeError means other user in chat not connected, its ok. Nothing happends
            pass
        except Exception as e:
            print(f"Un expected ERROR in ConnectionManager.send_personal_message(): {str(e)}")

connection_manager = ConnectionManager()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Middleware authorizes users on protected endpoints"""

    if request.url.path in ["/login", "/signup", "/test" , "/refresh"]:
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Missing token"})

    token = auth_header.split(" ")[1]
    
    if not auth(token):
        return JSONResponse(status_code=401, content={"detail": "Invalid token"})
    payload = decode(token)
    
    # Save user to state obj to pass it
    request.state.user = payload["username"]

    response = await call_next(request)
    return response


@app.post("/login")
async def login(request: Request):
    """Public endpoint for logging in users"""
    body = await request.json()
    
    user_creds = UserLogin(**body)  # Serialize manulally
    

    with Session(engine) as session:

        if user := session.query(User).where(User.user_tag==user_creds.username.lower()).first():
            if pbkdf2_sha256.verify(user_creds.password, user.password):

                refresh_token = create_refresh_token({"username": user.username, "user_id": user.id})
                access_token = create_access_token({"username": user.username, "user_id": user.id})

                #  Set-Cookie in response
                response = JSONResponse(content={"access_token": access_token, "detail": "User logged in successfuly"})
                response.set_cookie(
                    key="refresh_token",
                    value=refresh_token,
                    httponly=True,
                    max_age=4_320_000,
                    samesite="Strict",
                    secure=True
                )
                return response
            
        return JSONResponse(status_code=404, content={"detail": "Invalid credentials"})


@app.post("/signup")
async def signup(request: Request):
    """Public endpoint for singing up users"""

    try:
        body = await request.json()
        
        user = UserSignup(**body)  # Serialize manulally
        
    except ValidationError as validation_error:
        validation_error : ValidationError
        
        for err in validation_error.errors():
            if err['loc'][0] == "username":
                return JSONResponse(status_code=422, content={"detail": "Wrong username."})
            elif err['loc'][0] == "password1":
                return JSONResponse(status_code=422, content={"detail": str(err["ctx"]["error"])})
        
    # Check if passwords are same
    if user.password1 != user.password2:    
        return JSONResponse(status_code=400, content={"detail": "Passwords do not match"})
    
    with Session(engine) as session:
        # Check if username taken
        if session.query(User).where(User.user_tag == user.username.lower()).first():
            return JSONResponse(status_code=409, content={"detail": "Username already taken"})
        else:
            # tokens...
            new_user = User(user.username, user.username.lower(), pbkdf2_sha256.hash(user.password1))
            session.add(new_user)
            session.commit()
            session.refresh(new_user)


            refresh_token = create_refresh_token({"username": new_user.username, "user_id": new_user.id})
            access_token = create_access_token({"username": new_user.username, "user_id": new_user.id})
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
    """
    User enters here if only he has valid access_token.
    Protected endpoint.
    """
    return JSONResponse(content={"detail": "User authenticated", "auth": True})

@app.get("/refresh")
async def refresh_endpoint(request: Request):
    """
    Refreshes access_token if refresh_token valid
    """

    if auth(refresh_token := request.cookies["refresh_token"]):
        refresh_token_data = decode(refresh_token)
        new_access_token = create_access_token({"username": refresh_token_data["username"], "user_id": refresh_token_data["user_id"]})

    return JSONResponse(content={"detail": "Access token refreshed", "access_token": new_access_token})


@app.post("/find-user")
async def find_user(request: Request):
    """Protected endpoint for finding users for chatting"""
    data = await request.json() 
        
    with Session(engine) as session:

        if other_user:= session.query(User).where(User.user_tag==data["username"].lower()).first():
            this_user = session.query(User).filter_by(username=request.state.user).first()

            if get_chat_between_users(this_user.id, other_user.id):
                return JSONResponse(content={'detail': "Users have chat alredy"}, status_code=404)

            return JSONResponse(content={
                "user_id": other_user.id,
                'username': other_user.username,
                })
        else:
            return JSONResponse(content={'detail': "User not found"}, status_code=404)


@app.post("/upload")
async def upload_files(request: Request, files: list[UploadFile] = File(...), selectedUserId: str = Form(...)):
    """Protected endpoint for uploading files"""
    with Session(engine) as session:

        file_urls = []        
        user = session.query(User).filter_by(username=request.state.user).first()
        
        try:
            for file in files:
                sys_filename = str(uuid4()) + file.filename
                file_path = os.path.join(UPLOAD_DIR, sys_filename)

                with open(file_path, "wb") as f:
                    f.write(await file.read())

                new_message = Message(chat_id=int(selectedUserId), sender_id=user.id, text="")
                new_message.message_type = "file"

                new_message.file_size = file.size  # bytes
                new_message.file_name = file.filename
                new_message.file_type = file.content_type
                new_message.file_url = sys_filename
                chat = get_chat_between_users(user.id, int(selectedUserId))

                new_message.chat_id = chat.id

                session.add(new_message)
                session.commit()
                session.refresh(new_message)
                this_user_websocket = connection_manager.active_connections.get(user.id)
                other_user_websocket = connection_manager.active_connections.get(int(selectedUserId))

                data = {
                    "message_obj": new_message.to_dict(),
                    "type": "message",
                    "file_size": new_message.file_size,
                    "file_name": new_message.file_name,
                    "file_type":  new_message.file_type,
                    "file_url":  new_message.file_url,
                    
                    "sender_username": user.username,
                    "receiver_id": int(selectedUserId),

                    "is_own_message": False,
                }
                
                await connection_manager.send_personal_message(data, other_user_websocket)
                
                data["is_own_message"] = True
                await connection_manager.send_personal_message(data, this_user_websocket)
                
            return JSONResponse(content={"files": file_urls})
        except Exception as e:
            print(f"Error: in uploading files {str(e)}")


@app.get("/chats-list")
async def chats_list(request: Request):
    """Protected endpoing to fetch all users exiting chats and messages"""

    with Session(engine) as session:
        user = session.query(User).filter_by(username=request.state.user).first()

        response_data = []

        for chat in user.chats:
            
            other_user_username = ''
            for chatter in chat.users:
                chatter: User
                if chatter.username != user.username:
                    other_user_username = chatter.username
                    other_user_id = chatter.id
            # Last message by sent_at
            last_message = (
                session.query(Message)
                .filter(Message.chat_id == chat.id)
                .filter(Message.is_deleted == False)
                .order_by(Message.sent_at.desc())
                .first()
            )
            
            
            messages_data = []
            for msg in session.query(Message).filter(Message.chat_id == chat.id).filter(Message.is_deleted == False).order_by(Message.sent_at.asc()).all():
                
                if msg.message_type == "text":
                    messages_data.append({
                        "id": msg.id,
                        "type": "text",
                        "sender_id": msg.sender_id,
                        "text": msg.text,
                        "time": str(msg.sent_at),
                        "isDeleted": msg.is_deleted,
                        "editedAt": str(msg.edited_at) if msg.edited_at else "",

                        "fromMe": True if user.id == msg.sender_id else False
                    })
                elif msg.message_type == "file":
                    messages_data.append({
                        "id": msg.id,
                        "type": "file",
                        "sender_id": msg.sender_id,
                        "text": msg.text,
                        "time": str(msg.sent_at),
                        "isDeleted": msg.is_deleted,
                        "editedAt": str(msg.edited_at) if msg.edited_at else "",

                        "fromMe": True if user.id == msg.sender_id else False,
                        "file_size": msg.file_size,
                        "file_name": msg.file_name,
                        "file_type":  msg.file_type,
                        "file_url":  msg.file_url,
                    })
                    
            data = {
                "id": other_user_id,
                "title": other_user_username,
                "lastMessage": {
                    "id": last_message.id if last_message else 0,
                    "type": last_message.message_type if last_message else "text",
                    "fromMe": last_message.sender_id == user.id if last_message else False,
                    "text": last_message.text if last_message else "",
                    "time": str(last_message.sent_at) if last_message else ""
                },
                "unread": 1,
                "messages": messages_data
            }
            response_data.append(data)
        
        def by_time(chat):
            return chat["lastMessage"]["time"]

        response_data.sort(key=by_time, reverse=True)
        
        return JSONResponse(content={"chats_list": response_data, "your_username": user.username})




@app.websocket("/chat")
async def websocket_endpoint(websocket: WebSocket):
    """
    When client opens conncection it sends json with access_token,
    then server authenticates it.

    If Authenticated receives messages and sends to chatters

    If not Authenticated closes connection
    """
    await websocket.accept()

    # Authenticate connection
    data: dict= await websocket.receive_json()
    
    token = data.get("access_token")
    
    token_data = decode(token)
    
    this_user_id = token_data.get("user_id")
    with Session(engine) as session:
        try:
            # Authenticate
            if auth(token):
                connection_manager.add(token_data["user_id"], websocket)

                while True:
                    # receiveing message
                    message: dict = await websocket.receive_json()
                    other_user_id = message["selectedUserId"]
                    
                    
                    stmt = select(User).where(User.id == other_user_id)
                    other_user = session.execute(stmt).scalars().first()

                    this_user: User = session.query(User).filter_by(id=this_user_id).first()
                    
                    # If adresat dont exist
                    if not other_user:
                        continue

                    chat = get_chat_between_users(this_user_id, other_user_id)
                    
                    if chat:
                        #  IF TYPE OF MESSAGE IS REGULAR MESSAGE
                        if message["type"] == "message":

                            new_message = Message(chat.id, this_user.id, message.get("message"))
                            other_user_websocket = connection_manager.active_connections.get(other_user_id)
                            try:
                                print(connection_manager.active_connections, "active connctions")
                                session.add(new_message)
                                session.commit()
                                session.refresh(new_message)
                            
                                data = {
                                    "message_obj": new_message.to_dict(),
                                    "type": "message",
                                    "sender_username": this_user.username,
                                    "receiver_id": other_user_id,

                                    "is_own_message": False,
                                }

                                # This sent to the receiver
                                await connection_manager.send_personal_message(data, other_user_websocket)    
                                # Send to the sender
                                data["is_own_message"] = True
                                await websocket.send_json(data)
                            except Exception as e:
                                print(f"Error here: {str(e)}")

                        # IF TYPE OF MESSAGE IS EDIT_MESSAGE
                        elif message["type"] == "edit_message":
                            message_entity: Message = session.query(Message).filter_by(id=message["messageID"]).first()

                            # if message owner is this user
                            if message_entity.sender_id == this_user.id:
                                message_entity.text = message["message"]
                                
                                message_entity.edited_at = datetime.now()
                                session.commit()
                                session.refresh(message_entity)
                            else:
                                print("User does not own this message")
                            
                            data = {
                                "type": "edit_message",
                                "id": message_entity.id,
                                "text": message_entity.text,
                                "edited_at": str(message_entity.edited_at),
                            }

                            # This sent to the receiver
                            if other_user_websocket:= connection_manager.active_connections.get(other_user.id):
                                await connection_manager.send_personal_message(data, other_user_websocket)

                            # Send to the sender
                            await websocket.send_json(data)
                        
                        # IF TYPE OF MESSAGE IS DELETE_MESSAGE
                        elif message["type"] == "delete_message":
                            message_entity: Message = session.query(Message).filter_by(id=message["messageID"]).first()

                            # if message owner is this user
                            if message_entity.sender_id == this_user.id:
                                message_entity.is_deleted = True
                                session.commit()
                                session.refresh(message_entity)
                            else:
                                print("User does not own this message")
                            
                            data = {
                                "type": "delete_message",
                                "id": message_entity.id,
                            }

                            if other_user_websocket:= connection_manager.active_connections.get(other_user.id):
                                await connection_manager.send_personal_message(data, other_user_websocket)

                            await websocket.send_json(data)

                    else:
                        # if chat NOT exists between those users, then we create it
                        try:

                            new_chat = Chat()
                            
                            new_chat.users = [this_user, other_user]
                        
                            session.add(new_chat)
                            session.commit()
                            session.refresh(new_chat)
                            

                            # Chat created, then send message itself
                            new_message = Message(new_chat.id, this_user.id, message.get("message"))
                            
                            session.add(new_message)
                            session.commit()
                            session.refresh(new_message)

                            data = {
                                "message_obj": new_message.to_dict(),
                                "type": "message",
                                "sender_username": this_user.username,
                                "receiver_id": other_user_id,

                                "is_own_message": False,
                                
                            }

                            # send other user message
                            if other_user_websocket:= connection_manager.active_connections.get(other_user.id):
                                await connection_manager.send_personal_message(data, other_user_websocket)

                            data["is_own_message"] = True
                            # send to sender user message
                            await websocket.send_json(data)

                        except Exception as e:
                            print(f"Exception in creating new chat: {e}")


                    
        except WebSocketDisconnect as e:
            print(f"User disconnected")

        except Exception as e:
            print(f"Error: Unknow exception occured in chat-service /ws endpoint: {str(e)}")
        
        else:
            websocket.close()