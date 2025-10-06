from models import User, Message, Chat

from src.token_managment import create_refresh_token, create_access_token, auth, decode
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, Session

from schemas import UserLogin, UserSignup
from pydantic import ValidationError

from passlib.hash import pbkdf2_sha256

from src.db_requests import get_chat_between_users

engine = create_engine(f"postgresql+psycopg2://myuser:mypassword@db/mydatabase", echo=True)
# Session = sessionmaker(engine)
# session = Session()

app = FastAPI()

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    def add(self, user_id, websocket: WebSocket):
        self.active_connections.update({user_id: websocket})

    # def disconnect(self, websocket: WebSocket):
    #     # ???
    #     self.active_connections.pop(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except AttributeError as e:
            # If AttributeError means other user in chat not connected, its ok. Nothing happends
            pass
        except Exception as e:
            print(f"Un expected ERROR in ConnectionManager.send_personal_message(): {str(e)}")
            

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Игнорируем авторизацию для публичных роутов
    if request.url.path in ["/login", "/signup", "/test" , "/refresh"]:
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    # print(request.headers)
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Missing token"})

    token = auth_header.split(" ")[1]
    # print(token)
    # print(auth(token))

    if not auth(token):
        return JSONResponse(status_code=401, content={"detail": "Invalid token"})
    payload = decode(token)
    print(payload)
    # Сохраняем пользователя в request.state
    request.state.user = payload["username"]  # например, user_id

    response = await call_next(request)
    return response


@app.get("/test")
async def main():
    return "hello world hehe"


@app.post("/login")
async def login(request: Request):
    body = await request.json()
    # print(body)
    user_creds = UserLogin(**body)  # Serialize manulally
    # print(user)

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

    try:
        body = await request.json()
        # print(body)
        user = UserSignup(**body)  # Serialize manulally
        # print(user)
        # print("hello world")
    
    except ValidationError as validation_error:
        validation_error : ValidationError
        # print(validation_error)
        # print(str(validation_error) + "ALO")
        # print(validation_error.title)
        
        for err in validation_error.errors():
            if err['loc'][0] == "username":
                return JSONResponse(status_code=422, content={"detail": "Wrong username."})
            elif err['loc'][0] == "password1":
                print(err)
                print(err["ctx"]["error"])
                
                return JSONResponse(status_code=422, content={"detail": str(err["ctx"]["error"])})
                # return JSONResponse(status_code=422, content={"detail": "Password pattern missmatch."})
            
    if user.password1 != user.password2:    
        return JSONResponse(status_code=400, content={"detail": "Passwords do not match"})
    with Session(engine) as session:
    

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
    User enters here if only he has valid access_token
    """
    return JSONResponse(content={"detail": "User authenticated", "auth": True})

@app.get("/refresh")
async def refresh_endpoint(request: Request):
    """
    Refreshes access_token if refresh_token valid
    """

    # print(request.cookies)
    if auth(refresh_token := request.cookies["refresh_token"]):
        refresh_token_data = decode(refresh_token)
        new_access_token = create_access_token({"username": refresh_token_data["username"], "user_id": refresh_token_data["user_id"]})

    return JSONResponse(content={"detail": "Access token refreshed", "access_token": new_access_token})


@app.post("/find-user")
async def find_user(request: Request):
    data = await request.json() 
    print(await request.json())
    # TODO: check if users alredy have chat
    with Session(engine) as session:

        if user:= session.query(User).where(User.user_tag==data["username"].lower()).first():
            return JSONResponse(content={
                "user_id": user.id,
                'username': user.username,
                })
        else:
            return JSONResponse(content={'detail': "User not found"}, status_code=404)
            # return await request.json()


@app.get("/chats-list")
async def chats_list(request: Request):

    with Session(engine) as session:
        user = session.query(User).filter_by(username=request.state.user).first()

        response_data = []

        for chat in user.chats:
            # print(chat, "hello w")
            other_user_username = ''
            for chatter in chat.users:
                chatter: User
                if chatter.username != user.username:
                    other_user_username = chatter.username
                    other_user_id = chatter.id
            # Последнее сообщение по дате
            last_message = (
                session.query(Message)
                .filter(Message.chat_id == chat.id)
                .order_by(Message.sent_at.desc())
                .first()
            )
            
            print(last_message.sent_at, "flex")
            print(last_message.text, "flex")
            messages_data = []
            for msg in session.query(Message).filter(Message.chat_id == chat.id).order_by(Message.sent_at.asc()).all():
                messages_data.append({
                    "id": str(msg.id),
                    "sender_id": msg.sender_id,
                    "text": msg.text,
                    "time": str(msg.sent_at),
                    "is_deleted": msg.is_deleted,
                    "edited_at": msg.edited_at if str(msg.edited_at) else None,

                    "fromMe": user.id == msg.sender_id if True else False
                })
            
            data = {
                "id": other_user_id,
                "title": other_user_username,
                "lastMessage": {
                    "id": last_message.id,
                    "from_me": last_message.sender_id == user.id if True else False,
                    "text": last_message.text,
                    "time": str(last_message.sent_at)
                },
                "unread": 1,
                "messages": messages_data
            }
            response_data.append(data)
        
        def by_time(chat):
            return chat["lastMessage"]["time"]

        response_data.sort(key=by_time, reverse=True)
        # return "hello"
        return JSONResponse(content={"chats_list": response_data})

# type Message = {
#   id: string;
#   fromMe: boolean;
#   text: string;
#   time: string; // ISO or formatted
# };

# type Chat = {
#   id: string;
#   title: string;
#   lastMessage: string;
#   unread?: number;
#   messages: Message[];
# };


connection_manager = ConnectionManager()

@app.websocket("/chat")
async def websocket_endpoint(websocket: WebSocket):
    """
    When client opens conncection it sends json with access_token,
    then server authenticates it.
    If Authnticated

    If not Authnticated closes connection
    """
    await websocket.accept()
    # await websocket.send_json({"info": "You connected to the server"})

    # Authenticate connection
    data: dict= await websocket.receive_json()
    
    token = data.get("access_token")
    
    token_data = decode(token)
    
    this_user_id = token_data.get("user_id")
    with Session(engine) as session:
        try:
            if auth(token):
                # await websocket.send_json({"detail": "You are authenticated"})
                connection_manager.add(token_data["user_id"], websocket)

                while True:
                    # receiveing message
                    message: dict = await websocket.receive_json()
                    other_user_id = message["selectedUserId"]
                    print("hello world")
                    print(message)
                    print(other_user_id, type(other_user_id))
                    
                    stmt = select(User).where(User.id == other_user_id)
                    other_user = session.execute(stmt).scalars().first()
                    print(other_user)

                    this_user: User = session.query(User).filter_by(id=this_user_id).first()
                    # other_user = session.query(User).where(User.id==other_user_id).first()
                    # message = {
                    #       selectedUserId: str
                    #       message: str
                    # }


                    if not other_user:
                        # await websocket.send_json({"error": "User not found"})
                        print(other_user, "OTHER USER DONT EXIST")
                        continue

                    chat = get_chat_between_users(this_user_id, other_user_id)
                    print(chat, "CHAT")
                    print(chat, "EXISTS?", flush=True)
                    if chat:
                        # if chat exists between those users    new_message = Message(new_chat.id, this_user, message.get("message"))

                        # chat = get_chat(session, this_user.id, other_user_id)
                        new_message = Message(chat.id, this_user.id, message.get("message"))
                        other_user_websocket = connection_manager.active_connections.get(other_user_id)
                        try:
                            print(connection_manager.active_connections, "active connctions")
                            session.add(new_message)
                            session.commit()
                            session.refresh(new_message)
                            # other_user_websocket.send_text("hello new message")
                            # This sent to the receiver
                            data = {
                                "message_obj": new_message.to_dict(),
                                # "sent_at": str(new_message.sent_at),
                                # "sender_id": this_user_id,
                                "sender_username": this_user.username,
                                "receiver_id": other_user_id,
                                # "receiver_username": session.query(User).filter_by(id=other_user_id).first().username,

                                "is_own_message": False,
                                
                            }

                            await connection_manager.send_personal_message(data, other_user_websocket)
                                
                            # Send to the sender
                            data["is_own_message"] = True
                            await websocket.send_json(data)
                        except Exception as e:
                            print(f"Error here: {str(e)}")

                    else:
                        # if chat NOT exists between those users, then we create it
                        try:

                            new_chat = Chat()
                            
                            print("usrs", this_user,  other_user)
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
                                # "sent_at": str(new_message.sent_at),
                                # "sender_id": this_user_id,
                                "sender_username": this_user.username,
                                "receiver_id": other_user_id,
                                # "receiver_username": session.query(User).filter_by(id=other_user_id).first().username,

                                "is_own_message": False,
                                
                            }
                            # send other user message
                            if other_user_websocket:= connection_manager.active_connections.get(other_user.id):
                                await connection_manager.send_personal_message(data, other_user_websocket)

                            data["is_own_message"] = True
                            await websocket.send_json(data)

                            
                            # print(this_user.chat_list)

                        except Exception as e:
                            print(f"Exception in creating new chat: {e}")


                    
        except WebSocketDisconnect as e:
            # delete this websocket from pool
            print(f"User disconnected")

        except Exception as e:
            print(f"Error: Unknow exception occured in chat-service /ws endpoint: {str(e)}")
        
        else:
            # await websocket.send_text(f"You NOT authenticated")
            websocket.close()


    #     try:
    #         # await websocket.send_text(f"You authenticated")
    #         access_token = decode(data.get("access_token"))
    #         await manager.add(access_token.get("user_id"), websocket)  # User Authenticated and added to the all connection dict
    #         # await websocket.send_text(f"All connections: {manager.active_connections}")
    #         this_user_id = access_token.get("user_id")
            
    #         while True:
    #             print("loop started", flush=True)
    #             message: dict = await websocket.receive_json()
    #             other_user_id = message["selectedUserId"]

    #             with sessionLocal() as session:
    #                 session: Session

    #                 this_user: User = session.query(User).filter_by(id=this_user_id).first()
    #                 other_user = session.query(User).filter_by(id=other_user_id).first()
    #                 """
    #                 Check if this users have chat:
    #                     1. Take list of chat participants of this_user
    #                     2. Iterate throug list and chat all chat if those chats have other_user as participant
    #                 """
    #                 chat_exists = check_for_chat(session, this_user_id, other_user_id)
    #                 print(chat_exists, "EXISTS?")
    #                 if chat_exists:
    #                     # if chat exists between those users    new_message = Message(new_chat.id, this_user, message.get("message"))

    #                     chat = get_chat(session, this_user.id, other_user_id)
    #                     new_message = Message(chat.id, this_user.id, message.get("message"))
    #                     other_user_websocket = manager.active_connections.get(other_user_id)
    #                     try:
    #                         print(manager.active_connections, "active connctions")
    #                         session.add(new_message)
    #                         session.commit()
    #                         session.refresh(new_message)
    #                         # other_user_websocket.send_text("hello new message")
    #                         # This sent to the receiver
    #                         data = {
    #                             "message_obj": new_message.to_dict(),
    #                             "sent_at": str(new_message.sent_at),
    #                             "sender_id": this_user_id,
    #                             "sender_username": this_user.username,
    #                             "receiver_id": other_user_id,
    #                             "receiver_username": session.query(User).filter_by(id=other_user_id).first().username,
    #                         }
    #                         await manager.send_personal_message(data, manager.active_connections.get(other_user_id))
    #                         # {
    #                         #     "info": "message sent",
    #                         #     "message_obj": new_message.to_dict(),
    #                         #     # "is_own_message": True,
    #                         #     "sender_id": this_user.id,
    #                         #     "receiver_id": other_user_id,
    #                         #     "receiver_username": session.query(User).filter_by(id=other_user_id).first().username,

    #                         #     "data": str(manager.active_connections)
    #                         # } 
    #                         # This sent to the sender
    #                         await websocket.send_json(data)
    #                     except Exception as e:
    #                         print(f"Error here: {str(e)}")

    #                 else:
    #                     # if chat NOT exists between those users, then we create itr
    #                     try:
    #                         new_chat = Chat()
                        
    #                         session.add(new_chat)
    #                         session.commit()
    #                         session.refresh(new_chat)

    #                         this_user_CP = ChatParticipant(chat_id=new_chat.id, user_id=this_user.id)
    #                         other_user_CP = ChatParticipant(chat_id=new_chat.id, user_id=other_user.id)

    #                         session.add(this_user_CP)
    #                         session.add(other_user_CP)
                            
    #                         session.commit()

    #                         # Chat created, then send message itself
    #                         new_message = Message(new_chat.id, this_user.id, message.get("message"))
                            
    #                         session.add(new_message)
    #                         session.commit()
    #                         session.refresh(new_message)

    #                         data = {
    #                             "message_obj": new_message.to_dict(),
    #                             "sent_at": str(new_message.sent_at),
    #                             "sender_id": this_user_id,
    #                             "sender_username": this_user.username,
    #                             "receiver_id": other_user_id,
    #                             "receiver_username": session.query(User).filter_by(id=other_user_id).first().username,
    #                         }
    #                         await manager.send_personal_message(data, manager.active_connections.get(other_user_id))
    #                         # await manager.send_personal_message(data, manager.active_connections.get(this_user_id))
    #                         await websocket.send_json(data)



    #                         # print(this_user.chat_list)

    #                     except Exception as e:
    #                         print(f"Exeprion in creatin new chat: {e}")




                   
    #     except WebSocketDisconnect as e:
    #         # delete this websocket from pool
    #         websocket.close()
    #         manager.disconnect(websocket)
    #     except Exception as e:
    #         print(f"Error: Unknow exception occured in chat-service /ws endpoint: {str(e)}")
    
    # else:
    #     await websocket.send_text(f"You NOT authenticated")
    #     websocket.close()