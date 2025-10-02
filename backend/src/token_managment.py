from datetime import datetime, timedelta, timezone
from jose import jwt, jws, jwe
from jose.exceptions import JWSError, ExpiredSignatureError

# environment variables block
from dotenv import load_dotenv
import os
from pathlib import Path

env_path = Path(__file__).resolve().parent.parent / "shared" / ".env"
load_dotenv(env_path)
# SECRET_KEY = os.getenv("SECRET_KEY")
SECRET_KEY = "SECRET_KEYSECRET_KEYSECRET_KEYSECRET_KEYSECRET_KEY"



ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # 15 mins
REFRESH_TOKEN_EXPIRE_MINUTES = 72000  # 50 days
OPTIONS = {
    'verify_signature': True,  # True
    'verify_aud': False,
    'verify_iat': False,
    'verify_exp': True,  # True
    'verify_nbf': False,
    'verify_iss': False,
    'verify_sub': False,
    'verify_jti': False,
    'verify_at_hash': False,
    'require_aud': False,
    'require_iat': False,
    'require_exp': False,
    'require_nbf': False,
    'require_iss': False,
    'require_sub': False,
    'require_jti': False,
    'require_at_hash': False,
    'leeway': 0,
}


def auth(token):
    """
    Function that verifies integrity of any JWT.
    Returns bool
    """
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options=OPTIONS)
        # jws.verify(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWSError as e:
        print(e, flush=True)
        return False
    except ExpiredSignatureError as e:
        print(e, flush=True)


        return False
    except Exception as e:
        print(e, flush=True)

        return False
        raise Exception(f"Something happened in verifying JWT: {str(e)}")
    else:
        return True

def create_access_token(data: dict):
    """
    ### Access token
    Takes data as argument, adds expire date and encodes to JWT.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return token


def create_refresh_token(data: dict):
    """
    ### Refresh token
    Takes data as argument, adds expire date and encodes to JWT
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token
    
    

def decode(token: str):
    """
    Function that extracts paload, returns dict
    """
    try:
        
        payload = jwt.decode(token, key=SECRET_KEY, options={"verify_signature": False})
        return payload
    except Exception as e:
        print("Couldnt decode JWT:", str(e))
        return False