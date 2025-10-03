import re
from pydantic import BaseModel, StringConstraints, Field, field_validator

from typing import Annotated


class UserSignup(BaseModel):
    username: str = Field(
        min_length=4,
        max_length=16,
        # strict=True,
        pattern=r'^[A-Za-z][A-Za-z0-9_]*$'
    )

    password1: str
    password2: str

    @field_validator("password1")
    def validate_password(cls, v: str):
        if v != v.strip():
            raise ValueError("Should not start or end with whitespace.")
        if len(v) < 8 or len(v) > 24:
            raise ValueError("Password should be 8 - 24 symbols long.")
        if not re.search(r"[a-z]", v):
            raise ValueError("At least 1 lowercase  letter.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("At least 1 uppercase letter.")
        if not re.search(r"[0-9]", v):
            raise ValueError("At least 1 number.")
        if not re.fullmatch(r"[A-Za-z0-9 ]+", v):
            raise ValueError("Latin letters only.")
        return v
  

# class UserSignup(BaseModel):
    
#     username: Annotated[
#         str,
#         StringConstraints(
#             min_length=4,
#             max_length=20,
#             strip_whitespace=True,
#             pattern=r'[A-Za-z][A-Za-z0-9\_]*',
#         )
#     ]
#     password1: Annotated[
#         str,
#         StringConstraints(
#             min_length=8,
#             max_length=24,
#             strip_whitespace=True,
#             pattern=r"[\w!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+$",
#         )
#     ]
#     password2: Annotated[
#         str,
#         StringConstraints(
#             min_length=8,
#             max_length=24,
#             strip_whitespace=True,
#             pattern=r"[\w!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+$",
#         )
#     ]
    
class UserLogin(BaseModel):
    
    username: Annotated[str, StringConstraints()]
    password: Annotated[str, StringConstraints()]