from pydantic import BaseModel, StringConstraints
from typing import Annotated


class UserSignup(BaseModel):
    
    username: Annotated[
        str,
        StringConstraints(
            min_length=4,
            max_length=20,
            strip_whitespace=True,
            pattern=r'[A-Za-z][A-Za-z0-9\_]*',
        )
    ]
    password1: Annotated[
        str,
        StringConstraints(
            min_length=8,
            max_length=24,
            strip_whitespace=True,
            pattern=r"[\w!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+$",
        )
    ]
    password2: Annotated[
        str,
        StringConstraints(
            min_length=8,
            max_length=24,
            strip_whitespace=True,
            pattern=r"[\w!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+$",
        )
    ]
    
class UserLogin(BaseModel):
    
    username: Annotated[str, StringConstraints()]
    password: Annotated[str, StringConstraints()]