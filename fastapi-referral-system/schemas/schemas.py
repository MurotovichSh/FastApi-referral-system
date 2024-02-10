from uuid import UUID
from pydantic import BaseModel, Field

class TokenSchema(BaseModel):
    access_token: str
    
class UserAuth(BaseModel):
    username: str = Field(..., description="user username")
    email: str = Field(..., description="user email")
    password: str = Field(..., min_length=5, max_length=24, description="user password")


class User(BaseModel):
    username: str
    email: str | None = None


class UserInDB(User):
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

