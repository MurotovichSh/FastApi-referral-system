import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from database.database import Base
from database.database import engine
from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI

load_dotenv()


EMAIL_HUNTER_API_KEY = os.getenv("EMAIL_HUNTER_API_KEY")
CLEARBIT_API_KEY = os.getenv("CLEARBIT_API_KEY")

Base.metadata.create_all(bind=engine)

# JWT configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SECRET_KEY = os.getenv("SECRET_KEY")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()
