import uvicorn
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from config import ALGORITHM, SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES, EMAIL_HUNTER_API_KEY, CLEARBIT_API_KEY, password_context, oauth2_scheme, app
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from pydantic import EmailStr
from database.database import SessionLocal
from models.user import User as UserDB
from models.referral import Referral as ReferralDB
from typing import Union, Any
from schemas.schemas import UserAuth, TokenSchema,UserCreate, User, UserInDB
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi.responses import RedirectResponse
import random
import string
import requests
from cachetools import cached, TTLCache

# Cache settings
cache = TTLCache(maxsize=1000, ttl=900) 

def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)

def get_user(db, username: str):
    user_db = db.query(UserDB).filter(UserDB.username == username).first()
    if user_db:
        user_dict = {
            "username": user_db.username,
            "email": user_db.email,
            "password": user_db.password
        }
        return UserInDB(**user_dict)


def authenticate_user(username: str, password: str, db: Session):
    user = get_user(db, username)
    if not user:
        return None  
    if not verify_password(password, user.password):
        return None  
    return user

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create access token
def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, ALGORITHM)
    return encoded_jwt

@app.get('/', response_class=RedirectResponse, include_in_schema=False)
async def docs():
    return RedirectResponse(url='/docs')

# Route to get access token
@app.post('/token', summary="Create access tokens for user", response_model=TokenSchema)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )

    access_token = create_access_token(user.email)

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# Route to sign up a new user
@app.post('/signup', summary="Create new user", response_model=UserCreate)
async def create_user(data: UserAuth, db: Session = Depends(get_db)):
    # Verify email using emailhunter.co
    email_verification_result = requests.get(
        f"https://api.hunter.io/v2/email-verifier?email={data.email}&api_key={EMAIL_HUNTER_API_KEY}"
    ).json()
    if email_verification_result['data']['status']!='valid':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email address"
        )

    # Check if the user already exists in the database
    existing_user = db.query(UserDB).filter(UserDB.email == data.email).first()
    existing_username = db.query(UserDB).filter(UserDB.username == data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username already exists"
        )

    # Create a new user
    hashed_password = get_hashed_password(data.password)
    new_user = UserDB(username=data.username, email=data.email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserCreate(
        username=new_user.username,
        email=new_user.email,
        password=new_user.password
    )


# Get info about current user
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = db.query(UserDB).filter(UserDB.email == email).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )



# Generate a random referral code
@cached(cache)
def generate_referral_code():
    return ''.join(random.choices(string.digits, k=6))

@app.post("/referral/create/")
async def create_referral_code(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = await read_users_me(token, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_db = db.query(UserDB).filter(UserDB.username == user.username).first()

    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user_db.referral_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has an active referral code",
        )

    code = generate_referral_code()

    # Check if the referral code already exists in the database
    while db.query(ReferralDB).filter(ReferralDB.code == code).first():
        code = generate_referral_code()

    expiration_date = datetime.now() + timedelta(minutes=15)

    db_referral = ReferralDB(code=code, expiration_date=expiration_date, referrer_id=user_db.id, referrer_email=user_db.email)
    db.add(db_referral)
    db.commit()

    user_db.referral_code = code
    db.commit()

    return {"message": "Referral code created successfully"}

# Route to delete a referral code
@app.delete("/referral/delete/")
async def delete_referral_code(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = await read_users_me(token, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.referral_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User does not have an active referral code",
        )

    db.query(ReferralDB).filter(ReferralDB.code == user.referral_code).delete()
    user.referral_code = None
    db.commit()

    return {"message": "Referral code deleted successfully"}


# Route to get referral code by referrer's email
@app.get("/referral/get_by_email/{email}")
async def get_referral_by_email(email: EmailStr, db: Session = Depends(get_db)):
    referral = db.query(ReferralDB).filter(ReferralDB.referrer_email == email).first()
    if referral is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Referral code not found for the specified email",
        )
    return referral

# Route to register user using a referral code
@app.post("/register/{referral_code}")
async def register_user_with_referral(referral_code: str, user: User, db: Session = Depends(get_db)):
    referral = db.query(ReferralDB).filter(ReferralDB.code == referral_code).first()
    if referral is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Referral code not found",
        )
    return user

# Route to get referral information by referrer's ID
@app.get("/referral/get_by_referrer_id/{referrer_id}")
async def get_referrals_by_referrer_id(referrer_id: int, db: Session = Depends(get_db)):
    referrals = db.query(ReferralDB).filter(ReferralDB.referrer_id == referrer_id).all()
    if not referrals:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No referrals found for the specified referrer ID",
        )
    return referrals


def delete_expired_referral_codes(db: Session):
    current_time = datetime.now()
    expired_referral_codes = db.query(ReferralDB).filter(ReferralDB.expiration_date < current_time).all()
    for referral_code in expired_referral_codes:
        user = db.query(UserDB).filter(UserDB.id == referral_code.referrer_id).first()
        if user:
            user.referral_code = None
        db.delete(referral_code)
    db.commit()

# Function to retrieve person information using Clearbit API based on email.
@app.get("/person")
async def get_person_info(email: str):
    url = f"https://person.clearbit.com/v2/people/find?email={email}"
    headers = {
        "Authorization": f"Bearer {CLEARBIT_API_KEY}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(
            status_code=response.status_code,
            detail="Failed to retrieve a person's information from Clearbit API"
        )

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(delete_expired_referral_codes, 'interval', minutes=15, args=[SessionLocal()])



if __name__ == "__main__":
    scheduler.start()
    uvicorn.run(app)




