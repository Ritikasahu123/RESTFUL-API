from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from database import db
from models import User

router = APIRouter()

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(username: str):
    return db.users.find_one({"username": username})

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user

@router.post("/api/auth/signup")
async def signup(user: User):
    user_exists = get_user(user.username)
    if user_exists:
        raise HTTPException(status_code=400, detail="Username already registered")
    user.password = get_password_hash(user.password)
    db.users.insert_one(user.dict())
    return {"message": "User created successfully"}

@router.post("/api/auth/login")
async def login(form_data: User):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
