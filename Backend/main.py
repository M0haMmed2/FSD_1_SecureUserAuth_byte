from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI(title="Secure User Auth API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "super_secret_arithmatrix_key_change_this_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

users_db = {}

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/api/register")
def register_user(user: UserRegister):
     
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pw = hash_password(user.password)
    
    users_db[user.username] = hashed_pw
    
    return {"message": "User registered successfully"}

@app.post("/api/login")
def login_user(user: UserLogin):

    if user.username not in users_db:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    hashed_pw = users_db[user.username]
    if not verify_password(user.password, hashed_pw):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    token = create_access_token(data={"sub": user.username})
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/protected")
def get_protected_data(authorization: Optional[str] = Header(None)):
    # 1. Ensure the Authorization header exists and starts with "Bearer "
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    # Extract just the token string (remove "Bearer ")
    token = authorization.split(" ")[1]
    
    try:
        # 2. Decode the token using our secret key
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
        # 3. Return the highly sensitive data
        return {
            "message": f"Welcome, {username}!",
            "secret_data": "This is classified information only visible to logged-in users."
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    