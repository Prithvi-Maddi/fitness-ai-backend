from fastapi import FastAPI, HTTPException, status, Depends  
from app.database import engine, Base
from app.models import User
import bcrypt
from uuid import uuid4
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session  
from app.database import get_db  
from datetime import datetime, timedelta
from jose import jwt, JWTError
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path = ".env")
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
ALGORITHM = "HS256"

def create_access_token(data:dict) -> str:
    """ 
    Create JWT token containing 'data' as the payload
    Token will expire after ACCESS_TOKEN_EXPIRE_MINUTES
    """
    to_encode = data.copy()
    expire = datetime.now(datetime.timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str


app = FastAPI()

Base.metadata.create_all(bind=engine)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if email is already registered
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered."
        )

    # Hash the password
    hashed_pw = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    # Create a new User instance
    new_user = User(
        id=str(uuid4()),
        name=user.name,
        email=user.email,
        password_hash=hashed_pw.decode("utf-8")
    )

    # Add to the session and commit
    db.add(new_user)
    db.commit()
    db.refresh(new_user)  # load any defaults

    # Return a safe response
    return {
        "id": new_user.id,
        "name": new_user.name,
        "email": new_user.email,
        "created_at": new_user.created_at
    }

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    # fetch user by email
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Credentials"
        )
    
    # verify password
    if not bcrypt.checkpw(user.pw.encode("utf-8"), db_user.password_hash.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credential"
        )
    
    # Generate token with User ID
    access_token = create_access_token({"sub": db_user.id})

    #return token and token type
    return {"access_token": access_token, "token_type": "bearer"}