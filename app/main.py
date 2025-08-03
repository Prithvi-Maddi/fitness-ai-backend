from fastapi import FastAPI, HTTPException, status, Depends  
from app.database import engine, Base
from app.models import User
import bcrypt
from uuid import uuid4
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session  
from app.database import get_db  
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from dotenv import load_dotenv
import os
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer


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
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
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

# Allowed origins for the frontend
origins = [
    "http://localhost:3000",            # dev server
    # "https://your-production-frontend",  # add this in prod
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,           # which domains can talk to us
    allow_credentials=True,          # allow cookies, auth headers
    allow_methods=["*"],             # allow POST, GET, OPTIONS, etc.
    allow_headers=["*"],             # allow all headers
)


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
    if not bcrypt.checkpw(user.password.encode("utf-8"), db_user.password_hash.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credential"
        )
    
    # Generate token with User ID
    access_token = create_access_token({"sub": db_user.id})

    #return token and token type
    return {"access_token": access_token, "token_type": "bearer"}



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user


@app.get("/users/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "created_at": current_user.created_at
    }