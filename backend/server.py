from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Annotated
import uuid
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import json

# Directory and env setup
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'content_management')]

# Auth constants
SECRET_KEY = os.environ.get("SECRET_KEY", "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Define Models
class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    username: str
    email: str
    role: str

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "viewer"  # Default to viewer

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ContentBase(BaseModel):
    title: str
    body: str

class ContentCreate(ContentBase):
    pass

class Content(ContentBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    author_id: str
    author_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

# Auth functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(username: str):
    user = await db.users.find_one({"username": username})
    if user:
        return user
    return None

async def get_user_by_id(user_id: str):
    user = await db.users.find_one({"id": user_id})
    if user:
        return user
    return None

async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        role: str = payload.get("role")
        if username is None or user_id is None:
            raise credentials_exception
        token_data = TokenData(username=username, user_id=user_id, role=role)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[dict, Depends(get_current_user)]):
    if current_user.get("disabled", False):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def is_admin(current_user: Annotated[dict, Depends(get_current_active_user)]):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

# Auth Routes
@api_router.post("/register", response_model=User)
async def register_user(user: UserCreate):
    # Check if username exists
    db_user = await get_user(user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Check if email exists
    db_email = await db.users.find_one({"email": user.email})
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user with hashed password
    user_obj = User(**user.dict())
    hashed_password = get_password_hash(user.password)
    user_dict = user_obj.dict()
    user_dict["password"] = hashed_password
    
    await db.users.insert_one(user_dict)
    return user_obj

@api_router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "user_id": user["id"], "role": user["role"]},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"]
    }

@api_router.get("/users/me", response_model=User)
async def read_users_me(current_user: Annotated[dict, Depends(get_current_active_user)]):
    return current_user

# Content Management Routes
@api_router.post("/content", response_model=Content)
async def create_content(
    content: ContentCreate, 
    current_user: Annotated[dict, Depends(get_current_active_user)]
):
    # Only admins can create content
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    content_obj = Content(
        **content.dict(), 
        author_id=current_user["id"],
        author_name=current_user["username"]
    )
    await db.content.insert_one(content_obj.dict())
    return content_obj

@api_router.get("/content", response_model=List[Content])
async def get_all_content(current_user: Annotated[dict, Depends(get_current_active_user)]):
    # All authenticated users can view content
    content_items = await db.content.find().to_list(1000)
    return [Content(**item) for item in content_items]

@api_router.get("/content/{content_id}", response_model=Content)
async def get_content(content_id: str, current_user: Annotated[dict, Depends(get_current_active_user)]):
    # All authenticated users can view content
    content = await db.content.find_one({"id": content_id})
    if not content:
        raise HTTPException(status_code=404, detail="Content not found")
    return Content(**content)

@api_router.put("/content/{content_id}", response_model=Content)
async def update_content(
    content_id: str, 
    content: ContentCreate, 
    current_user: Annotated[dict, Depends(get_current_active_user)]
):
    # Only admins can update content
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    existing = await db.content.find_one({"id": content_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Content not found")
    
    update_data = content.dict()
    update_data["updated_at"] = datetime.utcnow()
    
    await db.content.update_one(
        {"id": content_id}, 
        {"$set": update_data}
    )
    
    updated_content = await db.content.find_one({"id": content_id})
    return Content(**updated_content)

@api_router.delete("/content/{content_id}")
async def delete_content(
    content_id: str, 
    current_user: Annotated[dict, Depends(get_current_active_user)]
):
    # Only admins can delete content
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    existing = await db.content.find_one({"id": content_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Content not found")
    
    await db.content.delete_one({"id": content_id})
    return {"message": "Content deleted successfully"}

# Test route
@api_router.get("/")
async def root():
    return {"message": "Content Management API is running"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
