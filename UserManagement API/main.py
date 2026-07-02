from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel, EmailStr
from typing import Optional, Literal
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta

# ==========================================
# DATABASE CONFIGURATION
# ==========================================

DATABASE_URL = "mysql+pymysql://root:$4saanvi@localhost:3308/realestate_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# JWT CONFIGURATION
# ==========================================

SECRET_KEY = "mysecretkey123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

# ==========================================
# PASSWORD HASHING
# ==========================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )

# ==========================================
# DATABASE MODEL
# ==========================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)

Base.metadata.create_all(bind=engine)

# ==========================================
# FASTAPI APP
# ==========================================

app = FastAPI(title="User Management API")

# ==========================================
# PYDANTIC MODELS
# ==========================================

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Literal["admin", "user"]

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# User can update only name and email
class UserSelfUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None

# Admin can update name, email and role
class AdminUserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[Literal["admin", "user"]] = None

# ==========================================
# JWT FUNCTIONS
# ==========================================

def create_access_token(data: dict):
    payload = data.copy()

    payload["exp"] = (
        datetime.utcnow() +
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

# ==========================================
# AUTHENTICATION
# ==========================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or Expired Token"
        )

# ==========================================
# ADMIN CHECK
# ==========================================

def admin_required(
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )

    return current_user

# ==========================================
# AUTH ROUTES
# ==========================================

@app.post("/register", tags=["Auth"])
def register(
    user: UserRegister,
    db: Session = Depends(get_db)
):

    existing_user = db.query(User).filter(
        User.email == user.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    new_user = User(
        name=user.name,
        email=user.email,
        password=hash_password(user.password),
        role=user.role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User Registered Successfully"
    }

@app.post("/login", tags=["Auth"])
def login(
    user: UserLogin,
    db: Session = Depends(get_db)
):

    db_user = db.query(User).filter(
        User.email == user.email
    ).first()

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid Email"
        )

    if not verify_password(
        user.password,
        db_user.password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid Password"
        )

    token = create_access_token(
        {
            "user_id": db_user.id,
            "email": db_user.email,
            "role": db_user.role
        }
    )

    return {
        "message": "Login Successful",
        "access_token": token,
        "token_type": "bearer",
        "role": db_user.role
    }

# ==========================================
# ADMIN ROUTES
# ==========================================

@app.get("/users", tags=["Admin"])
def get_all_users(
    db: Session = Depends(get_db),
    current_user: dict = Depends(admin_required)
):
    return db.query(User).all()

@app.put("/admin/users/{user_id}", tags=["Admin"])
def admin_update_user(
    user_id: int,
    updates: AdminUserUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(admin_required)
):

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User Not Found"
        )

    if user.role == "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin cannot update another admin"
        )

    if updates.name:
        user.name = updates.name

    if updates.email:
        user.email = updates.email

    if updates.role:
        user.role = updates.role

    db.commit()
    db.refresh(user)

    return {
        "message": "User Updated Successfully",
        "data": user
    }


@app.delete("/users/{user_id}", tags=["Admin"])
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(admin_required)
):

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User Not Found"
        )

    if user.role == "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin cannot delete another admin"
        )

    db.delete(user)
    db.commit()

    return {
        "message": "User Deleted Successfully"
    }

# ==========================================
# USER ROUTES
# ==========================================

@app.get("/users/{user_id}", tags=["User"])
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    if (
        current_user["role"] != "admin"
        and current_user["user_id"] != user_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Access Denied"
        )

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User Not Found"
        )

    return user

@app.put("/users/me", tags=["User"])
def update_my_profile(
    updates: UserSelfUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    user = db.query(User).filter(
        User.id == current_user["user_id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User Not Found"
        )

    if updates.name:
        user.name = updates.name

    if updates.email:
        user.email = updates.email

    db.commit()
    db.refresh(user)

    return {
        "message": "Profile Updated Successfully",
        "data": user
    }

# ==========================================
# HOME ROUTE
# ==========================================

@app.get("/")
def home():
    return {
        "message": "User Management API Running Successfully"
    }