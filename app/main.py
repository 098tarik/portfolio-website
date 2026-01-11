"""
FastAPI Application Main File

This is the entry point for the resume website backend. It sets up:
1. The FastAPI application instance
2. Database initialization
3. CORS middleware for cross-origin requests
4. Static file serving (for PDFs, images, etc.)
5. Routes for serving HTML pages and API endpoints
6. Authentication with JWT tokens

Think of this file as the "control center" that orchestrates everything.
"""

from datetime import timedelta
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
from fastapi.security import OAuth2PasswordRequestForm

from app.db.database import engine, get_db
from app.db.database import Base
from app.models.blog import BlogPost, User
from app.routers import blog
from app.core.security import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    get_password_hash
)
from app.schemas.user import Token, UserResponse, UserRegister
from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES

# ============================================================================
# DATABASE SETUP
# ============================================================================
# Create all database tables defined in our models
# This runs once when the app starts. If tables already exist, nothing happens.
Base.metadata.create_all(bind=engine)

# ============================================================================
# LIFESPAN CONTEXT MANAGER
# ============================================================================
# This function runs code at startup and shutdown
# - Before 'yield': startup code
# - After 'yield': shutdown code
# This is the modern way (FastAPI 0.93+) to handle app lifecycle events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP CODE
    # Create a default admin user if none exists
    try:
        db = next(get_db())
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin_user = User(
                username="admin",
                email="admin@example.com",
                full_name="Admin User",
                hashed_password=get_password_hash("admin"),  # Change this in production!
                is_admin=True,
                disabled=False
            )
            db.add(admin_user)
            db.commit()
            print("✓ Default admin user created (username: admin, password: admin)")
        else:
            print("✓ Admin user already exists")
    finally:
        db.close()
    
    yield  # App runs here
    
    # SHUTDOWN CODE
    # Cleanup code can go here when the app stops

# ============================================================================
# FASTAPI APP INITIALIZATION
# ============================================================================
# Create the main FastAPI application with the lifespan manager
# FastAPI automatically generates interactive API docs at /docs and /redoc
app = FastAPI(
    title="Resume Website API",
    description="A FastAPI application with OAuth2, JWT, and blog functionality",
    lifespan=lifespan
)

# ============================================================================
# STATIC FILES MOUNTING
# ============================================================================
# Mount the 'data' directory so files like PDFs and images are accessible
# Files in the 'data' folder can be accessed via /data/filename
# Example: /data/Pictures/tarik_profile.jpg serves the profile image
app.mount("/data", StaticFiles(directory="data"), name="data")

# ============================================================================
# CORS MIDDLEWARE
# ============================================================================
# CORS = Cross-Origin Resource Sharing
# This allows requests from different domains (needed for frontend to call API)
# allow_origins=["*"] means allow requests from ANY domain
# In production, you'd restrict this to only your domain for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (localhost, etc.)
    allow_credentials=True,  # Allow cookies/auth headers
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, DELETE, etc.)
    allow_headers=["*"],  # Allow all headers
)

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
) -> Token:
    """
    POST /token
    
    Login endpoint that returns a JWT access token.
    
    OAuth2PasswordRequestForm expects:
    - username: User's username
    - password: User's password
    
    Returns a JWT token that can be used for subsequent requests.
    
    Example:
    ```
    POST /token
    Content-Type: application/x-www-form-urlencoded
    
    username=admin&password=admin
    
    Response:
    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer"
    }
    ```
    """
    # Authenticate the user with username and password
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create an access token with expiration
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserRegister,
    db: Session = Depends(get_db)
) -> UserResponse:
    """
    POST /register
    
    Register a new user account.
    
    Request body:
    {
        "username": "johndoe",
        "email": "john@example.com",
        "full_name": "John Doe",
        "password": "secretpassword"
    }
    
    Returns the created user data (without password).
    """
    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create new user with hashed password
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        is_admin=False,  # New users are not admins by default
        disabled=False
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return UserResponse.from_orm(db_user)


@app.get("/users/me/", response_model=UserResponse)
async def read_users_me(
    current_user: Annotated[UserResponse, Depends(get_current_active_user)]
) -> UserResponse:
    """
    GET /users/me/
    
    Get the current authenticated user's information.
    
    Requires a valid JWT token in the Authorization header:
    Authorization: Bearer <token>
    
    Returns the current user's data.
    """
    return current_user
# HTML ROUTES (Frontend Page Serving)
# ============================================================================
# These routes serve HTML files when you visit URLs like / or /about
# The @app.get() decorator means "handle GET requests"
# response_class=HTMLResponse tells FastAPI to return HTML content

@app.get("/", response_class=HTMLResponse)
def index():
    """Serve the home page (index.html)"""
    with open("frontend/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/about", response_class=HTMLResponse)
def about():
    """Serve the about page (about.html)"""
    with open("frontend/about.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/resume", response_class=HTMLResponse)
def resume():
    """Serve the resume page (resume.html)"""
    with open("frontend/resume.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/blog", response_class=HTMLResponse)
def blog():
    """Serve the blog list page (blog.html)"""
    with open("frontend/blog.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/blog/post", response_class=HTMLResponse)
def blog_post_page():
    """Serve the individual blog post page (blog_post.html)"""
    with open("frontend/blog_post.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/admin", response_class=HTMLResponse)
def admin_login():
    """Serve the admin login page"""
    with open("frontend/admin.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard():
    """Serve the admin dashboard page"""
    with open("frontend/admin-dashboard.html", "r", encoding="utf-8") as f:
        return f.read()

