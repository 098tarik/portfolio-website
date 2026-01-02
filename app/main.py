"""
FastAPI Application Main File

This is the entry point for the resume website backend. It sets up:
1. The FastAPI application instance
2. Database initialization
3. CORS middleware for cross-origin requests
4. Static file serving (for PDFs, images, etc.)
5. Routes for serving HTML pages and API endpoints

Think of this file as the "control center" that orchestrates everything.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager

from app.db.database import engine, get_db
from app.db.database import Base
from app.models.blog import BlogPost
from app.routers import blog

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
    # Currently empty, but you could initialize connections or load data here
    # (The sample blog posts are seeded in database.py)
    
    try:
        db = next(get_db())
    finally:
        db.close()
    
    yield  # App runs here
    
    # SHUTDOWN CODE
    # Cleanup code can go here when the app stops
    # For now, not needed since FastAPI handles it automatically

# ============================================================================
# FASTAPI APP INITIALIZATION
# ============================================================================
# Create the main FastAPI application with the lifespan manager
# FastAPI automatically generates interactive API docs at /docs and /redoc
app = FastAPI(lifespan=lifespan)

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
# API ROUTERS
# ============================================================================
# Include the blog router (from app/routers/blog.py)
# This adds all the blog API endpoints like /api/blog, /api/blog/{id}, etc.
app.include_router(blog.router)

# ============================================================================
# HTML ROUTES (Frontend Page Serving)
# ============================================================================
# These routes serve HTML files when you visit URLs like / or /about
# The @app.get() decorator means "handle GET requests"
# response_class=HTMLResponse tells FastAPI to return HTML content

@app.get("/", response_class=HTMLResponse)
def index():
    """Serve the home page (index.html)"""
    with open("frontend/index.html", "r") as f:
        return f.read()

@app.get("/about", response_class=HTMLResponse)
def about():
    """Serve the about page (about.html)"""
    with open("frontend/about.html", "r") as f:
        return f.read()

@app.get("/resume", response_class=HTMLResponse)
def resume():
    """Serve the resume page (resume.html)"""
    with open("frontend/resume.html", "r") as f:
        return f.read()

@app.get("/blog", response_class=HTMLResponse)
def blog_page():
    """Serve the blog listing page (blog.html)"""
    with open("frontend/blog.html", "r") as f:
        return f.read()

@app.get("/blog/post", response_class=HTMLResponse)
def blog_post_page():
    """Serve the individual blog post page (blog_post.html)"""
    with open("frontend/blog_post.html", "r") as f:
        return f.read()

