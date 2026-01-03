"""
Blog API Routes - API Endpoints

This file defines all the REST API endpoints for the blog system.
These endpoints handle:
- Getting blog posts (GET) - Public access
- Creating blog posts (POST) - Admin only
- Getting comments (GET) - Public access
- Creating comments (POST) - Public access

REST API Basics:
- GET: Retrieve data (read-only, safe)
- POST: Create new data
- PUT: Update existing data
- DELETE: Delete data

CRUD = Create, Read, Update, Delete
We're implementing CRD (no Update/Delete for now).
"""

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.blog import BlogPost, Comment
from app.schemas.blog import BlogPostSchema, BlogPostCreateSchema, CommentSchema, CommentCreateSchema
from app.schemas.user import UserResponse
from app.core.security import get_current_admin_user

# ============================================================================
# ROUTER SETUP
# ============================================================================
# APIRouter groups related endpoints together
# prefix="/api/blog" means all routes in this file start with /api/blog
# tags=["blog"] groups them in the auto-generated API docs
router = APIRouter(prefix="/api/blog", tags=["blog"])

# ============================================================================
# BLOG POST ENDPOINTS
# ============================================================================

@router.get("")
def get_blog_posts(db: Session = Depends(get_db)):
    """
    GET /api/blog
    
    Retrieve all blog posts.
    
    Returns:
    {
        "posts": [
            {
                "id": 1,
                "title": "...",
                "content": "...",
                "date_published": "...",
                "author": {"id": 1, "username": "...", "full_name": "..."},
                "comments": []
            },
            ...
        ]
    }
    """
    # Query the database for ALL blog posts
    posts = db.query(BlogPost).all()
    
    # Convert each SQLAlchemy BlogPost object to a Pydantic BlogPostSchema
    # This converts database objects to JSON-serializable dicts
    return {"posts": [BlogPostSchema.from_orm(p) for p in posts]}

@router.get("/{post_id}")
def get_blog_post(post_id: int, db: Session = Depends(get_db)):
    """
    GET /api/blog/{post_id}
    
    Retrieve a SINGLE blog post by ID.
    
    Path parameter:
    - {post_id} = the post ID (e.g., GET /api/blog/5 retrieves post with id=5)
    
    Returns the full post with all comments, or an error if not found.
    """
    # Query for a specific post by ID
    # .filter(BlogPost.id == post_id) = WHERE clause in SQL
    # .first() = get only the first result (or None if not found)
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    
    if not post:
        return {"error": "Post not found"}
    
    # Convert to schema and return
    return BlogPostSchema.from_orm(post)

@router.post("")
def create_blog_post(
    post: BlogPostCreateSchema,
    current_admin: Annotated[UserResponse, Depends(get_current_admin_user)],
    db: Session = Depends(get_db)
):
    """
    POST /api/blog
    
    Create a NEW blog post (ADMIN ONLY).
    
    The 'post: BlogPostCreateSchema' parameter:
    - FastAPI automatically validates the JSON body against BlogPostCreateSchema
    - If validation fails, FastAPI returns a 422 error with details
    - If valid, 'post' is a BlogPostCreateSchema object with the data
    
    The function returns the newly created post (with auto-generated ID).
    
    Example request body:
    {
        "title": "My New Post",
        "content": "Post content here...",
        "date_published": "2024-12-29"
    }
    """
    # Create a new BlogPost object (database model, not yet in DB)
    db_post = BlogPost(
        title=post.title,
        content=post.content,
        date_published=post.date_published,
        author_id=current_admin.id  # Link to the admin user who created it
    )
    
    # Add to the session (marks for insertion)
    db.add(db_post)
    
    # Commit = execute the INSERT statement (actually save to database)
    db.commit()
    
    # Refresh = reload the object from the database
    # This ensures we have the auto-generated ID and relationships
    db.refresh(db_post)
    
    # Convert and return the new post
    return BlogPostSchema.from_orm(db_post)

# ============================================================================
# COMMENT ENDPOINTS
# ============================================================================

@router.get("/{post_id}/comments")
def get_comments(post_id: int, db: Session = Depends(get_db)):
    """
    GET /api/blog/{post_id}/comments
    
    Retrieve all comments for a specific blog post.
    
    Example: GET /api/blog/5/comments retrieves all comments on post #5
    
    Returns:
    {
        "comments": [
            {
                "id": 1,
                "blog_post_id": 5,
                "name": "John",
                "comment": "Great!",
                "created_at": "..."
            },
            ...
        ]
    }
    """
    # Query for ALL comments with the matching blog_post_id
    # .filter(Comment.blog_post_id == post_id) = WHERE blog_post_id = post_id
    comments = db.query(Comment).filter(Comment.blog_post_id == post_id).all()
    
    # Convert to schema objects and return
    return {"comments": [CommentSchema.from_orm(c) for c in comments]}

@router.post("/{post_id}/comments")
def create_comment(post_id: int, comment: CommentCreateSchema, db: Session = Depends(get_db)):
    """
    POST /api/blog/{post_id}/comments
    
    Create a NEW comment on a specific blog post.
    
    Path parameter:
    - {post_id} = which post to comment on
    
    Request body (CommentCreateSchema):
    {
        "name": "John Doe",
        "comment": "This is my comment!"
    }
    
    Returns the newly created comment (with auto-generated ID and timestamp).
    """
    # Create a new Comment object
    db_comment = Comment(
        blog_post_id=post_id,  # Link to the parent post
        name=comment.name,     # From the request body
        comment=comment.comment  # From the request body
    )
    
    # Add, commit, and refresh (same process as creating a post)
    db.add(db_comment)
    db.commit()
    db.refresh(db_comment)
    
    # Convert and return
    return CommentSchema.from_orm(db_comment)



