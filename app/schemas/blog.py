"""
Pydantic Schemas - Data Validation & Serialization

Schemas serve two purposes:
1. VALIDATION: Check that incoming data is the right type (when creating/updating)
2. SERIALIZATION: Convert database objects to JSON for API responses

The difference between Models and Schemas:
- Models (in models/blog.py): Represent database tables
- Schemas (this file): Represent data sent to/from the API (JSON)

Pydantic is a library that validates data and generates helpful error messages.
"""

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# ============================================================================
# COMMENT SCHEMAS
# ============================================================================

class CommentSchema(BaseModel):
    """
    Comment Schema (Full)
    
    Used for returning complete comment data from the API.
    Includes all fields including the auto-generated ID and timestamp.
    
    Example JSON response:
    {
        "id": 1,
        "blog_post_id": 5,
        "name": "John Doe",
        "comment": "Great post!",
        "created_at": "2024-12-29T10:30:00"
    }
    """
    id: int
    blog_post_id: int
    name: str
    comment: str
    created_at: datetime
    
    class Config:
        # from_attributes = True allows converting SQLAlchemy objects to Pydantic
        # Without this, you can't do CommentSchema.from_orm(db_comment)
        from_attributes = True

class CommentCreateSchema(BaseModel):
    """
    Comment Creation Schema (Minimal)
    
    Used when CREATING a new comment (POST request).
    Only includes fields the user should provide.
    The ID and created_at are generated automatically.
    
    Example JSON request:
    {
        "name": "John Doe",
        "comment": "Great post!"
    }
    """
    name: str
    comment: str

# ============================================================================
# BLOG POST SCHEMAS
# ============================================================================

class BlogPostCreateSchema(BaseModel):
    """
    Blog Post Creation Schema (Minimal)
    
    Used when CREATING a new blog post (POST request).
    Only includes fields the user provides.
    The ID is generated automatically by the database.
    
    Example JSON request:
    {
        "title": "My Blog Post",
        "content": "This is the content...",
        "date_published": "2024-12-29"
    }
    """
    title: str
    content: str
    date_published: str

class BlogPostSchema(BaseModel):
    """
    Blog Post Schema (Full)
    
    Used for returning complete blog post data from the API.
    Includes all fields AND related comments.
    
    Example JSON response:
    {
        "id": 1,
        "title": "My Blog Post",
        "content": "This is the content...",
        "date_published": "2024-12-29",
        "comments": [
            {
                "id": 1,
                "blog_post_id": 1,
                "name": "John Doe",
                "comment": "Great post!",
                "created_at": "2024-12-29T10:30:00"
            }
        ]
    }
    """
    id: int
    title: str
    content: str
    date_published: str
    comments: List[CommentSchema] = []  # default = empty list if no comments
    
    class Config:
        # Allow converting SQLAlchemy objects to Pydantic
        from_attributes = True



