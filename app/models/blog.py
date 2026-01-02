"""
Database Models - ORM Definition

This file defines the database structure using SQLAlchemy ORM.
Each class represents a table in the database.
Each attribute of the class represents a column in that table.

Models are the "bridge" between Python and SQL:
- Python: You work with BlogPost and Comment objects
- SQL: Behind the scenes, SQLAlchemy translates this to SQL queries
"""

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.database import Base

# ============================================================================
# BLOGPOST MODEL
# ============================================================================
# This class represents the "blog_posts" table in the database
# Each BlogPost instance = one row in the table
class BlogPost(Base):
    """
    Blog Post Model
    
    Attributes:
        id (int): Unique identifier, auto-incremented primary key
        title (str): The blog post title
        content (str): The blog post content (can be long)
        date_published (str): The date the post was published
        comments (List[Comment]): Related comments (one-to-many relationship)
    """
    
    # Tell SQLAlchemy what table this maps to
    __tablename__ = "blog_posts"
    
    # ========================================================================
    # COLUMNS
    # ========================================================================
    
    # Primary Key: Unique identifier for each blog post
    # index=True makes queries by ID faster
    id = Column(Integer, primary_key=True, index=True)
    
    # Blog post title
    # index=True makes searching/filtering by title faster
    title = Column(String, index=True)
    
    # Blog post full content (can be very long)
    content = Column(String)
    
    # Date the post was published (stored as string for simplicity)
    date_published = Column(String)
    
    # ========================================================================
    # RELATIONSHIPS
    # ========================================================================
    
    # Relationship to Comment model
    # "Comment" (string) = the related model name
    # back_populates="post" = create a two-way relationship
    #   - BlogPost.comments gives you all comments for a post
    #   - Comment.post gives you the parent post
    # cascade="all, delete-orphan" = if you delete a post, delete its comments too
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")

# ============================================================================
# COMMENT MODEL
# ============================================================================
# This class represents the "comments" table in the database
# Each Comment instance = one row in the table
class Comment(Base):
    """
    Comment Model
    
    Attributes:
        id (int): Unique identifier
        blog_post_id (int): Foreign key to the parent BlogPost
        name (str): Name of the person who commented
        comment (str): The comment text
        created_at (datetime): When the comment was created
        post (BlogPost): The parent blog post (relationship)
    """
    
    __tablename__ = "comments"
    
    # ========================================================================
    # COLUMNS
    # ========================================================================
    
    # Primary Key: Unique identifier for each comment
    id = Column(Integer, primary_key=True, index=True)
    
    # Foreign Key: Links this comment to a blog post
    # ForeignKey("blog_posts.id") means:
    #   "This column references the 'id' column in the 'blog_posts' table"
    # If you delete a blog post, all its comments are deleted too
    # index=True makes queries by blog_post_id faster
    blog_post_id = Column(Integer, ForeignKey("blog_posts.id"), index=True)
    
    # Name of the person who left the comment
    name = Column(String)
    
    # The actual comment text
    comment = Column(String)
    
    # Timestamp when the comment was created
    # default=datetime.utcnow means SQLAlchemy automatically sets this to now
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # ========================================================================
    # RELATIONSHIPS
    # ========================================================================
    
    # Relationship back to the parent BlogPost
    # This allows you to access the parent post via comment.post
    post = relationship("BlogPost", back_populates="comments")


