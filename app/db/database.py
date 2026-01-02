"""
Database Configuration Module

This file sets up SQLAlchemy (an ORM - Object Relational Mapper) to manage
the SQLite database. An ORM lets you work with databases using Python objects
instead of writing raw SQL queries.

Key concepts:
- Engine: The actual database connection
- SessionLocal: A factory for creating database sessions
- Base: The declarative base class for all database models
- get_db: A dependency provider for FastAPI routes
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# ============================================================================
# DATABASE CONNECTION URL
# ============================================================================
# This tells SQLAlchemy how to connect to the database
# Format: dialect+driver://[username[:password]]@[host][:port]/[database]
# 
# In our case:
# - sqlite: We're using SQLite (file-based database)
# - pysqlite: The Python driver for SQLite
# - ///./blog.db: Create a file named "blog.db" in the current directory
#   (The /// means "relative path", ./ means "current directory")
DATABASE_URL = "sqlite+pysqlite:///./blog.db"

# ============================================================================
# ENGINE
# ============================================================================
# The engine is the core connection to the database
# It manages the actual SQL communication with SQLite
# echo=True means: Print all SQL queries to the console (helpful for debugging)
engine = create_engine(DATABASE_URL, echo=True)

# ============================================================================
# SESSION FACTORY
# ============================================================================
# A session is a "conversation" with the database
# Think of it like a temporary workspace where you can:
# 1. Query (SELECT) records
# 2. Create (INSERT) new records
# 3. Update existing records
# 4. Delete records
#
# SessionLocal is a factory (a function) that creates new sessions
# autocommit=False: Changes aren't saved until you explicitly call db.commit()
# autoflush=False: Objects aren't flushed to DB until commit (safer)
# bind=engine: Connect this factory to our engine
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ============================================================================
# DECLARATIVE BASE
# ============================================================================
# This is the parent class for all our database models
# Any class that inherits from Base becomes a database table
# Example: class BlogPost(Base) → creates a "blog_posts" table
Base = declarative_base()

# ============================================================================
# DEPENDENCY INJECTION FUNCTION
# ============================================================================
# FastAPI uses "dependency injection" to provide database sessions to routes
# This is a generator function that:
# 1. Creates a database session
# 2. Yields it to the route (the route gets the session)
# 3. Closes it when done (cleanup)
#
# Usage in a route:
#   @router.get("/posts")
#   def get_posts(db: Session = Depends(get_db)):
#       posts = db.query(BlogPost).all()  # db is automatically provided!
def get_db():
    """
    Provides a database session for each request.
    
    FastAPI calls this function and injects the session into route handlers.
    The 'try/finally' ensures the session is always closed, even if errors occur.
    """
    db = SessionLocal()
    try:
        yield db  # Give the session to the route handler
    finally:
        db.close()  # Always clean up, even if something goes wrong

