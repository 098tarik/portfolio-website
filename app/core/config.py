import os
from dotenv import load_dotenv

load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./blog.db")

# App configuration
DEBUG = os.getenv("DEBUG", "True") == "True"
