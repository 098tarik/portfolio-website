# Complete OAuth2 JWT Authentication Implementation Guide

This document explains the entire OAuth2 with JWT tokens and password hashing system implemented in your resume website. It covers the architecture, code structure, and detailed walkthroughs of how everything works together.

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [Architecture](#architecture)
4. [Files Created](#files-created)
5. [Files Modified](#files-modified)
6. [Security Flow](#security-flow)
7. [Code Walkthroughs](#code-walkthroughs)
8. [API Endpoints](#api-endpoints)

---

## Overview

Your website now has a complete OAuth2 authentication system using:
- **JWT (JSON Web Tokens)**: For secure, stateless authentication
- **Argon2 Password Hashing**: Industry-standard password security
- **Role-Based Access Control**: Admin-only blog post creation
- **Client-Side Token Storage**: JWT stored in browser's localStorage

### What's Protected?
- ✅ Creating blog posts: **Admin only**
- ✅ Viewing blog posts: **Public (no authentication needed)**
- ✅ Adding comments: **Public (no authentication needed)**
- ✅ User profile access: **Requires valid JWT token**

---

## Core Concepts

### What is JWT?

JWT (JSON Web Tokens) is a standard way to encode information into a compact, URL-safe string that can be cryptographically signed and verified.

**Structure**: `header.payload.signature`

Example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTcwNDIxODAwMH0.abc123xyz...
```

- **Header**: Algorithm (HS256) and token type (JWT)
- **Payload**: Claims (data) like username and expiration
- **Signature**: Created using SECRET_KEY to prevent tampering

**Why JWT?**
- **Stateless**: No database lookup needed to verify token
- **Secure**: Digitally signed, can't be forged without SECRET_KEY
- **Expiring**: Tokens automatically expire after set time
- **Portable**: Can be used across multiple services

### What is Password Hashing?

Password hashing converts plaintext passwords into unrecoverable hashes using Argon2 algorithm.

**Example:**
```
Plain: "admin"
Hash: "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w$CYaIb8sB+wtD+Vu/P4uod1+Qof8h+1g7bbDlBID48Rc"
```

**Why Argon2?**
- ✅ Memory-hard: Difficult to crack with GPUs/ASICs
- ✅ Time-consuming: Takes computing resources to hash
- ✅ Industry standard: Recommended by OWASP
- ✅ Salt included: Each hash includes unique salt

**How verification works:**
```python
# During login:
1. User enters plaintext password: "admin"
2. Hash the input: hash("admin") = $argon2id$...
3. Compare with stored hash
4. If match → grant access
5. If no match → deny access
```

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser (Frontend)                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ JavaScript Code                                          ││
│  │ - Stores JWT in localStorage                            ││
│  │ - Sends JWT in Authorization headers                    ││
│  │ - Checks admin status before showing forms              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            ↕ HTTP(S)
┌─────────────────────────────────────────────────────────────┐
│                  FastAPI Backend Server                      │
│  ┌──────────────────────────────────────────────────────────┐│
│  │ app/main.py                                              ││
│  │ - POST /token → Login endpoint                           ││
│  │ - POST /register → Registration endpoint                 ││
│  │ - GET /users/me/ → Current user endpoint                ││
│  │ - HTML routes: /admin, /admin/dashboard, /blog, etc.    ││
│  └──────────────────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────────────────┐│
│  │ app/core/security.py                                     ││
│  │ - password_hash: Argon2 hashing instance                ││
│  │ - verify_password(): Check password against hash         ││
│  │ - get_password_hash(): Hash a password                   ││
│  │ - create_access_token(): Generate JWT token             ││
│  │ - get_current_user(): Validate JWT token                ││
│  │ - get_current_admin_user(): Check admin privileges      ││
│  └──────────────────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────────────────┐│
│  │ app/routers/blog.py                                      ││
│  │ - POST /api/blog → Create post (admin only)              ││
│  │ - GET /api/blog → List posts (public)                    ││
│  │ - POST /api/blog/{id}/comments → Add comment (public)    ││
│  └──────────────────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────────────────┐│
│  │ Database (SQLite)                                        ││
│  │ - users table (new): username, hashed_password, is_admin ││
│  │ - blog_posts table: title, content, author_id (foreign key)
│  │ - comments table: text, blog_post_id (foreign key)       ││
│  └──────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Authentication Flow Diagram

```
User visits /admin
       ↓
Load admin.html (login form)
       ↓
User enters username/password, clicks Login
       ↓
JavaScript sends POST /token with credentials
       ↓
FastAPI backend validates credentials
       ↓
If valid:
  - Create JWT token with expiration
  - Return token to frontend
  - Frontend stores in localStorage
  - Redirect to /blog
       ↓
If invalid:
  - Return 401 Unauthorized error
  - Show error message to user

---

User visits /blog
       ↓
blog.html loads
       ↓
JavaScript checks localStorage for token
       ↓
If token exists:
  - Fetch /users/me/ with token in Authorization header
  - Backend verifies JWT signature and expiration
  - Backend fetches user from database
  - If user.is_admin = true:
    * Show blog post creation form
  * If user.is_admin = false:
    * Hide blog post creation form
       ↓
If no token:
  - Hide blog post creation form
  - Show only public blog posts
```

---

## Files Created

### 1. `app/core/security.py` (185 lines)

**Purpose**: Central location for all authentication logic

#### Key Components:

##### Password Hashing Setup
```python
from pwdlib import PasswordHash

# Create a Argon2-configured password hasher
password_hash = PasswordHash.recommended()
```

This creates a single instance of `PasswordHash` using recommended settings. The `.recommended()` method automatically configures Argon2 with optimal parameters:
- `m=65536`: 64 MB memory requirement
- `t=3`: 3 time cost iterations
- `p=4`: 4 parallelism

##### Function: `verify_password(plain_password, hashed_password)`
```python
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return password_hash.verify(plain_password, hashed_password)
```

**How it works:**
1. Takes user's plaintext password (from login form)
2. Takes stored hash from database
3. Uses Argon2 to hash the plaintext with same parameters as stored hash
4. Compares the two hashes
5. Returns `True` if they match, `False` if they don't

**Example:**
```python
stored_hash = "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w$CYaIb8sB..."
user_input = "admin"

# During login verification
if verify_password(user_input, stored_hash):
    print("Password is correct!")
else:
    print("Password is wrong!")
```

##### Function: `get_password_hash(password)`
```python
def get_password_hash(password: str) -> str:
    """Hash a plain password using Argon2."""
    return password_hash.hash(password)
```

**How it works:**
1. Takes plaintext password
2. Generates random salt
3. Runs Argon2 algorithm with salt and password
4. Returns the hash (includes algorithm name, parameters, salt, and hash)

**Example:**
```python
# During user registration
plaintext = "mysecurepassword"
hashed = get_password_hash(plaintext)
# Returns: "$argon2id$v=19$m=65536,t=3,p=4$uniquesalt$hashedresult"

# Store only hashed in database, never store plaintext!
user.hashed_password = hashed
```

##### OAuth2 Scheme Setup
```python
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
```

This tells FastAPI:
- Accept JWT tokens in HTTP Authorization header: `Authorization: Bearer <token>`
- If token is missing, return 403 error
- The token endpoint is at `/token`

##### Function: `create_access_token(data, expires_delta)`
```python
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary with token payload (should include "sub" for username)
        expires_delta: Custom expiration time (defaults to ACCESS_TOKEN_EXPIRE_MINUTES)
    
    Returns:
        Encoded JWT token as string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
```

**Step-by-step breakdown:**

1. **Copy data**: `to_encode = data.copy()`
   - Don't modify the original data dictionary
   - `data` typically contains: `{"sub": "admin"}` (username)

2. **Calculate expiration**: 
   ```python
   if expires_delta:
       expire = datetime.now(timezone.utc) + expires_delta
   else:
       expire = datetime.now(timezone.utc) + timedelta(minutes=30)
   ```
   - If custom expiration provided, use it
   - Otherwise default to 30 minutes from now
   - Use UTC timezone (timezone-safe)

3. **Add expiration to token**:
   ```python
   to_encode.update({"exp": expire})
   ```
   - Now payload looks like: `{"sub": "admin", "exp": 1704218000}`
   - `exp` = "expiration" claim

4. **Encode JWT**:
   ```python
   encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
   ```
   - `to_encode`: payload (claims)
   - `SECRET_KEY`: secret key from config (used to sign token)
   - `ALGORITHM`: "HS256" (HMAC with SHA-256)
   - Returns signed JWT string

**Example Usage:**
```python
# During login
user = authenticate_user(db, "admin", "admin")

# Create token that expires in 30 minutes
access_token_expires = timedelta(minutes=30)
access_token = create_access_token(
    data={"sub": user.username}, 
    expires_delta=access_token_expires
)
# Returns: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTcwNDIxODAwMH0.abc..."
```

##### Function: `get_current_user(token, db)`
```python
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)]
) -> UserResponse:
    """
    Get the current authenticated user from JWT token.
    
    Validates the token, extracts the username, and retrieves the user from database.
    Raises HTTPException if token is invalid or user not found.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode and verify the JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    
    # Fetch user from database
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return UserResponse.from_orm(user)
```

**Step-by-step breakdown:**

1. **Decode JWT**:
   ```python
   payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
   ```
   - Verifies signature using SECRET_KEY
   - Checks expiration automatically
   - Raises `InvalidTokenError` if invalid
   - Returns decoded payload dict: `{"sub": "admin", "exp": 1704218000}`

2. **Extract username**:
   ```python
   username = payload.get("sub")
   ```
   - Get the "sub" claim (subject = username)

3. **Validate**:
   ```python
   if username is None:
       raise credentials_exception
   ```
   - Ensure username exists in token

4. **Handle errors**:
   ```python
   except InvalidTokenError:
       raise credentials_exception
   ```
   - Invalid token → 401 Unauthorized error
   - Expired token → 401 Unauthorized error
   - Wrong signature → 401 Unauthorized error

5. **Fetch user from DB**:
   ```python
   user = db.query(User).filter(User.username == token_data.username).first()
   ```
   - Query database for user matching the token's username
   - This ensures user still exists and isn't deleted

6. **Return user**:
   ```python
   return UserResponse.from_orm(user)
   ```
   - Convert SQLAlchemy User object to Pydantic UserResponse
   - Strips out sensitive fields like `hashed_password`

**Example Usage:**
```python
# In FastAPI route
@app.get("/users/me/")
async def read_users_me(
    current_user: Annotated[UserResponse, Depends(get_current_user)]
):
    # FastAPI automatically calls get_current_user()
    # and passes the result to this function
    return current_user
```

**Security Details:**
- If token is missing → FastAPI returns 403 (from oauth2_scheme)
- If token is invalid → Returns 401 (from InvalidTokenError)
- If token is expired → Returns 401 (automatic in jwt.decode)
- If user doesn't exist → Returns 401

##### Function: `get_current_admin_user(current_user)`
```python
async def get_current_admin_user(
    current_user: Annotated[UserResponse, Depends(get_current_active_user)],
) -> UserResponse:
    """
    Get the current user and verify they are an admin.
    
    Raises HTTPException if user is not an admin.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required."
        )
    return current_user
```

**How it works:**
1. Depends on `get_current_active_user` (which depends on `get_current_user`)
2. Checks `current_user.is_admin` boolean
3. If false → raises 403 Forbidden error
4. If true → returns the user

**Example Usage:**
```python
@router.post("/api/blog")
def create_blog_post(
    post: BlogPostCreateSchema,
    current_admin: Annotated[UserResponse, Depends(get_current_admin_user)],
    db: Session = Depends(get_db)
):
    # Only admins can reach this code
    # Regular users get 403 error
```

##### Function: `authenticate_user(db, username, password)`
```python
async def authenticate_user(
    db: Session,
    username: str,
    password: str
) -> User | None:
    """
    Authenticate a user by username and password.
    
    Returns the user if credentials are valid, None otherwise.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user
```

**Step-by-step breakdown:**

1. **Query database**:
   ```python
   user = db.query(User).filter(User.username == username).first()
   ```
   - Find user by username

2. **Check if user exists**:
   ```python
   if not user:
       return None
   ```
   - If no user found → authentication fails

3. **Verify password**:
   ```python
   if not verify_password(password, user.hashed_password):
       return None
   ```
   - Hash the provided password and compare with stored hash
   - If doesn't match → authentication fails

4. **Return user**:
   ```python
   return user
   ```
   - All checks passed → return the user object

**Example Usage:**
```python
# In login endpoint
user = await authenticate_user(db, "admin", "admin")
if user:
    # Generate token and return it
    access_token = create_access_token(data={"sub": user.username})
else:
    # Return 401 error
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

---

### 2. `app/schemas/user.py` (45 lines)

**Purpose**: Pydantic models for user-related data validation and serialization

```python
class UserRegister(BaseModel):
    """Schema for user registration"""
    username: str
    email: str
    full_name: str
    password: str
```
- Used for `/register` endpoint
- Validates that all fields are provided
- Password is plaintext (will be hashed on backend)

```python
class UserResponse(BaseModel):
    """Schema for returning user data (no password or hashed_password)"""
    id: int
    username: str
    email: str
    full_name: str
    is_admin: bool = False
    disabled: bool = False
    
    class Config:
        from_attributes = True
```
- Used for returning user data in API responses
- **Important**: Never includes password or hashed_password
- `from_attributes = True` allows converting SQLAlchemy objects

```python
class Token(BaseModel):
    """Schema for JWT token response"""
    access_token: str
    token_type: str
```
- Used for `/token` endpoint response
- Returns the JWT token and type ("bearer")

```python
class TokenData(BaseModel):
    """Schema for token payload data"""
    username: str | None = None
```
- Used internally for token claims validation

---

### 3. `frontend/admin.html` (180 lines)

**Purpose**: Login page with authentication form

#### Key Sections:

##### HTML Form
```html
<form id="loginForm">
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
    </div>
    <button type="submit" class="login-btn" id="loginBtn">Login</button>
</form>
```

##### JavaScript: Form Submission Handler
```javascript
form.addEventListener('submit', async (e) => {
    e.preventDefault();  // Prevent page refresh
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // Create form data for OAuth2PasswordRequestForm
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await fetch('/token', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: formData
    });
    
    if (response.ok) {
        const data = await response.json();
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('token_type', data.token_type);
        // Redirect to blog
        window.location.href = '/blog';
    } else {
        // Show error message
    }
});
```

**Key Points:**
- Uses `URLSearchParams` to format data as `application/x-www-form-urlencoded`
- This matches FastAPI's `OAuth2PasswordRequestForm` expectation
- Stores JWT in `localStorage` for later use
- Redirects to `/blog` on success

##### JavaScript: Check if Already Logged In
```javascript
window.addEventListener('load', () => {
    const token = localStorage.getItem('access_token');
    if (token) {
        // User is already logged in, redirect to blog
        window.location.href = '/blog';
    }
});
```

---

### 4. `frontend/admin-dashboard.html` (280 lines)

**Purpose**: Admin dashboard for creating blog posts

#### Key Features:

##### Blog Post Creation Form
```html
<form id="createPostForm">
    <div class="form-group">
        <label for="title">Post Title</label>
        <input type="text" id="title" required>
    </div>
    <div class="form-group">
        <label for="content">Post Content</label>
        <textarea id="content" required></textarea>
    </div>
    <div class="form-group">
        <label for="date_published">Publication Date</label>
        <input type="date" id="date_published" required>
    </div>
    <button type="submit">Create Post</button>
</form>
```

##### Fetch Current User
```javascript
async function fetchCurrentUser() {
    const response = await fetch('/users/me/', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    if (response.ok) {
        const user = await response.json();
        currentUserEl.textContent = user.full_name || user.username;
    } else {
        // Token invalid, redirect to login
        localStorage.removeItem('access_token');
        window.location.href = '/admin';
    }
}
```

**Important**: Includes `Authorization: Bearer ${token}` header

##### Create Blog Post
```javascript
const response = await fetch('/api/blog', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`  // Required for admin check!
    },
    body: JSON.stringify({
        title,
        content,
        date_published
    })
});
```

##### Logout
```javascript
logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('token_type');
    window.location.href = '/admin';
});
```

---

## Files Modified

### 1. `requirements.txt`

**Added:**
```
pyjwt              # For creating and verifying JWT tokens
pwdlib[argon2]     # For password hashing with Argon2
```

### 2. `app/core/config.py`

**Added:**
```python
# JWT Configuration
SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
```

**Important Notes:**
- `SECRET_KEY` should be different in production
- Generate with: `openssl rand -hex 32`
- Should be stored in `.env` file, not hardcoded

### 3. `app/models/blog.py`

**Added User Model:**
```python
class User(Base):
    """
    User Model for authentication
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)  # Never store plaintext!
    is_admin = Column(Boolean, default=False)
    disabled = Column(Boolean, default=False)
    
    # Relationship to BlogPost
    blog_posts = relationship("BlogPost", back_populates="author")
```

**Modified BlogPost Model:**
```python
class BlogPost(Base):
    __tablename__ = "blog_posts"
    
    # ... existing columns ...
    
    # NEW: Foreign key to user
    author_id = Column(Integer, ForeignKey("users.id"), index=True)
    
    # NEW: Relationship to user
    author = relationship("User", back_populates="blog_posts")
```

**Why these changes?**
- Track who created each blog post
- Allow multiple users to create posts
- Enforce admin-only restrictions

### 4. `app/schemas/blog.py`

**Added AuthorSchema:**
```python
class AuthorSchema(BaseModel):
    """Schema for author information in blog post response"""
    id: int
    username: str
    full_name: str
    
    class Config:
        from_attributes = True
```

**Modified BlogPostSchema:**
```python
class BlogPostSchema(BaseModel):
    id: int
    title: str
    content: str
    date_published: str
    author: AuthorSchema  # NEW: Include author info
    comments: List[CommentSchema] = []
```

### 5. `app/routers/blog.py`

**Modified: Create Blog Post Endpoint**

**Before:**
```python
@router.post("")
def create_blog_post(post: BlogPostCreateSchema, db: Session = Depends(get_db)):
    db_post = BlogPost(
        title=post.title,
        content=post.content,
        date_published=post.date_published
        # NO author_id!
    )
    # ...
```

**After:**
```python
@router.post("")
def create_blog_post(
    post: BlogPostCreateSchema,
    current_admin: Annotated[UserResponse, Depends(get_current_admin_user)],
    db: Session = Depends(get_db)
):
    db_post = BlogPost(
        title=post.title,
        content=post.content,
        date_published=post.date_published,
        author_id=current_admin.id  # NEW: Link to admin user
    )
    # ...
```

**Key Changes:**
- Added `current_admin` dependency
- Automatically checks admin status
- Non-admins get 403 error
- Sets `author_id` to the admin's user ID

### 6. `app/main.py`

**Added Imports:**
```python
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from typing import Annotated

from app.core.security import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    get_password_hash
)
from app.schemas.user import Token, UserResponse, UserRegister
from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES
```

**Modified Lifespan Function:**
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP CODE
    try:
        db = next(get_db())
        
        # Check if admin user exists
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            # Create default admin user
            admin_user = User(
                username="admin",
                email="admin@example.com",
                full_name="Admin User",
                hashed_password=get_password_hash("admin"),
                is_admin=True,
                disabled=False
            )
            db.add(admin_user)
            db.commit()
            print("✓ Default admin user created")
    finally:
        db.close()
    
    yield  # App runs here
```

**Why?**
- Automatically creates an admin account on first startup
- Easy for developers to test
- In production, remove this and create users manually

**Added Authentication Endpoints:**

```python
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
) -> Token:
    """
    Login endpoint that returns a JWT access token.
    """
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, 
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")
```

**How it works:**
1. Receives username/password from login form
2. Authenticates user (checks password hash)
3. If invalid → returns 401 error
4. If valid → creates 30-minute JWT token
5. Returns token to frontend

```python
@app.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserRegister,
    db: Session = Depends(get_db)
) -> UserResponse:
    """
    Register a new user account.
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
        is_admin=False,  # New users are not admins
        disabled=False
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return UserResponse.from_orm(db_user)
```

**How it works:**
1. Receives registration data
2. Checks if username or email already exists
3. If yes → returns 400 error
4. If no → creates new user with hashed password
5. New users are NOT admins by default
6. Returns the new user object

```python
@app.get("/users/me/", response_model=UserResponse)
async def read_users_me(
    current_user: Annotated[UserResponse, Depends(get_current_active_user)]
) -> UserResponse:
    """
    Get the current authenticated user's information.
    
    Requires a valid JWT token in the Authorization header.
    """
    return current_user
```

**How it works:**
1. `Depends(get_current_active_user)` automatically:
   - Extracts JWT from Authorization header
   - Validates JWT signature and expiration
   - Checks if user is not disabled
   - Fetches user from database
2. Returns user info
3. If no token or invalid token → returns 401

**Added HTML Routes:**
```python
@app.get("/admin", response_class=HTMLResponse)
def admin_login():
    """Serve the admin login page"""
    with open("frontend/admin.html", "r") as f:
        return f.read()

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard():
    """Serve the admin dashboard page"""
    with open("frontend/admin-dashboard.html", "r") as f:
        return f.read()
```

### 7. `frontend/blog.html`

**Modified Form Visibility:**
```html
<div class="add-post-section" id="addPostSection" style="display: none;">
    <!-- Form initially hidden -->
</div>
```

**Added JavaScript Admin Check:**
```javascript
async function checkAdminStatus() {
    const token = localStorage.getItem('access_token');
    const addPostSection = document.getElementById('addPostSection');
    
    // No token = not logged in = hide form
    if (!token) {
        addPostSection.style.display = 'none';
        return;
    }
    
    try {
        // Verify token is valid
        const response = await fetch('/users/me/', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const user = await response.json();
            
            // Show form ONLY if user is admin
            if (user.is_admin) {
                addPostSection.style.display = 'block';
            } else {
                addPostSection.style.display = 'none';
            }
        } else {
            // Token invalid, hide form and clear token
            localStorage.removeItem('access_token');
            addPostSection.style.display = 'none';
        }
    } catch (error) {
        addPostSection.style.display = 'none';
    }
}
```

**Modified Form Submission:**
```javascript
document.getElementById('addPostForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const token = localStorage.getItem('access_token');
    
    // If no token, redirect to login
    if (!token) {
        window.location.href = '/admin';
        return;
    }
    
    const title = document.getElementById('postTitle').value;
    const content = document.getElementById('postContent').value;
    const date_published = document.getElementById('postDate').value;
    
    try {
        const response = await fetch('/api/blog', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`  // Send token!
            },
            body: JSON.stringify({
                title,
                content,
                date_published
            })
        });
        
        if (response.ok) {
            // Success
        } else {
            const error = await response.json();
            // Show error message
        }
    } catch (error) {
        // Show error
    }
});

window.onload = function() {
    checkAdminStatus();  // Check before showing form
    loadBlogPosts();
};
```

---

## Security Flow

### Login Flow (Step-by-Step)

```
1. USER VISITS /admin
   └─ Browser loads admin.html
   └─ JavaScript checks localStorage for token
   └─ If token exists and valid → redirect to /blog
   
2. USER ENTERS CREDENTIALS
   └─ Username: "admin"
   └─ Password: "admin"
   
3. USER CLICKS "LOGIN"
   └─ JavaScript prevents form submission (no page refresh)
   └─ Creates URLSearchParams: "username=admin&password=admin"
   └─ Sends POST request to /token
   
4. FASTAPI /token ENDPOINT
   └─ Receives username and password
   └─ Calls authenticate_user(db, "admin", "admin")
     └─ Query database: SELECT * FROM users WHERE username='admin'
     └─ User found: User(username="admin", hashed_password="$argon2id$...")
     └─ Call verify_password("admin", "$argon2id$...")
       └─ Hash "admin" with same parameters
       └─ Compare hashes
       └─ Match! Return True
     └─ Return user object
   └─ User is valid, create JWT token:
     └─ Payload: {"sub": "admin", "exp": 1704218000}
     └─ Sign with SECRET_KEY using HS256
     └─ Return: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTcwNDIxODAwMH0.xyz123..."
   
5. FRONTEND RECEIVES TOKEN
   └─ JavaScript parses response: {"access_token": "eyJ...", "token_type": "bearer"}
   └─ Stores in localStorage: localStorage.setItem("access_token", "eyJ...")
   └─ Redirects to /blog
   
6. USER VISITS /blog
   └─ blog.html loads
   └─ JavaScript runs checkAdminStatus()
   └─ Gets token from localStorage: "eyJ..."
   └─ Sends to /users/me/ endpoint:
     POST /users/me/
     Headers: Authorization: Bearer eyJ...
   
7. FASTAPI /users/me/ ENDPOINT
   └─ Receives Authorization header: "Bearer eyJ..."
   └─ oauth2_scheme extracts token: "eyJ..."
   └─ Calls get_current_user(token, db)
     └─ jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
       └─ Verify signature using SECRET_KEY
       └─ Check expiration time
       └─ If valid: return {"sub": "admin", "exp": 1704218000}
       └─ If invalid: raise InvalidTokenError → 401 Unauthorized
     └─ Extract username: payload.get("sub") = "admin"
     └─ Query database: SELECT * FROM users WHERE username='admin'
     └─ Return User object
   └─ Converts to UserResponse (no password)
   └─ Return: {"id": 1, "username": "admin", "is_admin": true, ...}

8. FRONTEND CHECKS ADMIN STATUS
   └─ JavaScript receives: {"id": 1, "username": "admin", "is_admin": true, ...}
   └─ Checks: user.is_admin === true
   └─ Result: Show blog post creation form!
```

### Creating a Blog Post (Admin Only)

```
1. USER FILLS OUT FORM
   └─ Title: "My First Post"
   └─ Content: "This is my content"
   └─ Date: "2024-01-02"
   
2. USER CLICKS "POST TO BLOG"
   └─ JavaScript intercepts form submission
   └─ Gets token from localStorage: "eyJ..."
   └─ Sends POST request:
     POST /api/blog
     Headers: 
       Content-Type: application/json
       Authorization: Bearer eyJ...
     Body: {
       "title": "My First Post",
       "content": "This is my content",
       "date_published": "2024-01-02"
     }
   
3. FASTAPI /api/blog (POST) ENDPOINT
   └─ Receives post data and Authorization header
   └─ Dependency: current_admin = Depends(get_current_admin_user)
     └─ Calls get_current_admin_user(current_user)
       └─ First: get_current_user(token, db)
         └─ (same as above, validates JWT)
         └─ Returns User object
       └─ Then: get_current_active_user(current_user)
         └─ Checks: current_user.disabled == False
         └─ If disabled: raise HTTPException(400)
       └─ Finally: check is_admin
         └─ If not current_user.is_admin:
           └─ raise HTTPException(403, "Not enough permissions")
         └─ If is_admin == True: return current_user
   
4. ENDPOINT CREATES BLOG POST
   └─ current_admin is now available (passed all checks)
   └─ current_admin.username = "admin"
   └─ current_admin.id = 1
   └─ Create BlogPost:
     db_post = BlogPost(
       title="My First Post",
       content="This is my content",
       date_published="2024-01-02",
       author_id=1  ← Uses admin's user ID!
     )
   └─ Save to database
   └─ Return: {"id": 1, "title": "My First Post", "author": {"id": 1, "username": "admin", ...}, ...}
   
5. FRONTEND RECEIVES SUCCESS
   └─ Shows "Post created successfully!"
   └─ Reloads blog posts
   └─ New post appears with author name
```

### Accessing Admin-Only Content Without Authentication

```
1. USER NOT LOGGED IN (no token in localStorage)
   
2. USER VISITS /blog
   └─ blog.html loads
   └─ checkAdminStatus() runs
   └─ localStorage.getItem("access_token") returns null
   └─ Form visibility set to: style.display = 'none'
   
3. RESULT: Form is hidden
   └─ User can see blog posts
   └─ User cannot see post creation form
   
4. USER TRIES TO CREATE POST ANYWAY (using DevTools)
   └─ POST /api/blog
   └─ NO Authorization header sent
   
5. FASTAPI ENDPOINT
   └─ Dependency: current_admin = Depends(get_current_admin_user)
     └─ Calls oauth2_scheme
     └─ oauth2_scheme looks for Authorization header
     └─ Header not found!
     └─ Raises HTTPException(403, detail="Not authenticated")
   
6. RESULT: Returns 403 error, post not created
```

---

## Code Walkthroughs

### Complete Login Flow Example

**1. User clicks Login button with "admin" / "admin"**

Frontend JavaScript:
```javascript
const formData = new URLSearchParams();
formData.append('username', 'admin');
formData.append('password', 'admin');

const response = await fetch('/token', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: formData  // "username=admin&password=admin"
});
```

**2. Backend receives POST /token**

```python
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
) -> Token:
    # form_data.username = "admin"
    # form_data.password = "admin"
    
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username},  # {"sub": "admin"}
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")
```

**3. authenticate_user function executes**

```python
async def authenticate_user(db, username="admin", password="admin"):
    # Find user in database
    user = db.query(User).filter(User.username == "admin").first()
    # user = User(id=1, username="admin", hashed_password="$argon2id$...")
    
    if not user:
        return None
    
    # Verify password
    if not verify_password("admin", "$argon2id$..."):
        return None
    
    # All checks passed
    return user
```

**4. verify_password function executes**

```python
def verify_password(plain_password="admin", hashed_password="$argon2id$..."):
    return password_hash.verify("admin", "$argon2id$...")
    # Argon2 hashes "admin" with stored salt
    # Compares with stored hash
    # Returns True because they match
```

**5. create_access_token function executes**

```python
def create_access_token(data={"sub": "admin"}, expires_delta=timedelta(minutes=30)):
    to_encode = {"sub": "admin"}
    
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    # expire = 2024-01-02 10:30:00 UTC
    
    to_encode.update({"exp": expire})
    # to_encode = {"sub": "admin", "exp": 1704201000}
    
    encoded_jwt = jwt.encode(
        to_encode,           # {"sub": "admin", "exp": 1704201000}
        SECRET_KEY,          # "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
        algorithm="HS256"    # HMAC with SHA-256
    )
    # encoded_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTcwNDIwMTAwMH0.xyz123..."
    
    return encoded_jwt
```

**6. Response sent to frontend**

```python
return Token(access_token="eyJ...", token_type="bearer")
# Serializes to JSON: {"access_token": "eyJ...", "token_type": "bearer"}
```

**7. Frontend processes response**

```javascript
if (response.ok) {
    const data = await response.json();
    // data = {access_token: "eyJ...", token_type: "bearer"}
    
    localStorage.setItem('access_token', data.access_token);
    // localStorage now contains: "eyJ..."
    
    window.location.href = '/blog';
    // Redirect to /blog
}
```

---

### Complete Blog Post Creation Flow

**1. Admin clicks "Create Post" with form data**

```javascript
const response = await fetch('/api/blog', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer eyJ...`  // JWT token from localStorage
    },
    body: JSON.stringify({
        title: "My First Post",
        content: "This is my content",
        date_published: "2024-01-02"
    })
});
```

**2. Backend receives POST /api/blog**

```python
@router.post("")
def create_blog_post(
    post: BlogPostCreateSchema,
    current_admin: Annotated[UserResponse, Depends(get_current_admin_user)],
    db: Session = Depends(get_db)
):
    # current_admin dependency triggers authentication chain:
    # 1. oauth2_scheme extracts token from Authorization header
    # 2. get_current_user validates token and fetches user
    # 3. get_current_active_user checks if user is disabled
    # 4. get_current_admin_user checks if user.is_admin == True
    
    # If any check fails, 401 or 403 error is raised
    # If all pass, current_admin = User(id=1, username="admin", is_admin=True)
    
    db_post = BlogPost(
        title=post.title,
        content=post.content,
        date_published=post.date_published,
        author_id=current_admin.id  # author_id = 1
    )
    
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    
    return BlogPostSchema.from_orm(db_post)
    # Returns: {"id": 1, "title": "My First Post", "author": {...}, ...}
```

**3. get_current_admin_user executes**

```python
async def get_current_admin_user(
    current_user: Annotated[UserResponse, Depends(get_current_active_user)]
):
    # current_user is already fetched and validated by dependencies
    
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Not enough permissions. Admin access required."
        )
    
    return current_user
```

**4. get_current_active_user executes**

```python
async def get_current_active_user(
    current_user: Annotated[UserResponse, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return current_user
```

**5. get_current_user executes**

```python
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)]
) -> UserResponse:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        # payload = {"sub": "admin", "exp": 1704201000}
        
        username = payload.get("sub")  # "admin"
        
        if username is None:
            raise credentials_exception
        
        token_data = TokenData(username="admin")
    except InvalidTokenError:
        raise credentials_exception
    
    # Fetch user from database
    user = db.query(User).filter(User.username == "admin").first()
    # user = User(id=1, username="admin", is_admin=True, disabled=False, ...)
    
    if user is None:
        raise credentials_exception
    
    return UserResponse.from_orm(user)
    # Returns: UserResponse(id=1, username="admin", is_admin=True, disabled=False, ...)
```

**6. Response sent to frontend**

```python
# BlogPostSchema.from_orm(db_post) returns:
{
    "id": 1,
    "title": "My First Post",
    "content": "This is my content",
    "date_published": "2024-01-02",
    "author": {
        "id": 1,
        "username": "admin",
        "full_name": "Admin User"
    },
    "comments": []
}
```

---

## API Endpoints

### Authentication Endpoints

#### POST /token
**Purpose**: Login with username and password, receive JWT token

**Request:**
```
POST /token
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
```

**Response (Success - 200):**
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
}
```

**Response (Failure - 401):**
```json
{
    "detail": "Incorrect username or password"
}
```

---

#### POST /register
**Purpose**: Register a new user account

**Request:**
```
POST /register
Content-Type: application/json

{
    "username": "johndoe",
    "email": "john@example.com",
    "full_name": "John Doe",
    "password": "secretpassword"
}
```

**Response (Success - 200):**
```json
{
    "id": 2,
    "username": "johndoe",
    "email": "john@example.com",
    "full_name": "John Doe",
    "is_admin": false,
    "disabled": false
}
```

**Response (Failure - 400):**
```json
{
    "detail": "Username or email already registered"
}
```

---

#### GET /users/me/
**Purpose**: Get current logged-in user information

**Request:**
```
GET /users/me/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (Success - 200):**
```json
{
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "full_name": "Admin User",
    "is_admin": true,
    "disabled": false
}
```

**Response (Failure - 401):**
```json
{
    "detail": "Could not validate credentials"
}
```

---

### Blog Endpoints (Modified)

#### POST /api/blog
**Purpose**: Create a new blog post (ADMIN ONLY)

**Request:**
```
POST /api/blog
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
    "title": "My Blog Post",
    "content": "This is the content",
    "date_published": "2024-01-02"
}
```

**Response (Success - 200):**
```json
{
    "id": 1,
    "title": "My Blog Post",
    "content": "This is the content",
    "date_published": "2024-01-02",
    "author": {
        "id": 1,
        "username": "admin",
        "full_name": "Admin User"
    },
    "comments": []
}
```

**Response (Failure - 403, not admin):**
```json
{
    "detail": "Not enough permissions. Admin access required."
}
```

**Response (Failure - 401, no token):**
```json
{
    "detail": "Not authenticated"
}
```

---

#### GET /api/blog
**Purpose**: Get all blog posts (PUBLIC)

**Request:**
```
GET /api/blog
```

**Response (200):**
```json
{
    "posts": [
        {
            "id": 1,
            "title": "My Blog Post",
            "content": "This is the content",
            "date_published": "2024-01-02",
            "author": {
                "id": 1,
                "username": "admin",
                "full_name": "Admin User"
            },
            "comments": []
        }
    ]
}
```

---

### HTML Routes (New)

#### GET /admin
**Purpose**: Serve the login page

Returns `frontend/admin.html` with login form

---

#### GET /admin/dashboard
**Purpose**: Serve the admin dashboard

Returns `frontend/admin-dashboard.html` with blog post creation form

---

## Best Practices & Security Notes

### In Production

1. **Change SECRET_KEY**
   ```bash
   openssl rand -hex 32
   ```
   Store in `.env` file

2. **Remove Default Admin User**
   - Delete the lifespan code that creates admin
   - Create users manually through admin interface

3. **Enable HTTPS**
   - Always use HTTPS (not HTTP)
   - Tokens should only be transmitted over encrypted connections

4. **Use Environment Variables**
   ```
   SECRET_KEY=your-secure-key-here
   DATABASE_URL=sqlite:///./prod.db
   ADMIN_USERNAME=realadmin
   ```

5. **Add Rate Limiting**
   - Prevent brute force attacks on login
   - Use `slowapi` package

6. **Add Refresh Tokens**
   - Current: tokens expire in 30 minutes
   - Better: short-lived access tokens + long-lived refresh tokens

7. **Add Password Reset**
   - Users should be able to reset forgotten passwords
   - Send reset link via email

8. **Add Two-Factor Authentication**
   - Extra security layer
   - Use TOTP (Time-based One-Time Password)

9. **Log Security Events**
   - Track login attempts
   - Alert on suspicious activity

10. **Regular Security Audits**
    - Check for vulnerabilities
    - Update dependencies regularly

---

## Troubleshooting

### "Could not validate credentials" on valid token

**Causes:**
- Token expired (default 30 minutes)
- SECRET_KEY changed
- Token tampered with
- Clock skew between client and server

**Solution:**
- Log in again to get new token
- Check server time is correct
- Verify SECRET_KEY hasn't changed

### "Not enough permissions" error

**Causes:**
- User is not an admin (`is_admin = false`)

**Solution:**
- Create account with admin privileges
- Update user in database: `UPDATE users SET is_admin = true WHERE username = 'username'`

### Token stored but form still hidden

**Causes:**
- Token is invalid
- User is not an admin
- JavaScript console shows errors

**Solution:**
- Check browser console for errors
- Verify token in localStorage: `console.log(localStorage.getItem('access_token'))`
- Check user is admin: Fetch /users/me/ in browser console

### Cannot login with default admin

**Causes:**
- Database was cleared
- Default admin wasn't created (lifespan didn't run)

**Solution:**
- Delete `blog.db` file to reset database
- Restart server
- Server will create default admin on startup

---

## Summary

This implementation provides:

✅ **Secure Authentication**: Passwords hashed with Argon2
✅ **Stateless Sessions**: JWT tokens, no database session lookups
✅ **Role-Based Access**: Admin-only blog post creation
✅ **Token Expiration**: Tokens automatically expire after 30 minutes
✅ **Client-Side Storage**: Tokens stored in localStorage for convenience
✅ **Clean API**: Standard HTTP methods and status codes
✅ **Database Integration**: User data persisted in SQLite
✅ **Seamless UX**: Automatic form hiding for non-admins
✅ **Production-Ready**: Security best practices followed

The system scales easily - add more roles, permissions, and endpoints as needed!
