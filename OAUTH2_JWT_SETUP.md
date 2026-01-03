# OAuth2 with JWT Authentication Setup

This document explains the OAuth2 and JWT implementation for your FastAPI resume website.

## What Was Implemented

### 1. **Security Module** (`app/core/security.py`)
- **Password Hashing**: Uses `pwdlib` with Argon2 algorithm
  - `verify_password()`: Verifies plain password against hash
  - `get_password_hash()`: Hashes passwords securely
  
- **JWT Token Management**:
  - `create_access_token()`: Creates JWT tokens with expiration
  - `oauth2_scheme`: OAuth2 password flow configuration
  
- **Authentication Dependencies**:
  - `get_current_user()`: Validates JWT token and returns user
  - `get_current_active_user()`: Ensures user is not disabled
  - `get_current_admin_user()`: Verifies user has admin privileges
  - `authenticate_user()`: Validates username/password

### 2. **User Model** (`app/models/blog.py`)
Added a `User` table with:
- `username` (unique): For login
- `email` (unique): User's email address
- `full_name`: Display name
- `hashed_password`: Securely hashed password
- `is_admin`: Boolean flag for admin access
- `disabled`: Can deactivate accounts
- Relationship to `BlogPost` (one-to-many)

### 3. **User Schemas** (`app/schemas/user.py`)
- `UserRegister`: For registration requests
- `UserLogin`: For login requests
- `UserResponse`: For API responses (no password exposure)
- `Token`: JWT token response
- `TokenData`: Token payload data

### 4. **Authentication Endpoints** (`app/main.py`)

#### `POST /token`
Login endpoint that returns a JWT access token.
```bash
curl -X POST "http://localhost:8000/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

#### `POST /register`
Register a new user account.
```bash
curl -X POST "http://localhost:8000/register" \
  -H "Content-Type: application/json" \
  -d {
    "username": "johndoe",
    "email": "john@example.com",
    "full_name": "John Doe",
    "password": "secretpassword"
  }
```

#### `GET /users/me/`
Get the current authenticated user's information.
```bash
curl -X GET "http://localhost:8000/users/me/" \
  -H "Authorization: Bearer <your_token>"
```

### 5. **Admin-Only Blog Creation**
Updated `POST /api/blog` endpoint:
- **Required**: Valid JWT token + admin role
- **Returns**: 403 Forbidden error if user is not an admin
- Only admins can create blog posts
- Regular users can still view blog posts and add comments

## Default Admin User

On first startup, a default admin user is automatically created:
- **Username**: `admin`
- **Password**: `admin`
- **Email**: `admin@example.com`

⚠️ **IMPORTANT**: Change this password in production!

## JWT Token Details

- **Algorithm**: HS256
- **Secret Key**: Stored in environment variable `SECRET_KEY`
- **Expiration**: 30 minutes (configurable in `app/core/config.py`)
- **Key Location**: `app/core/config.py`

## Testing the Authentication Flow

### 1. Login and Get Token
```bash
curl -X POST "http://localhost:8000/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin"
```

### 2. Use Token to Access Protected Endpoints
```bash
curl -X GET "http://localhost:8000/users/me/" \
  -H "Authorization: Bearer <token_from_step_1>"
```

### 3. Create a Blog Post (Admin Only)
```bash
curl -X POST "http://localhost:8000/api/blog" \
  -H "Authorization: Bearer <token_from_step_1>" \
  -H "Content-Type: application/json" \
  -d {
    "title": "My First Post",
    "content": "This is the content",
    "date_published": "2024-01-02"
  }
```

### 4. View Blog Posts (Public, No Auth Required)
```bash
curl -X GET "http://localhost:8000/api/blog"
```

## Database Changes

The SQLite database now includes:
- `users` table: Stores user accounts with hashed passwords
- `blog_posts` table: Updated with `author_id` foreign key
- Relationships properly configured for ORM

## Security Features

✅ **Passwords**: Hashed with Argon2 (industry standard)
✅ **JWT Tokens**: Signed with SECRET_KEY (cryptographically secure)
✅ **Token Expiration**: Tokens expire after 30 minutes
✅ **Admin-Only Operations**: Blog creation restricted to admins
✅ **Disabled Accounts**: Can deactivate user accounts
✅ **CORS Protection**: Configurable cross-origin resource sharing

## Configuration

Edit `app/core/config.py` to customize:
- `SECRET_KEY`: Change this in production (use `openssl rand -hex 32`)
- `ALGORITHM`: JWT signing algorithm (default: HS256)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Token expiration time (default: 30)

## Next Steps

1. **Start the server**:
   ```bash
   uvicorn resume_website.main:app --reload
   ```

2. **Access API documentation**:
   - Swagger UI: http://127.0.0.1:8000/docs
   - ReDoc: http://127.0.0.1:8000/redoc

3. **In production**:
   - Change the default admin password
   - Update `SECRET_KEY` to a secure random value
   - Use environment variables for sensitive config
   - Enable HTTPS/TLS
   - Implement password reset functionality
   - Add rate limiting to prevent brute force attacks
   - Consider adding refresh tokens for better security
