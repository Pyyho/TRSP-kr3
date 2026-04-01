import secrets
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasicCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from database import init_db, get_db_connection
from models import (
    User, TodoCreate, TodoUpdate, Todo, LoginRequest,
    TokenResponse, UserResponse
)
from auth import (
    fake_users_db, get_password_hash, verify_password,
    create_jwt_token
)
from dependencies import auth_user, auth_docs, security_basic, require_admin, require_user

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("Initializing database...")
    init_db()
    print("Database initialized")

    # Initialize in-memory user DB with sample data
    if not fake_users_db:
        fake_users_db["alice"] = {
            "username": "alice",
            "hashed_password": get_password_hash("qwerty123"),
            "role": "admin"
        }
        fake_users_db["bob"] = {
            "username": "bob",
            "hashed_password": get_password_hash("password456"),
            "role": "user"
        }
        fake_users_db["charlie"] = {
            "username": "charlie",
            "hashed_password": get_password_hash("guestpass"),
            "role": "guest"
        }
        print("Sample users created")

    yield
    # Shutdown
    print("Shutting down...")


# Create FastAPI app
app = FastAPI(
    title="Server Application API",
    version="1.0.0",
    lifespan=lifespan
)

# Rate limiter setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ==================== Health Check ====================
@app.get("/")
async def root():
    return {"message": "Server is running!", "mode": settings.MODE}


@app.get("/health")
async def health_check():
    return {"status": "ok", "mode": settings.MODE}


# ==================== Задание 6.2 ====================
@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")
async def register(request: Request, user: User):
    """Register a new user with hashed password"""
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )

    hashed_password = get_password_hash(user.password)
    fake_users_db[user.username] = {
        "username": user.username,
        "hashed_password": hashed_password,
        "role": "user"
    }

    # Also save to SQLite
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (user.username, user.password)
            )
            conn.commit()
    except Exception as e:
        print(f"SQLite error: {e}")

    return {"message": "New user created"}


@app.get("/login", response_model=UserResponse)
async def login_basic(user: dict = Depends(auth_user)):
    """Login with Basic Auth"""
    return {"message": f"Welcome, {user['username']}!"}


# ==================== Задание 6.3 ====================
def configure_documentation():
    """Configure documentation based on environment mode"""
    if settings.MODE == "PROD":
        @app.get("/docs", include_in_schema=False)
        @app.get("/openapi.json", include_in_schema=False)
        @app.get("/redoc", include_in_schema=False)
        async def not_found():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    elif settings.MODE == "DEV":
        @app.get("/docs", include_in_schema=False)
        async def get_docs(_: bool = Depends(auth_docs)):
            from fastapi.openapi.docs import get_swagger_ui_html
            return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")

        @app.get("/openapi.json", include_in_schema=False)
        async def get_openapi(_: bool = Depends(auth_docs)):
            from fastapi.openapi.utils import get_openapi
            return get_openapi(title=app.title, version=app.version, routes=app.routes)

        @app.get("/redoc", include_in_schema=False)
        async def redoc_not_found():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    else:
        print(f"WARNING: Invalid MODE value: {settings.MODE}. Using DEV defaults.")


configure_documentation()


# ==================== Задание 6.4 & 6.5 ====================
@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def jwt_login(request: Request, login_data: LoginRequest):
    """JWT Login endpoint"""
    user = fake_users_db.get(login_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not secrets.compare_digest(login_data.username, user["username"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed"
        )

    if not verify_password(login_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed"
        )

    access_token = create_jwt_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected_resource")
async def protected_resource(user: dict = Depends(require_user)):
    """Protected resource requiring JWT authentication"""
    return {"message": "Access granted"}


# ==================== Задание 7.1 ====================
@app.get("/admin/resource")
async def admin_resource(user: dict = Depends(require_admin)):
    """Admin-only resource"""
    return {"message": f"Welcome admin {user['username']}! You have full access."}


@app.get("/user/resource")
async def user_resource(user: dict = Depends(require_user)):
    """User-level resource"""
    return {"message": f"Hello {user['username']}! You have read/write access."}


@app.get("/guest/resource")
async def guest_resource():
    """Guest resource - public read-only"""
    return {"message": "Welcome guest! You have read-only access."}


# ==================== Задание 8.1 ====================
@app.post("/sql/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def sql_register(user: User):
    """Register user in SQLite database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (user.username, user.password)
            )
            conn.commit()
        return {"message": "User registered successfully!"}
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


# ==================== Задание 8.2 ====================
@app.post("/todos", response_model=Todo, status_code=status.HTTP_201_CREATED)
async def create_todo(todo: TodoCreate, user: dict = Depends(require_user)):
    """Create a new todo item"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO todos (title, description, completed) VALUES (?, ?, ?)",
            (todo.title, todo.description, False)
        )
        conn.commit()

        todo_id = cursor.lastrowid
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        new_todo = cursor.fetchone()

    return Todo(
        id=new_todo["id"],
        title=new_todo["title"],
        description=new_todo["description"],
        completed=bool(new_todo["completed"])
    )


@app.get("/todos/{todo_id}", response_model=Todo)
async def get_todo(todo_id: int):
    """Get a single todo by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        todo = cursor.fetchone()

        if not todo:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Todo not found"
            )

    return Todo(
        id=todo["id"],
        title=todo["title"],
        description=todo["description"],
        completed=bool(todo["completed"])
    )


@app.put("/todos/{todo_id}", response_model=Todo)
async def update_todo(todo_id: int, todo_update: TodoUpdate, user: dict = Depends(require_user)):
    """Update a todo by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM todos WHERE id = ?", (todo_id,))
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Todo not found"
            )

        updates = []
        values = []

        if todo_update.title is not None:
            updates.append("title = ?")
            values.append(todo_update.title)
        if todo_update.description is not None:
            updates.append("description = ?")
            values.append(todo_update.description)
        if todo_update.completed is not None:
            updates.append("completed = ?")
            values.append(1 if todo_update.completed else 0)

        if updates:
            values.append(todo_id)
            query = f"UPDATE todos SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()

        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        updated = cursor.fetchone()

    return Todo(
        id=updated["id"],
        title=updated["title"],
        description=updated["description"],
        completed=bool(updated["completed"])
    )


@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int, user: dict = Depends(require_admin)):
    """Delete a todo by ID - Admin only"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM todos WHERE id = ?", (todo_id,))
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Todo not found"
            )

        cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()

    return {"message": f"Todo {todo_id} deleted successfully"}


@app.get("/todos")
async def list_todos(
        skip: int = 0,
        limit: int = 10,
        completed: Optional[bool] = None,
        user: dict = Depends(require_user)
):
    """List all todos with pagination and filtering"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        query = "SELECT id, title, description, completed FROM todos"
        params = []

        if completed is not None:
            query += " WHERE completed = ?"
            params.append(1 if completed else 0)

        query += " LIMIT ? OFFSET ?"
        params.extend([limit, skip])

        cursor.execute(query, params)
        todos = cursor.fetchall()

    return [
        Todo(
            id=todo["id"],
            title=todo["title"],
            description=todo["description"],
            completed=bool(todo["completed"])
        )
        for todo in todos
    ]


if __name__ == "__main__":
    import uvicorn

    print("Starting FastAPI server on http://127.0.0.1:8000")
    print("Press Ctrl+C to stop")
    uvicorn.run(app, host="127.0.0.1", port=8000)