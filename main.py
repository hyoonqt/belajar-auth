import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv()

import models
import security
from database import engine, get_db
from routers import auth, users, admin

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

def run_migrations():
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    existing_cols = {c["name"] for c in inspector.get_columns("users")}
    with engine.begin() as conn:
        if "name" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN name VARCHAR"))
        if "role" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR NOT NULL DEFAULT 'user'"))
        if "profile_picture" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN profile_picture VARCHAR"))
        if "country" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN country VARCHAR"))
        if "postal_code" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN postal_code VARCHAR"))
        if "city" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN city VARCHAR"))
        if "province" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN province VARCHAR"))
        if "district" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN district VARCHAR"))

def seed_default_admin():
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if not admin_email or not admin_password:
        return

    db = next(get_db())
    try:
        existing = db.query(models.UserDB).filter(models.UserDB.email == admin_email).first()
        if existing:
            if existing.role != "admin":
                existing.role = "admin"
                db.commit()
            return

        admin = models.UserDB(
            email=admin_email,
            hashed_password=security.hash_password(admin_password),
            name="Administrator",
            role="admin",
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()

models.Base.metadata.create_all(bind=engine)
run_migrations()
seed_default_admin()

app = FastAPI(title="Production Ready Auth")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Daftarkan Router
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)

@app.get("/")
def home():
    return {"message": "hello, world!"}