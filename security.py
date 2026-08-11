import os
import time
import bcrypt
import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import models
from database import get_db


JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_key_dev")
JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 2628000

auth_scheme = HTTPBearer()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def create_access_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": int(time.time() + JWT_EXP_SECONDS),
        "iat": int(time.time()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401, detail="Sesi berakhir, silakan login ulang."
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token tidak valid.")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(auth_scheme),
    db: Session = Depends(get_db),
):
    email = decode_token(credentials.credentials)
    user = db.query(models.UserDB).filter(models.UserDB.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Akun tidak ditemukan.")
    return user

