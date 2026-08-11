import time
import secrets
import httpx
import os
from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

import models
import schemas
import security
from database import get_db
from email_service import send_otp_email

router = APIRouter(prefix="/auth", tags=["Auth"])
limiter = Limiter(key_func=get_remote_address)

OTP_EXP_SECONDS = 180
pending_registrations = {}
pending_resets = {}
pending_login_otps = {}


async def verify_recaptcha(token: str):
    secret_key = os.getenv("RECAPTCHA_SECRET_KEY")
    if not secret_key:
        raise HTTPException(
            status_code=500, detail="Konfigurasi recaptcha belum diatur"
        )

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": secret_key, "response": token},
        )
        result = response.json()
        if not result.get("success"):
            raise HTTPException(
                status_code=400, detail="Verifikasi ReCaptcha gagal, mohon coba lagi."
            )


@router.post("/register/request")
@limiter.limit("100/minute")
async def request_registration(
    request: Request, payload: schemas.UserRegister, db: Session = Depends(get_db)
):
    await verify_recaptcha(payload.recaptcha_token)
    if db.query(models.UserDB).filter(models.UserDB.email == payload.email).first():
        raise HTTPException(status_code=409, detail="Email ini sudah terdaftar.")

    otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    pending_registrations[payload.email] = {
        "password": security.hash_password(payload.password),
        "name": payload.name,
        "profile_picture": payload.profile_picture,
        "country": payload.country,
        "postal_code": payload.postal_code,
        "city": payload.city,
        "province": payload.province,
        "otp": otp,
        "exp": time.time() + OTP_EXP_SECONDS,
    }
    await send_otp_email(payload.email, otp, "register")
    return {"message": "OTP berhasil dikirim."}


@router.post("/register/verify")
@limiter.limit("100/minute")
async def verify_registration(
    request: Request, payload: schemas.VerifyRegistration, db: Session = Depends(get_db)
):
    record = pending_registrations.get(payload.email)
    if not record or time.time() > record["exp"]:
        if payload.email in pending_registrations:
            del pending_registrations[payload.email]
        raise HTTPException(
            status_code=400, detail="Kode OTP kedaluwarsa. Silakan daftar ulang."
        )

    if record["otp"] != str(payload.otp):
        raise HTTPException(status_code=400, detail="Kode OTP salah.")

    new_user = models.UserDB(
        email=payload.email,
        hashed_password=record["password"],
        name=record["name"],
        profile_picture=record["profile_picture"],
        country=record["country"],
        postal_code=record["postal_code"],
        city=record["city"],
        province=record["province"],
        role="user",
    )
    db.add(new_user)
    db.commit()
    del pending_registrations[payload.email]
    return {"message": "Akun berhasil dibuat."}


@router.post("/login")
@limiter.limit("100/minute")
async def login(
    request: Request, payload: schemas.UserLogin, db: Session = Depends(get_db)
):
    user = db.query(models.UserDB).filter(models.UserDB.email == payload.email).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Email belum terdaftar, silahkan registrasi terlebih dahulu",
        )

    if not security.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="password salah")

    token = security.create_access_token(user.email)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/password/forgot")
@limiter.limit("100/minute")
async def forgot_password(
    request: Request, payload: schemas.ForgotPassword, db: Session = Depends(get_db)
):
    await verify_recaptcha(payload.recaptcha_token)
    user = db.query(models.UserDB).filter(models.UserDB.email == payload.email).first()
    if not user:
        return {"message": "Jika email terdaftar, kode OTP telah dikirim."}

    otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    pending_resets[payload.email] = {"otp": otp, "exp": time.time() + OTP_EXP_SECONDS}
    await send_otp_email(payload.email, otp, "reset")
    return {"message": "Jika email terdaftar, kode OTP telah dikirim."}


@router.post("/password/reset")
@limiter.limit("100/minute")
async def reset_password(
    request: Request, payload: schemas.ResetPassword, db: Session = Depends(get_db)
):
    record = pending_resets.get(payload.email)
    if not record or time.time() > record["exp"]:
        if payload.email in pending_resets:
            del pending_resets[payload.email]
        raise HTTPException(status_code=400, detail="Kode OTP kedaluwarsa.")

    if record["otp"] != str(payload.otp):
        raise HTTPException(status_code=400, detail="Kode OTP salah.")

    user = db.query(models.UserDB).filter(models.UserDB.email == payload.email).first()
    if user:
        user.hashed_password = security.hash_password(payload.new_password)
        db.commit()

    del pending_resets[payload.email]
    return {"message": "Password berhasil diubah."}


@router.post("/login/otp/request")
@limiter.limit("100/minute")
async def request_login_otp(
    request: Request, payload: schemas.LoginOTPRequest, db: Session = Depends(get_db)
):
    await verify_recaptcha(payload.recaptcha_token)
    user = db.query(models.UserDB).filter(models.UserDB.email == payload.email).first()
    if not user:
        return {"message": "Jika email terdaftar, OTP telah dikirim."}

    otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    pending_login_otps[payload.email] = {"otp": otp, "exp": time.time() + OTP_EXP_SECONDS}
    await send_otp_email(payload.email, otp, "login")
    return {"message": "Jika email terdaftar, OTP telah dikirim."}


@router.post("/login/otp/verify")
@limiter.limit("5/minute")
async def verify_login_otp(
    request: Request, payload: schemas.LoginOTPVerify, db: Session = Depends(get_db)
):
    record = pending_login_otps.get(payload.email)
    if not record or time.time() > record["exp"]:
        if payload.email in pending_login_otps:
            del pending_login_otps[payload.email]
        raise HTTPException(status_code=400, detail="Kode OTP kedaluwarsa.")

    if record["otp"] != str(payload.otp):
        raise HTTPException(status_code=400, detail="Kode OTP salah.")

    user = db.query(models.UserDB).filter(models.UserDB.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Akun tidak ditemukan.")

    del pending_login_otps[payload.email]
    token = security.create_access_token(user.email)
    return {"access_token": token, "token_type": "bearer"}