import time
import secrets
from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

import models
import schemas
import security
from database import get_db
from email_service import send_otp_email
from routers.auth import OTP_EXP_SECONDS
from security import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])
limiter = Limiter(key_func=get_remote_address)

pending_deletions = {}
pending_profile_otps = {}

@router.get("/me", response_model=schemas.UserOut)
async def profile(user: models.UserDB = Depends(get_current_user)):
    return user

@router.post("/me/password/otp/request")
@limiter.limit("3/minute")
async def request_profile_otp(
    request: Request, user: models.UserDB = Depends(get_current_user)
):
    otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    pending_profile_otps[user.email] = {"otp": otp, "exp": time.time() + OTP_EXP_SECONDS}
    await send_otp_email(user.email, otp, "update_pwd")
    return {"message": "OTP untuk ubah password telah dikirim ke email."}

@router.patch("/me", response_model=schemas.UserOut)
async def update_profile(
    request: Request,
    payload: schemas.UpdateProfile,
    user: models.UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if payload.new_password and payload.new_password.strip():
        if payload.otp and payload.otp.strip():
            record = pending_profile_otps.get(user.email)
            if not record or time.time() > record["exp"]:
                raise HTTPException(status_code=400, detail="OTP kedaluwarsa atau tidak valid.")
            if record["otp"] != payload.otp:
                raise HTTPException(status_code=400, detail="OTP salah.")
            del pending_profile_otps[user.email]

        elif payload.current_password and payload.current_password.strip():
            if not security.verify_password(payload.current_password, user.hashed_password):
                raise HTTPException(status_code=401, detail="Password lama salah.")
                
        else:
            raise HTTPException(
                status_code=400, detail="Pilih autentikasi: gunakan password lama atau kirim kode OTP."
            )
        
        user.hashed_password = security.hash_password(payload.new_password)

    if payload.name is not None:
        user.name = payload.name
    if payload.profile_picture is not None:
        user.profile_picture = payload.profile_picture
    if payload.country is not None:
        user.country = payload.country
    if payload.city is not None:
        user.city = payload.city
    if payload.province is not None:
        user.province = payload.province
    if payload.district is not None:
        user.district = payload.district

    db.commit()
    db.refresh(user)
    return user


@router.post("/me/delete/request")
@limiter.limit("3/minute")
async def request_delete_account(
    request: Request, user: models.UserDB = Depends(get_current_user)
):
    otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    pending_deletions[user.email] = {"otp": otp, "exp": time.time() + OTP_EXP_SECONDS}
    await send_otp_email(user.email, otp, "delete")
    return {"message": "OTP untuk hapus akun telah dikirim."}


@router.delete("/me")
@limiter.limit("5/minute")
async def delete_own_account(
    request: Request, 
    payload: schemas.VerifyDeleteAccount, 
    user: models.UserDB = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    record = pending_deletions.get(user.email)
    if not record or time.time() > record["exp"]:
        if user.email in pending_deletions:
            del pending_deletions[user.email]
        raise HTTPException(status_code=400, detail="Kode OTP kadaluarsa")
    if record["otp"] != str(payload.otp):
        raise HTTPException(status_code=400, detail="Kode OTP salah")

    db.delete(user)
    db.commit()
    del pending_deletions[user.email]
    return {"message": "Akun berhasil dihapus."}
    