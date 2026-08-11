from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

import models
import schemas
import security

from database import get_db
from security import get_current_user

router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(user: models.UserDB = Depends(get_current_user)) -> models.UserDB:
    if not user:
        raise HTTPException(status_code=401, detail="Autentikasi gagal.")
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang bisa akses.")
    return user


@router.get("/users", response_model=list[schemas.UserOut])
async def list_users(
    admin: models.UserDB = Depends(require_admin), db: Session = Depends(get_db)
):
    return db.query(models.UserDB).order_by(models.UserDB.id).all()


@router.patch("/users/{user_id}", response_model=schemas.UserOut)
async def admin_update_user(
    user_id: int,
    payload: schemas.AdminUpdateUser,
    admin: models.UserDB = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.query(models.UserDB).filter(models.UserDB.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")

    if target.role == "admin" and target.id != admin.id:
        raise HTTPException(
            status_code=403, detail="Tidak bisa mengubah akun admin lainnya."
        )

    if (
        target.id == admin.id
        and payload.role is not None
        and payload.role != admin.role
    ):
        raise HTTPException(status_code=400, detail="Tidak bisa mengubah role admin.")

    if payload.name is not None:
        target.name = payload.name
    if payload.role is not None:
        target.role = payload.role
    if payload.new_password:
        target.hashed_password = security.hash_password(payload.new_password)
    if payload.profile_picture is not None:
        target.profile_picture = payload.profile_picture
    if payload.country is not None:
        target.country = payload.country
    if payload.postal_code is not None:
        target.postal_code = payload.postal_code
    if payload.city is not None:
        target.city = payload.city
    if payload.province is not None:
        target.province = payload.province

    db.commit()
    db.refresh(target)
    return target


@router.delete("/users/{user_id}")
async def admin_delete_user(
    user_id: int,
    admin: models.UserDB = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.query(models.UserDB).filter(models.UserDB.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")

    if target.role == "admin":
        raise HTTPException(status_code=403, detail="Tidak bisa menghapus akun admin.")

    db.delete(target)
    db.commit()
    return {"message": "User berhasil dihapus."}
