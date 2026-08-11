import re
from typing import Optional, Literal
from pydantic import BaseModel, EmailStr, field_validator


def validate_strong_password(v: str) -> str:
    if len(v) < 12:
        raise ValueError("Password minimal 12 karakter.")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Gunakan minimal satu huruf besar (uppercase).")
    if not re.search(r"[a-z]", v):
        raise ValueError("Gunakan minimal satu huruf kecil (lowercase).")
    if not re.search(r"\d", v):
        raise ValueError("Gunakan minimal satu angka.")
    if not re.search(r"[^A-Za-z0-9]", v):
        raise ValueError("Gunakan minimal satu karakter spesial (contoh: !@#$).")
    return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserRegister(BaseModel):
    email: EmailStr
    password: str
    recaptcha_token: str
    name: str
    country: str
    province: str
    city: str
    postal_code: Optional[str] = None
    profile_picture: Optional[str] = None       

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str) -> str:
        return validate_strong_password(v)


class VerifyRegistration(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("otp")
    @classmethod
    def validate_otp_format(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError(
                "Format kode OTP tidak valid, kode OTP terdiri dari 6 angka."
            )
        return v


class ForgotPassword(BaseModel):
    email: EmailStr
    recaptcha_token: str


class ResetPassword(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, v: str) -> str:
        return validate_strong_password(v)

    @field_validator("otp")
    @classmethod
    def validate_otp_format(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("Format kode OTP tidak valid.")
        return v


class VerifyDeleteAccount(BaseModel):
    otp: str

    @field_validator("otp")
    @classmethod
    def validate_otp_format(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("Format kode OTP tidak valid.")
        return v


# --- Profil & manajemen role ---


class UserOut(BaseModel):
    id: int
    email: EmailStr
    name: Optional[str] = None
    role: str
    profile_picture: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None
    city: Optional[str] = None
    province: Optional[str] = None

    class Config:
        from_attributes = True


class UpdateProfile(BaseModel):
    name: Optional[str] = None
    profile_picture: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None
    city: Optional[str] = None
    province: Optional[str] = None
    current_password: Optional[str] = None
    otp: Optional[str] = None
    new_password: Optional[str] = None

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return validate_strong_password(v)


class AdminUpdateUser(BaseModel):
    name: Optional[str] = None
    role: Optional[Literal["user", "admin"]] = None
    new_password: Optional[str] = None
    profile_picture: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None
    city: Optional[str] = None
    province: Optional[str] = None

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return validate_strong_password(v)


class LoginOTPRequest(BaseModel):
    email: EmailStr
    recaptcha_token: str


class LoginOTPVerify(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("otp")
    @classmethod
    def validate_otp_format(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("Format kode OTP tidak valid.")
        return v