import os
import aiosmtplib
from email.mime.text import MIMEText

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")


async def send_otp_email(receiver_email: str, otp: str, context: str):
    subjects = {
        "register": "Kode Verifikasi Registrasi",
        "reset": "Kode Reset Password",
        "delete": "Kode Hapus Akun",
        "login": "Kode OTP Login",
        "update_pwd": "Kode OTP Ubah Password",
    }

    msg = MIMEText(f"Kode OTP Anda adalah: {otp}\n\nKode ini berlaku selama 3 menit.")
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email
    msg["Subject"] = subjects.get(context, "OTP Code")

    await aiosmtplib.send(
        msg,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        username=SENDER_EMAIL,
        password=SENDER_PASSWORD,
        use_tls=True,
    )
