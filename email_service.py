import os
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

async def send_otp_email(receiver_email: str, otp: str, context: str):
    subjects = {
        "register": "Kode Verifikasi Registrasi",
        "reset": "Kode Pemulihan Password",
        "delete": "Konfirmasi Hapus Akun",
        "login": "Kode OTP Login",
        "update_pwd": "Konfirmasi Perubahan Password",
    }

    subject_text = subjects.get(context, "Kode Verifikasi Keamanan")
    
    # 1. Wording Teks Biasa (Fallback untuk email client lawas)
    plain_text = f"""Halo,

Kami menerima permintaan untuk {subject_text.lower()} pada akun Anda.
Kode OTP Anda adalah: {otp}

Kode ini hanya berlaku selama 3 menit.
PENTING: Jangan berikan kode ini kepada siapa pun, termasuk pihak admin.

Jika Anda tidak melakukan permintaan ini, segera amankan akun Anda.

Salam,
Secure Auth System
"""

    # 2. Template HTML dengan Internal CSS
    html_content = f"""
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background-color: #f4f4f5;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 500px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
                border: 1px solid #e4e4e7;
            }}
            .header {{
                background-color: #09090b;
                padding: 24px;
                text-align: center;
                color: #ffffff;
            }}
            .content {{
                padding: 32px;
                color: #3f3f46;
                line-height: 1.6;
                font-size: 15px;
            }}
            .otp-box {{
                background-color: #f4f4f5;
                border: 1px dashed #a1a1aa;
                border-radius: 6px;
                padding: 16px;
                text-align: center;
                font-size: 32px;
                font-weight: 700;
                letter-spacing: 8px;
                color: #09090b;
                margin: 24px 0;
            }}
            .warning {{
                background-color: rgba(239, 68, 68, 0.1);
                color: #dc2626;
                padding: 12px;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 500;
                text-align: center;
                margin-bottom: 20px;
                border: 1px solid rgba(239, 68, 68, 0.2);
            }}
            .footer {{
                background-color: #fafafa;
                padding: 16px;
                text-align: center;
                font-size: 12px;
                color: #a1a1aa;
                border-top: 1px solid #e4e4e7;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2 style="margin: 0; font-size: 20px;">Secure Auth</h2>
            </div>
            <div class="content">
                <p style="margin-top: 0;">Halo,</p>
                <p>Kami menerima permintaan untuk <strong>{subject_text.lower()}</strong> pada akun Anda. Berikut adalah kode verifikasi yang Anda butuhkan:</p>
                
                <div class="otp-box">{otp}</div>
                
                <div class="warning">
                    ⚠️ PENTING: Jangan berikan kode ini kepada siapa pun, termasuk pihak admin.
                </div>
                
                <p style="font-size: 13px; color: #71717a; margin-bottom: 0;">
                    Kode ini hanya berlaku selama <strong>3 menit</strong>. Jika Anda tidak merasa melakukan permintaan ini, abaikan email ini dan pastikan password Anda aman.
                </p>
            </div>
            <div class="footer">
                &copy; 2026 Secure Auth System. Pesan ini dibuat secara otomatis.
            </div>
        </div>
    </body>
    </html>
    """

    # 3. Setup MIMEMultipart
    msg = MIMEMultipart("alternative")
    msg["From"] = f"Secure Auth <{SENDER_EMAIL}>"
    msg["To"] = receiver_email
    msg["Subject"] = subject_text

    # 4. Attach bagian teks dan HTML (Urutan sangat penting: plain dulu, baru html)
    part1 = MIMEText(plain_text, "plain")
    part2 = MIMEText(html_content, "html")
    
    msg.attach(part1)
    msg.attach(part2)

    # 5. Kirim Email
    await aiosmtplib.send(
        msg,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        username=SENDER_EMAIL,
        password=SENDER_PASSWORD,
        use_tls=True,
    )