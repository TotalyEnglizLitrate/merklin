from asyncio import Queue

from email.message import EmailMessage
from aiosmtplib import SMTP
import os
from dotenv import load_dotenv

load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PSWD = os.getenv("EMAIL_PASSWORD")


def make_mail(to: str, type: str, warning: str) -> EmailMessage:
    mail = EmailMessage()
    mail["Subject"] = "Merklin alert: Tampered Logs Found."
    mail["From"] = EMAIL_USER
    mail["To"] = to

    # Plain-text fallback
    text_content = f"Security Alert: {type}\n\n" f"Warning:\n{warning}\n\n"

    mail.set_content(text_content)

    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #222;">
        <h3 style="margin-bottom: 8px;">Security Alert: {type}</h3>

        <p style="margin-top: 0;">
          <strong>Warning:</strong><br>
          {warning}
        </p>

        <hr style="margin-top: 20px;">

        <p style="font-size: 12px; color: #555;">
          This alert was generated automatically by the tamper-detection system.
        </p>
      </body>
    </html>
    """

    mail.add_alternative(html_content, subtype="html")

    return mail


async def alert(queue: Queue[EmailMessage]) -> None:
    smtp = SMTP(
        hostname="smtp.gmail.com",
        port=465,
        use_tls=True,
    )

    if not EMAIL_USER:
        raise RuntimeError("EMAIL_USER is not set")
    if not EMAIL_PSWD:
        raise RuntimeError("EMAIL_PASSWORD is not set")

    await smtp.connect()
    await smtp.login(EMAIL_USER, EMAIL_PSWD)

    while True:
        msg = await queue.get()
        try:
            await smtp.send_message(msg)
        except Exception as e:
            print("Email send failed:", e)
        finally:
            queue.task_done()
