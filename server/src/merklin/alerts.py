from asyncio import Queue
import logging
from email.message import EmailMessage
from aiosmtplib import SMTP
import os

logger = logging.getLogger(__name__)

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PSWD = os.getenv("EMAIL_PASSWORD")


def make_alert(to: str, type: str, warning: str, session: int) -> EmailMessage:
    logger.debug(f"Creating alert email for {to} with type {type}")
    mail = EmailMessage()
    mail["Subject"] = "Merklin alert: Tampered Logs Found."
    mail["From"] = EMAIL_USER
    mail["To"] = to

    # Plain-text fallback
    text_content = (
        f"Security Alert: {type}\n\n"
        f"Session ID: {session}\n\n"
        f"Warning:\n{warning}\n\n"
    )

    mail.set_content(text_content)

    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #222;">
        <h3 style="margin-bottom: 8px;">Security Alert: {type}</h3>
        <p style="margin-top: 0;">
          <strong>Session ID:</strong><br>
          {session}
        </p>

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

    if EMAIL_USER is None or EMAIL_PSWD is None:
        logger.error("Email credentials not found!")
        raise RuntimeError("Email credentials not set in environment")

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


def make_session_alert(to: str, session: int) -> EmailMessage:
    logger.debug(f"Creating session email for {to} with session {session}")
    mail = EmailMessage()
    mail["Subject"] = "Merklin: New Logging Session Started."
    mail["From"] = EMAIL_USER
    mail["To"] = to

    # Plain-text fallback
    text_content = f"New Logging Session Started\n\n" f"Session ID: {session}\n\n"

    mail.set_content(text_content)

    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #222;">
        <h3 style="margin-bottom: 8px;">New Logging Session Started</h3>

        <p style="margin-top: 0;">
          <strong>Session ID:</strong><br>
          {session}
        </p>

        <hr style="margin-top: 20px;">

        <p style="font-size: 12px; color: #555;">
          This notification was generated automatically by the Merklin system.
        </p>
      </body>
    </html>
    """

    mail.add_alternative(html_content, subtype="html")

    return mail
