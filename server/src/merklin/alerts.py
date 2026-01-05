from asyncio import Queue

from email.message import EmailMessage

def make_mail(to: str, message: str) -> EmailMessage:
    ...

async def alert(queue: Queue[EmailMessage]) -> None:
    ...
    