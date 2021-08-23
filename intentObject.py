from pydantic import BaseModel


class Intent(BaseModel):
    subject: str
    object: str
    action: str
