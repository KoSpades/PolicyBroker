from pydantic import BaseModel


class Intent(BaseModel):
    subject: str
    object: str
    action: str


class Dataset(BaseModel):
    object: str



