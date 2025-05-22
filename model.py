from typing import Literal
from pydantic import BaseModel, field_validator, ConfigDict
from utils import rsa, CryptoUtils

class Hello(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    type: Literal['hello']
    id: str
    public: rsa.RSAPublicKey | None
    groups: set[str]

    @field_validator('public', mode='before')
    @classmethod
    def _validate_public(cls, v: str):
        return CryptoUtils.deserialize_public(CryptoUtils.decode(v))

class Request(BaseModel):
    type: Literal['request']
    target: str
    group_id: str
    group_key: str

class Conflict(BaseModel):
    type: Literal['conflict']
    name: str

class Message(BaseModel):
    type: Literal['message']
    group_id: str
    content: str

class Shutdown(BaseModel):
    type: Literal['shutdown']
    id: str

def serialize(data: dict[str, str]):
    t = data.get('type', None)
    if t == 'hello':
        return Hello.model_validate(data)
    if t == 'request':
        return Request.model_validate(data)
    if t == 'conflict':
        return Conflict.model_validate(data)
    if t == 'message':
        return Message.model_validate(data)
    if t == 'shutdown':
        return Shutdown.model_validate(data)
    return None