"""
用于处理消息的数据模型。

Classes:
    ServerPublic: 服务端Hello
    HelloSecret: 客户端认证
    Hello: 客户端认证封装
    AckHello: 服务端响应
    AckHelloSigned: 服务端响应封装
    Request: 客户端请求
    Conflict: 客户端冲突
    Message: 消息
    KeepAlive: 心跳

Functions:
    serialize: 序列化消息
"""

from typing import Literal
from pydantic import BaseModel

class ServerPublic(BaseModel):
    '''Websocket 握手成功后服务端向客户端发出的 ServerHello

    Attributes:
        type (Literal['srv_public']): 消息类型
        public (str): 服务端公钥
        signature (str) 服务端公钥签名
    '''
    type: Literal['srv_public'] = 'srv_public'
    public: str
    signature: str

class HelloSecret(BaseModel):
    '''客户端认证信息
    
    Attributes:
        id (str): 客户端ID
        passwd (str): 客户端密码
        public (str): 客户端公钥
    '''
    id: str 
    passwd: str
    public: str 

class Hello(BaseModel):
    '''客户端认证信息封装

    Attributes:
        type (Literal['hello']): 消息类型
        data (str): AES加密后的HelloSecret
        enc_key (str): 服务端公钥加密后的AES密钥
    '''
    type: Literal['hello'] = 'hello'
    data: str
    enc_key: str

class AckHello(BaseModel):
    '''服务端响应

    Attributes:
        clients (dict[str, str]): 客户端ID到公钥的映射
        groups (set[str]): 当前网络存在的群组
    '''
    clients: dict[str, str]
    groups: set[str]

class AckHelloSigned(BaseModel):
    '''服务端响应封装

    Attributes:
        type (Literal['ack_hello']): 消息类型
        data (str): 服务端响应JSON
        signature (str): 服务端响应签名
    '''
    type: Literal['ack_hello'] = 'ack_hello'
    data: str
    signature: str

class Request(BaseModel):
    '''拉群请求
    
    Attributes:
        type (Literal['request']): 消息类型
        target (str): 目标客户端ID
        group_id (str): 群组ID
        group_key (str): RSA加密后的群组密钥
    '''
    type: Literal['request'] = 'request'
    target: str
    group_id: str
    group_key: str

class Conflict(BaseModel):
    '''客户端冲突

    Attributes:
        type (Literal['conflict']): 消息类型
        timestamp (int): 时间戳
        signature (str): 时间戳签名
    '''
    type: Literal['conflict'] = 'conflict'
    timestamp: int
    signature: str

class Message(BaseModel):
    '''消息

    Attributes:
        type (Literal['message']): 消息类型
        group_id (str): 群组ID
        uid (str): 发送者ID
        content (str): 加密后的消息内容
    '''
    type: Literal['message'] = 'message'
    group_id: str
    uid: str
    content: str

class KeepAlive(BaseModel):
    '''心跳

    Attributes:
        type (Literal['keep_alive']): 消息类型
    '''
    type: Literal['keep_alive'] = 'keep_alive'

def serialize(data: dict[str, str]):
    '''序列化消息

    Args:
        data (dict[str, str]): 消息数据
    
    Returns:
        BaseModel: 消息数据
    '''
    return (
        _.model_validate(data) 
        if 
        (
            _:={
                'srv_public': ServerPublic,
                'hello': Hello,
                'ack_hello': AckHelloSigned,
                'request': Request,
                'conflict': Conflict,
                'message': Message,
               'keep_alive': KeepAlive,
            }.get(data.get('type', ''))
        )
        else
        None
    )