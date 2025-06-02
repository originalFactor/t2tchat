'''
客户端实现

Classes:
    ChatClient: 客户端实现
'''

from model import *
import os
import asyncio
import json
import threading
import logging
from dataclasses import dataclass
from collections.abc import Callable, Awaitable
import websockets
from utils import CryptoUtils as crypto

if os.environ.get("LOG_FILE"):
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s - [%(levelname)s] %(message)s",
        filename=os.environ["LOG_FILE"],
    )

logger = logging.getLogger(__name__)


@dataclass
class StatusReturn:
    '''返回状态信息

    Attributes:
        status (bool): 状态
        message (str): 信息
    '''
    status: bool
    message: str

class ChatClient:
    '''端到端加密聊天客户端实现
    
    Attributes:
        id (str): 用户名
        pwd (str): 密码
        server_url (str): 服务端地址
        key_file (str): 客户端私钥路径
        ca_file (str): CA公钥路径
        group_keys_file (str): 群组缓存路径

    Methods:
        load_ca: 重加载CA文件
        load_group_keys: 重加载群组缓存
        load_key: 重加载客户端私钥
        send: 发送信息
        callback: 添加回调
        run: 运行客户端
        stop: 停止客户端
        handshake: 发起拉群
    '''

    def __init__(
        self,
        id: str = "default",
        pwd: str = "default",
        server_url: str = "ws://localhost:8765/ws",
        key_file: str = "client_priv.pem",
        ca_file: str = "root_public.pem",
        group_keys_file: str = "group_keys.json",
    ):

        # 连接信息
        self.websocket: websockets.ClientConnection | None = None

        # 用户信息
        self.id = id
        self.passwd = pwd

        # 服务端信息
        self.server_url = server_url
        self.srv_pub: crypto.RsaKey | None = None

        # 网络信息
        self.group_keys: dict[str, bytes] = {}
        self.network_groups: set[str] = set()
        self.network_clients: dict[str, crypto.RsaKey] = {}

        # 文件信息
        self.key_file = key_file
        self.ca_file = ca_file
        self.group_keys_file = group_keys_file

        # 运行状态
        self.callbacks: dict[
            str, set[Callable[[BaseModel], None | Awaitable[None]]]
        ] = {}
        self.loop = asyncio.new_event_loop()
        self._stop_event = threading.Event()

        # 密钥信息
        self.private_key: crypto.RsaKey | None = None
        self.public_key: str | None = None
        self.ca_public: crypto.RsaKey | None = None

    def load_ca(self):
        '''重加载CA证书，正常情况下会在启动时自动加载'''

        if not os.path.isfile(self.ca_file):
            return StatusReturn(False, "CA公钥文件不存在")

        with open(self.ca_file, "rb") as f:
            self.ca_public = crypto.rsa_import(f.read())
        return StatusReturn(True, "CA公钥加载成功")

    def load_group_keys(self):
        '''重加载群组缓存，正常情况下会在启动时自动加载'''
        if os.path.isfile(self.group_keys_file):
            with open(self.group_keys_file, "r") as f:
                self.group_keys.update(
                    {k: crypto.b64decode(v) for k, v in json.load(f).items()}
                )
            return StatusReturn(True, "群组密钥加载成功")
        return StatusReturn(False, "群组密钥文件不存在")

    def load_key(self):
        '''重加载客户端私钥，正常情况下会在启动时自动加载'''
        if os.path.isfile(self.key_file):
            with open(self.key_file, "rb") as f:
                self.private_key = crypto.rsa_import(f.read())
            public_key = crypto.rsa_derive(self.private_key)
        else:
            self.private_key, public_key = crypto.rsa_generate()
            with open(self.key_file, "wb") as f:
                f.write(crypto.rsa_export(self.private_key))

        self.public_key = crypto.b64encode(crypto.rsa_export(public_key))
        return StatusReturn(True, "密钥加载成功")

    def send(self, group_id: str, message: str):
        """发送消息
        
        Args:
            group_id (str): 群组id
            message (str): 消息内容
        """
        return asyncio.run_coroutine_threadsafe(
            self._send_message(message.encode(), group_id), self.loop
        ).result()

    def callback(
        self, msg_type: str, func: Callable[[BaseModel], None | Awaitable[None]]
    ):
        """注册消息类型对应的回调函数
        
        Args:
            msg_type (str): 消息类型，具体参考文档
            func (Callable[[BaseModel], None | Awaitable[None]]): 回调函数，接受一个data参数，可为异步，具体参考文档
        """
        if msg_type not in self.callbacks:
            self.callbacks[msg_type] = set()
        self.callbacks[msg_type].add(func)
        return StatusReturn(True, "回调函数注册成功")

    def _run_async_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._run())

    async def _run(self):
        res = self.load_ca()
        if not res.status:
            logger.error(res.message)
            return
        self.load_group_keys()
        self.load_key()
        await self._connect()
        asyncio.create_task(self._send_keep_alive())
        await self._receive_messages()

    def run(self):
        """启动守护线程执行异步循环"""
        thread = threading.Thread(target=self._run_async_loop, daemon=True)
        thread.start()
        return StatusReturn(True, "客户端启动成功")

    def stop(self):
        """停止客户端"""
        self._stop_event.set()
        self.loop.call_soon_threadsafe(self.loop.stop)
        return StatusReturn(True, "客户端已停止")

    async def _connect(self):
        self.websocket = await websockets.connect(self.server_url)

    async def _handshake(self, client_id: str, group_id: str):
        if client_id not in self.network_clients:
            return StatusReturn(False, "目标终端不存在")

        if group_id not in self.network_groups:
            # 群组不存在，创建新的群组
            group_key = crypto.aes_generate()
            self.group_keys[group_id] = group_key
            self.network_groups.add(group_id)
        else:
            if group_id not in self.group_keys:
                return StatusReturn(False, "群组已被占用")

        # 本客户端已加入群组，同步密钥给对方
        encrypted_key = crypto.rsa_encrypt(
            self.network_clients[client_id], self.group_keys[group_id]
        )
        await self._send(
            Request(
                target=client_id,
                group_id=group_id,
                group_key=crypto.b64encode(encrypted_key),
            )
        )
        return StatusReturn(True, f"已向 {client_id} 发送握手请求，群组: {group_id}")

    def handshake(self, client_id: str, group_id: str):
        """同步发送握手请求
        
        Args:
            client_id (str): 目标客户端id
            group_id (str): 目标群组id
        """
        return asyncio.run_coroutine_threadsafe(
            self._handshake(client_id, group_id), self.loop
        ).result()

    def _accept_handshake(self, encrypted_key: str, group_id: str):
        assert self.private_key, "未加载私钥"
        self.group_keys[group_id] = crypto.rsa_decrypt(
            self.private_key, crypto.b64decode(encrypted_key)
        )
        self.network_groups.add(group_id)

    async def _send_message(self, message: bytes, group_id: str):
        if group_id not in self.group_keys:
            return StatusReturn(False, f"未加入群组 {group_id}")

        # 发送加密消息
        await self._send(
            Message(
                group_id=group_id,
                uid=self.id,
                content=crypto.b64encode(
                    crypto.aes_encrypt(self.group_keys[group_id], message)
                ),
            )
        )
        return StatusReturn(True, "消息发送成功")

    async def _send_keep_alive(self):
        while not self._stop_event.is_set():
            try:
                if self.websocket:
                    await self._send(KeepAlive())
                    logger.debug("发送心跳包")
            except Exception as e:
                logger.error(f"发送心跳包失败: {e}")
            await asyncio.sleep(30)  # 每30秒发送一次心跳包

    async def _receive_messages(self):
        try:
            assert self.websocket, "未连接到服务器"
            async for message in self.websocket:
                try:
                    data = serialize(json.loads(message))
                    if not data:
                        continue
                except json.JSONDecodeError as e:
                    logger.error(f"解析消息失败: {e}")
                    continue
                except Exception as e:
                    logger.error(f"处理消息时发生错误: {e}")
                    continue

                await self._process_event(data, data.type)

        except Exception as e:
            logger.error(f"接收消息循环中断: {e}")
        finally:
            await self._close()

    async def _process_event(self, data: BaseModel, type: str):
        result: bool = False
        if isinstance(data, ServerPublic):
            result = await self._process_srv_public(data)
        elif isinstance(data, Conflict):
            result = await self._process_conflict(data)
        elif isinstance(data, AckHelloSigned):
            result = await self._process_ack(data)
        elif isinstance(data, Request):
            result = await self._process_request(data)
        elif isinstance(data, Message):
            result = await self._process_message(data)
        else:
            logger.warning(f"未知的数据类型 {type}")
            return
        if result:
            await self._call_callback(data.type, data)

    async def _process_srv_public(self, data: ServerPublic):
        assert self.ca_public, "未加载CA证书"
        assert self.public_key, "未加载客户端证书"
        decoded_public = crypto.b64decode(data.public)
        verify = crypto.rsa_verify(
            self.ca_public, decoded_public, crypto.b64decode(data.signature)
        )
        if verify:
            self.srv_pub = crypto.rsa_import(decoded_public)
            aes_key = crypto.aes_generate()
            await self._send(
                Hello(
                    data=crypto.b64encode(
                        crypto.aes_encrypt(
                            aes_key,
                            HelloSecret(
                                id=self.id, passwd=self.passwd, public=self.public_key
                            )
                            .model_dump_json()
                            .encode(),
                        )
                    ),
                    enc_key=crypto.b64encode(crypto.rsa_encrypt(self.srv_pub, aes_key)),
                )
            )
            return True
        return False

    async def _process_conflict(self, data: Conflict):
        assert self.srv_pub, "未收到服务端公钥"
        if crypto.rsa_verify(
            self.srv_pub, str(data.timestamp).encode(), crypto.b64decode(data.signature)
        ):
            return True
        return False

    async def _process_ack(self, data: AckHelloSigned):
        assert self.srv_pub, "未收到服务端公钥"
        if crypto.rsa_verify(
            self.srv_pub, data.data.encode(), crypto.b64decode(data.signature)
        ):
            inner_data = AckHello.model_validate_json(data.data)
            self.network_clients = {
                k: crypto.rsa_import(crypto.b64decode(v))
                for k, v in inner_data.clients.items()
            }
            self.network_groups.update(inner_data.groups)
            return True
        return False

    async def _process_request(self, data: Request):
        if data.target == self.id and data.group_id not in self.group_keys:
            self._accept_handshake(data.group_key, data.group_id)
        return True

    async def _process_message(self, data: Message):
        if data.group_id not in self.network_groups:
            self.network_groups.add(data.group_id)
        if data.group_id in self.group_keys:
            try:
                decrypted_msg = crypto.aes_decrypt(
                    self.group_keys[data.group_id], crypto.b64decode(data.content)
                ).decode()
                data.content = decrypted_msg
                return True
            except Exception as e:
                logger.error(f"解密消息失败: {e}")
        return False

    async def _call_callback(self, msg_type: str, data: BaseModel):
        for callback in self.callbacks.get(msg_type, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as e:
                logger.error(f"调用回调函数 {callback.__name__} 时发生错误: {e}")

    def _send(self, data: BaseModel):
        assert self.websocket
        return self.websocket.send(data.model_dump_json())

    async def _close(self):
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception as e:
                logger.error(f"关闭连接时发生错误: {e}")
        with open(self.group_keys_file, "w") as f:
            json.dump({k: crypto.b64encode(v) for k, v in self.group_keys.items()}, f)
