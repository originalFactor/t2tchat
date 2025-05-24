import asyncio
import os
import websockets
import json
from utils import CryptoUtils as crypto
from model import *
import threading
import logging
import signal
import time

if os.environ.get('LOG_FILE'):
    logging.basicConfig(
        level=os.environ.get('LOG_LEVEL', 'INFO'),
        format="%(asctime)s - [%(levelname)s] %(message)s",
        filename=os.environ['LOG_FILE']
    )

logger = logging.getLogger(__name__)

class ChatClient:
    def __init__(self, 
                 id: str, 
                 pwd: str = 'default',
                 server_url: str = 'ws://localhost:8765/ws', 
                 key_file: str = 'client_priv.pem',
                 ca_file: str = 'root_public.pem',
                 group_keys_file: str = 'group_keys.json'
                 ):
        self.id = id
        self.passwd = pwd
        self.server_url = server_url
        self.srv_pub: crypto.RsaKey | None = None
        self.group_keys: dict[str, bytes] = {}  # 群组ID -> AES密钥的映射
        self.websocket: websockets.ClientConnection | None  = None
        self.network_groups: set[str] = set()  # 网络中存在的群组ID集合
        self.network_clients: dict[str, crypto.RsaKey] = {}
        self.group_keys_file = group_keys_file
        
        assert os.path.isfile(ca_file), 'CA certificate not found'
            
        with open(ca_file, 'rb') as f:
            self.ca_public = crypto.rsa_import(f.read())

        if os.path.isfile(group_keys_file):
            with open(group_keys_file, 'r') as f:
                self.group_keys.update({
                    k: crypto.b64decode(v) 
                    for k, v in json.load(f).items()
                })

        if os.path.isfile(key_file):
            with open(key_file, 'rb') as f:
                self.private_key = crypto.rsa_import(f.read())
            public_key = crypto.rsa_derive(self.private_key)
        else:
            self.private_key, public_key = crypto.rsa_generate()
            with open(key_file, 'wb') as f:
                f.write(crypto.rsa_export(self.private_key))
        
        self.public_key = crypto.b64encode(
            crypto.rsa_export(public_key)
        )
    
    def send(self, data: BaseModel):
        assert self.websocket
        return self.websocket.send(data.model_dump_json())

    async def connect(self):
        self.websocket = await websockets.connect(self.server_url)
        print(f"已连接到服务器: {self.server_url}")
    
    async def handshake(self, client_id: str, group_id: str):
        if client_id not in self.network_clients:
            print("目标终端不存在")
            return False

        if group_id not in self.network_groups:
            # 群组不存在，创建新的群组
            group_key = crypto.aes_generate()
            self.group_keys[group_id] = group_key
            self.network_groups.add(group_id)
        else:
            if group_id not in self.group_keys:
                print(f"群组已被占用")
                return False

        # 本客户端已加入群组，同步密钥给对方
        encrypted_key = crypto.rsa_encrypt(
            self.network_clients[client_id],
            self.group_keys[group_id]
        )
        await self.send(Request(
            target=client_id,
            group_id=group_id,
            group_key=crypto.b64encode(encrypted_key)
        ))
        print(f"已向 {client_id} 发送握手请求，群组: {group_id}")
        return True
    
    def accept_handshake(self, encrypted_key: str, group_id: str):
        self.group_keys[group_id] = crypto.rsa_decrypt(
            self.private_key, 
            crypto.b64decode(encrypted_key)
        )
        self.network_groups.add(group_id)
        print(f"已加入群组: {group_id}")
    
    def send_message(self, message: bytes, group_id: str):
        if group_id not in self.group_keys:
            print(f"未加入群组 {group_id}")
            return asyncio.sleep(0)

        # 发送加密消息
        return self.send(Message(
            group_id=group_id,
            uid=self.id,
            content=crypto.b64encode(
                crypto.aes_encrypt(
                    self.group_keys[group_id],
                    message
                )
            )
        ))
    
    async def send_keep_alive(self):
        while True:
            try:
                if self.websocket:
                    await self.send(KeepAlive())
                    logger.debug("发送心跳包")
            except Exception as e:
                logger.error(f"发送心跳包失败: {e}")
            await asyncio.sleep(30)  # 每30秒发送一次心跳包
    
    async def receive_messages(self):
        assert self.websocket

        try:
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
                    
                logger.info(f"收到消息: {data}")

                if data.type =='srv_public':
                    decoded_public = crypto.b64decode(data.public)
                    if crypto.rsa_verify(
                        self.ca_public, 
                        decoded_public,
                        crypto.b64decode(data.signature)
                    ):
                        self.srv_pub = crypto.rsa_import(decoded_public)
                        aes_key = crypto.aes_generate()
                        await self.send(Hello(
                            data=crypto.b64encode(
                                crypto.aes_encrypt(
                                    aes_key,
                                    HelloSecret(
                                        id=self.id,
                                        passwd=self.passwd,
                                        public=self.public_key
                                    ).model_dump_json().encode()
                                )
                            ),
                            enc_key=crypto.b64encode(
                                crypto.rsa_encrypt(
                                    self.srv_pub,
                                    aes_key
                                )
                            )
                        ))
                    else:
                        print("服务器公钥签名验证失败")
                    continue

                if data.type == 'conflict':
                    assert self.srv_pub
                    if crypto.rsa_verify(
                        self.srv_pub,
                        str(data.timestamp).encode(),
                        crypto.b64decode(data.signature)
                    ):
                        raise Exception('ID already taken')
                    else:
                        print('收到客户端ID冲突消息，但是签名无效')
                    continue
                
                if data.type == 'ack_hello':
                    assert self.srv_pub
                    if crypto.rsa_verify(
                        self.srv_pub,
                        data.data.encode(),
                        crypto.b64decode(data.signature)
                    ):
                        inner_data = AckHello.model_validate_json(data.data)
                        self.network_clients = {
                            k: crypto.rsa_import(
                                crypto.b64decode(v)
                            )
                            for k, v in inner_data.clients.items()
                        }
                        self.network_groups.update(inner_data.groups)
                    else:
                        print('收到服务端响应消息，但是签名无效')
                    continue
                
                if data.type == 'request':
                    if data.target == self.id and data.group_id not in self.group_keys:
                        self.accept_handshake(data.group_key, data.group_id)
                    continue

                if data.type == 'message':
                    if data.group_id in self.group_keys:
                        # 解密消息
                        try:
                            decrypted_msg = crypto.aes_decrypt(
                                self.group_keys[data.group_id],
                                crypto.b64decode(data.content)
                            ).decode()
                        except Exception as e:
                            print(f"解密消息失败: {e}")
                            continue
                        print(f"[{data.group_id}] {data.uid} : {decrypted_msg}")
                    if data.group_id not in self.network_groups:
                        self.network_groups.add(data.group_id)
                    continue
        except Exception as e:
            print(f"接收消息循环中断: {e}")
        finally:
            await self.close()
            os.kill(os.getpid(), signal.SIGINT)
    
    async def close(self):
        if self.websocket:
            try:
                await self.websocket.close()
                print("已断开与服务器的连接")
            except Exception as e:
                print(f"关闭连接时发生错误: {e}")
        with open(self.group_keys_file, 'w') as f:
            json.dump({k: crypto.b64encode(v) for k,v in self.group_keys.items()}, f)

    async def run(self):
        """运行客户端"""
        keep_alive_task = None
        receive_task = None
        try:
            await self.connect()
            # 启动心跳包发送任务
            keep_alive_task = asyncio.create_task(self.send_keep_alive())
            # 启动消息接收任务
            receive_task = asyncio.create_task(self.receive_messages())
            # 等待任务完成
            await asyncio.gather(receive_task, keep_alive_task, return_exceptions=True)
        except Exception as e:
            print(f"客户端运行错误: {e}")
        finally:
            if keep_alive_task:
                keep_alive_task.cancel()
            if receive_task:
                receive_task.cancel()
            await self.close()
            
class ChatTUI:
    def __init__(self):
        self.core: ChatClient | None = None
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.run_loop, args=(self.loop,))
    
    @staticmethod
    def run_loop(loop: asyncio.AbstractEventLoop):
        asyncio.set_event_loop(loop)
        loop.run_forever()

    @staticmethod
    def print_help():
        """显示帮助信息"""
        print("\n可用命令:")
        print("help                     - 显示此帮助信息")
        print("list                     - 显示在线终端列表")
        print("handshake <终端> <群组>   - 向指定终端发起群组握手请求")
        print("send <群组> <消息>        - 向指定群组发送消息")
        print("quit                     - 退出程序\n")

    def print_clients(self):
        """显示在线终端列表"""
        print("在线终端:")
        assert self.core
        for client_id in self.core.network_clients:
            print(f"- {client_id}")
        print("群组:")
        for group_id in self.core.network_groups:
            print(f"- {group_id} {'√' if group_id in self.core.group_keys else ''}")
        print()

    def handle_command(self, command: str):
        """处理用户输入的命令"""
        assert self.core

        parts = command.strip().split()
        if not parts:
            return True

        cmd = parts[0].lower()
        if cmd == 'quit':
            return False
        elif cmd == 'help':
            self.print_help()
        elif cmd == 'list':
            self.print_clients()
        elif cmd == 'handshake' and len(parts) == 3:
            asyncio.run_coroutine_threadsafe(
                self.core.handshake(parts[1], parts[2]),
                self.loop
            )
        elif cmd == 'send' and len(parts) >= 3:
            group_id = parts[1]
            message = ' '.join(parts[2:])
            try:
                asyncio.run_coroutine_threadsafe(
                    self.core.send_message(message.encode(), group_id),
                    self.loop
                )
            except Exception as e:
                print(f"发送失败: {e}")
        else:
            print("无效的命令，输入 'help' 查看帮助")
        return True

    def run(self):
        """运行命令行界面"""
        print("欢迎使用加密聊天客户端！")

        server = input("请输入服务器地址 (默认为 ws://localhost:8765/ws): ").strip()
        if not server: server = 'ws://localhost:8765/ws'

        key = input("请输入密钥文件路径 (默认为 client_priv.pem): ").strip()
        if not key: key = 'client_priv.pem'

        ca = input("请输入CA证书文件路径 (默认为 root_public.pem): ").strip()
        if not ca: ca = 'root_public.pem'

        group_keys_file = input("请输入群组密钥文件路径 (默认为 group_keys.json): ").strip()
        if not group_keys_file: group_keys_file = 'group_keys.json'

        username = input("请输入您的用户名: ").strip()
        while not username:
            username = input("用户名不能为空，请重新输入: ").strip()
        password = input("请输入您的密码: ").strip()
        while not password:
            password = input("密码不能为空，请重新输入: ").strip()

        self.core = ChatClient(
            id=username,
            pwd=password,
            server_url=server,
            key_file=key,
            ca_file=ca,
            group_keys_file=group_keys_file
        )

        self.thread.start()
        asyncio.run_coroutine_threadsafe(
            self.core.run(),
            self.loop
        )

        print("\n输入 'help' 查看帮助信息。")
        self.print_help()

        try:
            while True:
                command = input('> ')
                if not self.handle_command(command):
                    break
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            stop_task = asyncio.run_coroutine_threadsafe(
                self.core.close(),
                self.loop
            )
            while not stop_task.done():
                time.sleep(1)
            self.loop.stop()
            self.thread.join()
            print("程序已退出。")

if __name__ == '__main__':
    ChatTUI().run()