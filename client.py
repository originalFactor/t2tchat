import asyncio
import os
from typing import Any
import websockets
import json
from utils import CryptoUtils, rsa
from model import *

import threading

class ChatClient:
    def __init__(self, id: str, server_url: str = 'ws://localhost:8765', key_file: str = 'private.pem'):
        self.id = id
        self.server_url = server_url
        self.crypto = CryptoUtils()
        self.group_keys: dict[str, bytes] = {}  # 群组ID -> AES密钥的映射
        self.websocket: websockets.ClientConnection | None  = None
        self.network_groups: set[str] = set()  # 网络中存在的群组ID集合
        self.network_clients: dict[str, rsa.RSAPublicKey] = {}

        flag = True
        if os.path.isfile(key_file):
            with open(key_file, 'rb') as f:
                self.private_key = self.crypto.deserialize_private(f.read())
                if self.private_key:
                    self.public_key = self.private_key.public_key()
                    flag = False
        if flag:
            self.private_key = self.crypto.generate_private()
            self.public_key = self.private_key.public_key()
    
    def send(self, data: dict[str, Any]):
        assert self.websocket
        return self.websocket.send(json.dumps(data))

    def hello(self):
        return self.send({
            'type': 'hello',
            'id': self.id,
            'public': self.crypto.encode(self.crypto.serialize_public(self.public_key)),
            'groups': list(self.network_groups)
        })

    async def connect(self):
        """连接到服务器"""
        self.websocket = await websockets.connect(self.server_url)
        await self.hello()
        print(f"已连接到服务器: {self.server_url}")
    
    async def handshake(self, client_id: str, group_id: str):
        """与对等端进行握手以生成共享密钥
        返回值:
        - True: 成功
        - False: 失败
        """
        if client_id not in self.network_clients:
            print("目标终端不存在")
            return False

        if group_id not in self.network_groups:
            # 群组不存在，创建新的群组
            group_key = self.crypto.generate_aes_key()
            self.group_keys[group_id] = group_key
            self.network_groups.add(group_id)
        else:
            if group_id not in self.group_keys:
                return False

        # 本客户端已加入群组，同步密钥给对方
        encrypted_key = self.crypto.rsa_encrypt(self.network_clients[client_id], self.group_keys[group_id])
        await self.send({
            'type': 'request',
            'target': client_id,
            'group_id': group_id,
            'group_key': self.crypto.encode(encrypted_key)
        })
        print(f"已向 {client_id} 发送握手请求，群组: {group_id}")
        return True
    
    def accept_handshake(self, encrypted_key: str, group_id: str):
        """接受握手请求并设置群组密钥
        返回值:
        - True: 成功加入群组
        - False: 加入群组失败
        """
        assert self.private_key
        self.group_keys[group_id] = self.crypto.rsa_decrypt(self.private_key, encrypted_key)
        self.network_groups.add(group_id)
        print(f"已加入群组: {group_id}")
        return True
    
    def send_message(self, message: bytes, group_id: str):
        """发送加密消息到指定群组"""
        if group_id not in self.group_keys:
            raise ValueError(f"未找到群组 {group_id} 的密钥")
        print(f'[{group_id}] {message}')
        # 发送加密消息
        return self.send({
            'type': 'message',
            'group_id': group_id,
            'content': self.crypto.encode(self.crypto.aes_encrypt(self.group_keys[group_id], message))
        })
    
    async def receive_messages(self):
        """接收并解密消息"""
        assert self.websocket
        async for message in self.websocket:
            data = serialize(json.loads(message))
            if not data: continue

            if data.type == 'conflict':
                if data.name == self.id:
                    raise Exception('ID already taken')
                continue
            
            if data.type == 'hello':
                if data.id not in self.network_clients:
                    await self.hello()
                if data.public:
                    self.network_clients[data.id] = data.public
                    print(f"发现新终端: {data.id}")
                self.network_groups.update(data.groups)
                continue
            
            if data.type == 'request':
                if data.target == self.id and data.group_id not in self.group_keys:
                    self.accept_handshake(data.group_key, data.group_id)
                continue

            if data.type == 'message':
                if data.group_id in self.group_keys:
                    # 解密消息
                    decrypted_msg = self.crypto.aes_decrypt(
                        self.group_keys[data.group_id],
                        data.content
                    ).decode()
                    print(f"[群组 {data.group_id}] {decrypted_msg}")
                if data.group_id not in self.network_groups:
                    self.network_groups.add(data.group_id)
                continue
            
            if data.type == 'shutdown':
                del self.network_clients[data.id]
                print(f'{data.id} 下线了！')
                continue
    
    async def run(self):
        """运行客户端"""
        try:
            await self.connect()
            await self.receive_messages()
        finally:
            await self.send({
                'type': 'shutdown',
                'id': self.id
            })
            if self.websocket:
                await self.websocket.close()

class ChatTUI:
    def __init__(self, core: ChatClient):
        self.core = core
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.run_loop, args=(self.loop,), daemon=True)
    
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
        print("\n在线终端:")
        for client_id in self.core.network_clients:
            print(f"- {client_id}")
        print()

    def handle_command(self, command: str):
        """处理用户输入的命令"""
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
                print(f"[群组 {group_id}] {self.core.id}: {message}")
            except Exception as e:
                print(f"发送失败: {e}")
        else:
            print("无效的命令，输入 'help' 查看帮助")
        return True

    def run(self):
        """运行命令行界面"""
        print("欢迎使用加密聊天客户端！")
        username = input("请输入您的用户名: ").strip()
        while not username:
            username = input("用户名不能为空，请重新输入: ").strip()
        self.core.id = username

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

if __name__ == '__main__':
    ChatTUI(ChatClient("")).run()