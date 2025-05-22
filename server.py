import asyncio
import json
import websockets

import model

class ChatServer:
    def __init__(self, host: str = 'localhost', port: int = 8765):
        self.host = host
        self.port = port
        self.clients: set[websockets.ServerConnection] = set()
        
    async def register(self, websocket: websockets.ServerConnection):
        """注册新的客户端连接"""
        self.clients.add(websocket)
        print(f"新客户端连接。当前连接数: {len(self.clients)}")
        
    async def unregister(self, websocket: websockets.ServerConnection):
        """注销客户端连接"""
        self.clients.remove(websocket)
        print(f"客户端断开连接。当前连接数: {len(self.clients)}")
        
    async def broadcast(self, message: websockets.Data, sender: websockets.ServerConnection):
        """向所有客户端广播消息"""
        try:
            # 解析消息内容以记录日志
            data = model.serialize(json.loads(message))
            
            print(f"转发消息: {data}")
            
            if self.clients:
                await asyncio.gather(
                    *[client.send(message) for client in self.clients if client != sender]
                )
        except Exception as e:
            print(f"消息转发失败: {str(e)}")
            return
    
    async def handle_connection(self, websocket: websockets.ServerConnection):
        """处理WebSocket连接"""
        await self.register(websocket)
        try:
            async for message in websocket:
                # 广播加密消息到其他客户端
                await self.broadcast(message, websocket)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)
    
    def run(self):
        """启动WebSocket服务器"""
        server = websockets.serve(self.handle_connection, self.host, self.port)
        print(f"服务器启动于 ws://{self.host}:{self.port}")
        return server

async def main():
    server = ChatServer()
    async with await server.run():
        # 保持服务器运行
        await asyncio.Future()  # 这会一直等待，直到服务器被关闭

if __name__ == '__main__':
    asyncio.run(main())
