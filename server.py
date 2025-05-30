from fastapi import FastAPI, WebSocket
from model import *
from utils import CryptoUtils as crypto
import logging
import uvicorn
import json
from os import path, environ
from hashlib import sha256
import time
import asyncio

# 配置日志
def setup_logging():
    logging.basicConfig(
        level=environ.get('LOG_LEVEL', 'INFO'),
        format="%(asctime)s - [%(levelname)s] - %(name)s : %(message)s",
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# 加载密钥和签名
def load_keys_and_signature():
    if path.isfile('leaf_private.pem') and path.isfile('leaf_public.pem') and path.isfile('leaf_sign.pem'):
        try:
            with open('leaf_private.pem', 'rb') as f:
                priv = crypto.rsa_import(f.read())
            with open('leaf_public.pem', 'rb') as f:
                pub = crypto.b64encode(f.read())
            with open('leaf_sign.pem', 'rb') as f:
                sign = crypto.b64encode(f.read())
            return priv, pub, sign
        except Exception as e:
            logger.error(f"Error loading keys and signature: {e}")
    priv, pub_key = crypto.rsa_generate()
    with open('leaf_private.pem', 'wb') as f:
        f.write(crypto.rsa_export(priv))
    with open('leaf_public.pem', 'wb') as f:
        f.write(crypto.rsa_export(pub_key))
    raise Exception("There are no signed leafs. Please contact your CA to get one.")

priv, pub, sign = load_keys_and_signature()

app = FastAPI()

connection_pool: set[WebSocket] = set()
# 记录每个客户端的最后活跃时间
client_last_active: dict[WebSocket, float] = {}

clients: dict[str, str] = {}

passwords: dict[str, str] = {}

# 加载密码
def load_passwords():
    if path.isfile('passwords.json'):
        try:
            with open('passwords.json', 'r') as f:
                passwords.update(json.load(f))
        except Exception as e:
            logger.error(f"Error loading passwords: {e}")

load_passwords()

groups: set[str] = set()

# 加载群组
def load_groups():
    if path.isfile('groups.json'):
        try:
            with open('groups.json', 'r') as f:
                groups.update(json.load(f))
        except Exception as e:
            logger.error(f"Error loading groups: {e}")

load_groups()

async def check_connections():
    """检查连接状态，关闭超时连接"""
    while True:
        current_time = time.time()
        to_remove: list[WebSocket] = []
        for ws, last_active in client_last_active.items():
            # 如果客户端超过60秒没有活动，认为连接超时
            if current_time - last_active > 60:
                logger.warning(f"Client {ws.client} timed out after 60 seconds of inactivity")
                to_remove.append(ws)
        
        # 关闭超时连接
        for ws in to_remove:
            try:
                await ws.close(code=1000, reason="Connection timeout")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
            if ws in connection_pool:
                connection_pool.remove(ws)
            if ws in client_last_active:
                del client_last_active[ws]
        
        await asyncio.sleep(10)  # 每10秒检查一次

@app.on_event("startup")
async def startup_event():
    """启动时创建后台任务"""
    asyncio.create_task(check_connections())

# 处理消息发送
async def send_message_to_all(text: str, sender: WebSocket | None = None):
    for conn in list(connection_pool):
        if conn == sender:
            continue
        try:
            await conn.send_text(text)
        except Exception as e:
            logger.warning(f"Error sending message to {conn.client}: {e}")
            if conn in connection_pool:
                connection_pool.remove(conn)
            if conn in client_last_active:
                del client_last_active[conn]

@app.websocket("/ws")
async def websocket(ws: WebSocket):
    await ws.accept()
    connection_pool.add(ws)
    # 记录客户端连接时间
    client_last_active[ws] = time.time()
    logger.info(f"Client connected: {ws.client}")
    heartbeated = False
    client_id: str | None = None

    while True:
        hello = False
        try:
            data = await ws.receive_text()
            # 更新客户端活跃时间
            client_last_active[ws] = time.time()
        except Exception as e:
            logger.error(f"Connection error: {e}")
            break
        try:
            data = serialize(json.loads(data))
        except json.JSONDecodeError:
            logger.error(f"Received invalid JSON: {data}")
            continue

        assert data

        if data.type == 'hello':
            try:
                encrypted_data = HelloSecret.model_validate_json(
                    crypto.aes_decrypt(
                        crypto.rsa_decrypt(
                            priv,
                            crypto.b64decode(data.enc_key)
                        ),
                        crypto.b64decode(data.data)
                    )
                )
                logger.debug(f"Hello from {encrypted_data.id}")
                pwd_hash = sha256(encrypted_data.passwd.encode()).hexdigest()
                if encrypted_data.id in passwords and pwd_hash != passwords[encrypted_data.id]:
                    ts = int(time.time())
                    conflict_msg = Conflict(
                        timestamp=ts,
                        signature=crypto.b64encode(
                            crypto.rsa_sign(
                                priv,
                                str(ts).encode()
                            )
                        )
                    ).model_dump_json()
                    await ws.send_text(conflict_msg)
                    continue
                client_id = encrypted_data.id
                clients[client_id] = encrypted_data.public
                passwords[client_id] = pwd_hash
                hello = True
            except Exception as e:
                logger.error(f"Error processing hello message: {e}")
                continue

        if data.type == 'keep_alive':
            logger.debug(f"Keep alive from {ws.client}")
            if not heartbeated:
                heartbeated = True
                server_public_msg = ServerPublic(
                    public=pub,
                    signature=sign
                ).model_dump_json()
                await ws.send_text(server_public_msg)
            continue
        
        if (data.type == 'message' or data.type == 'request') and data.group_id not in groups:
            groups.add(data.group_id)
            hello = True
        
        if hello:
            ack = AckHello(
                clients=clients,
                groups=groups
            ).model_dump_json()
            signed_ack = AckHelloSigned(
                data=ack,
                signature=crypto.b64encode(
                    crypto.rsa_sign(
                        priv,
                        ack.encode()
                    )
                )
            ).model_dump_json()
            await send_message_to_all(signed_ack)
        else:
            text = data.model_dump_json()
            await send_message_to_all(text, sender=ws)

    logger.info(f"Client disconnected: {ws.client}")
    
    # 清理连接数据
    if ws in connection_pool:
        connection_pool.remove(ws)
    if ws in client_last_active:
        del client_last_active[ws]
    if client_id in clients:
        del clients[client_id]
    
@app.on_event("shutdown")
async def shutdown_event():
    try:
        with open('passwords.json', 'w') as f:
            json.dump(passwords, f)
        with open('groups.json', 'w') as f:
            json.dump(list(groups), f)
    except Exception as e:
        logger.error(f"Error saving data on shutdown: {e}")

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8765)