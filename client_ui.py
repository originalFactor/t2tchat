"""
简易客户端UI

Variables:
    app: FastAPI实例
    message_list: 消息缓冲区
    client: 客户端实例

Classes:
    Login: 登录请求模型
    Send: 发送请求模型
    Pair: 一对多请求模型

Functions:
    message_callback: 接收消息回调

Routes:
    index: 首页
    ui: UI
    login: 登录
    send: 发送消息
    pair: 将用户拉进群组
    logout: 登出
    receive: 从缓冲区读出消息
    list_clients: 列出在线客户端
    list_groups: 列出已存在群组
    available_groups: 列出已加入群组
"""

from client import *
import fastapi
from fastapi import responses
from pydantic import BaseModel, Field

app = fastapi.FastAPI()

client: ChatClient | None = None

message_list: list[Message] = []

async def message_callback(data: BaseModel):
    """接收消息回调

    Args:
        data (Message): 消息模型
    """
    if isinstance(data, Message):
        message_list.append(data)

async def conflict_callback(data: BaseModel):
    """冲突回调

    Args:
        data (Conflict): 冲突模型
    """
    global client
    if isinstance(data, Conflict):
        if client:
            client.stop()
            client = None

class Login(BaseModel):
    """登录请求模型

    Attributes:
        username (str): 用户名
        password (str): 密码
        server_addr (str): 服务器地址
    """
    username: str = Field(..., examples=['user'])
    password: str = Field(..., examples=['password'])
    server_addr: str = Field(..., examples=['ws://127.0.0.1:8765/ws'])

class Send(BaseModel):
    """发送消息模型
    
    Attributes:
        gid (str): 群组ID
        msg (str): 消息内容
    """
    gid: str = Field(..., examples=['group'])
    msg: str = Field(..., examples=['message'])

class Pair(BaseModel):
    """拉群请求模型
    
    Attributes:
        gid (str): 群组ID
        cid (str): 目标用户ID
    """
    gid: str = Field(..., examples=['group'])
    cid: str = Field(..., examples=['client'])

@app.get("/", response_class=responses.RedirectResponse)
async def index():
    """首页重定向到UI
    
    Returns:
        responses.RedirectResponse: 重定向到UI
    """
    return responses.RedirectResponse("/ui/")

@app.get("/ui/{file_name:path}", response_class=responses.FileResponse)
async def ui(file_name: str):
    """UI
    
    Args:
        file_name (str): 文件名，默认`index.html`
    
    Returns:
        responses.FileResponse: 文件响应
    """
    if not file_name:
        file_name = "index.html"
    print(file_name)
    return responses.FileResponse(f"./client_web/{file_name}")

@app.post("/login")
async def login(r: Login) -> StatusReturn:
    """登录
    
    Args:
        r (Login): 登录请求模型
    
    Returns:
        StatusReturn: 登录结果
    """
    global client
    if client is not None:
        return StatusReturn(False, "Already logged in")
    client = ChatClient(r.username, r.password, r.server_addr)
    client.callback("message", message_callback)
    client.callback("conflict", conflict_callback)
    return client.run()

@app.get("/logout")
async def logout() -> StatusReturn:
    """登出
    
    Returns:
        StatusReturn: 登出结果
    """
    global client
    if client is None:
        return StatusReturn(False, "Not logged in")
    ret = client.stop()
    if ret.status:
        client = None
    return ret

@app.post("/send")
async def send(r: Send) -> StatusReturn:
    """发送消息
    
    Args:
        r (Send): 发送消息模型
    
    Returns:
        StatusReturn: 发送结果
    """
    if client is None:
        return StatusReturn(False, "Not logged in")
    return client.send(r.gid, r.msg)

@app.get("/receive")
async def receive() -> list[Message]:
    """从缓冲区读出消息
    
    Returns:
        list[Message]: 消息列表
    """
    ret = message_list.copy()
    message_list.clear()
    return ret

@app.get("/clients")
async def list_clients() -> set[str]:
    """列出在线客户端
    
    Returns:
        set[str]: 在线客户端列表
    """
    if client is None:
        return set()
    return set(client.network_clients.keys())

@app.get("/groups")
async def list_groups() -> set[str]:
    """列出已存在群组
    
    Returns:
        set[str]: 已存在群组列表
    """
    if client is None:
        return set()
    return set(client.network_groups)

@app.post("/pair")
async def pair(r: Pair) -> StatusReturn:
    """将用户拉进群组
    
    Args:
        r (Pair): 拉群请求模型
    
    Returns:
        StatusReturn: 拉群结果
    """
    if client is None:
        return StatusReturn(False, "Not logged in")
    return client.handshake(r.cid, r.gid)

@app.get("/available_groups")
async def available_groups() -> set[str]:
    """列出已加入群组
    
    Returns:
        set[str]: 已加入群组列表
    """
    if client is None:
        return set()
    return set(client.group_keys.keys())

class LoginStatus(BaseModel):
    """登录状态模型

    Attributes:
        logged_in (bool): 登录状态
        username (str | None): 用户名
    """
    logged_in: bool
    username: str | None

@app.get("/status")
async def status() -> LoginStatus:
    """获取当前登录状态

    Returns:
        dict: 包含登录状态和用户名的字典
    """
    if client is None:
        return LoginStatus(logged_in=False, username=None)
    return LoginStatus(logged_in=True, username=client.id)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
