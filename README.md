# <center> T2TChat </center>

<center> 一个端到端的即时通信核心实现 </center>

## 目录

- [项目架构](#项目架构)
- [快速使用](#快速使用)
- [客户端核心](#客户端核心)
  - [附录](#附录)

## 项目架构

```tree
t2tchat
│  client.py - 客户端核心
│  client_ui.py - 示例客户端UI
│  generate_ca.py - 生成CA
│  model.py - 通信模型
│  server.py - 服务端实现
│  sign_leaf.py - 签名服务端证书
│  utils.py - 加解密工具类实现
│  validate_leaf.py - 验证服务端证书
│  
├─client_web - 示例客户端UI前端
│      index.html
│      script.js
│      styles.css
```

## 快速使用

首先在服务端、客户端和本地都需要拉取本仓库

```bash
git clone https://github.com/originalFactor/t2tchat.git
```

首先在本地生成CA

```bash
python3 generate_ca.py
```

这将会生成 `root_private.pem` (私钥) 和 `root_public.pem` (公钥)，私钥需保密，公钥需通过可信渠道分发给客户端，例如经由传统CA，如HTTPS。

然后在服务器运行服务端生成服务端证书

```bash
python3 server.py
```

这会生成 `leaf_public.pem` (公钥) 和 `leaf_private.pem` (私钥需保密)

接着把 `leaf_public.pem` 传回本地，用CA私钥签名服务端公钥

```bash
python3 sign_leaf.py
```

这会生成 `leaf_sign.pem`, 虽然并不是有效 pem

然后测试一下

```bash
python3 validate_leaf.py
```

输出OK就是没问题


接着把 `leaf_sign.pem` 传上服务器，启动服务端就行了

```bash
python3 server.py
```

默认在 `127.0.0.1:8000` 端口监听，配置nginx反代一下就好

确保客户端有 `root_public.pem` 后，可以运行客户端

```bash
python3 client_ui.py
```

打开 `http://127.0.0.1:8080` 就可以了。

## 客户端核心

客户端核心是 `client.py`，它实现了一个基础的客户端，供您做出扩充。

首先，您需要导入实现类：

```py
from client import ChatClient
```

然后，您可以创建一个实例：

```py
client = ChatClient(
    id = "default", # 用户名
    pwd = "default", # 密码
    server_url = "ws://127.0.0.1:8765/ws", # 服务器地址
    key_file = "client_priv.pem", # 证书
    ca_file = "root_public.pem", # CA
    group_keys_file = "group_keys.json" # 群组秘钥存储
)

# 或者，你可以选择类似依赖注入的方式
client = ChatClient()
client.id = "default"
client.pwd = "default"
client.server_url = "ws://127.0.0.1:8765/ws"
client.key_file = "client_priv.pem"
client.ca_file = "root_public.pem"
client.group_keys_file = "group_keys.json"
# 所有这些参数会在运行时才加载
```

注意：在连接到服务器之前，您必须注册一个conflict回调函数，用于处理冲突：

```py
from pydantic import BaseModel

def handle_conflict(data: BaseModel):
    if isinstance(data, Conflict):
        client.stop() # 触发回调之前会自动验证签名，无需手动确认有效

client.callback("conflict", handle_conflict)
```

然后，您可以运行客户端，并连接到服务器：

```py
client.run()
```

然后，假设网络中存在另一台设备`device2`，您可以通过 `client.handshake` 方法请求它加入群组：

```py
client.handshake("device2", "group1")
```

这将向 `device2` 发送`group1`的密钥。默认情况下，`device2` 会自动接受请求。

如果您想拒绝请求，您可以设置一个callback函数：

```py
def handle_handshake(data: BaseModel):
    if isinstance(data, Request):
        if input():
            client.group_keys.pop(data.group_id)

client.callback("request", handle_handshake)
```

接着，您可以通过 `client.send` 方法发送消息：

```py
client.send("group1", "Hello, world!")
```

如果你想要接收消息，你需要增加一个callback：

```py
from client import Message

message_list: list[Message]

def handle_message(data: BaseModel):
    if isinstance(data, Message):
        message_list.append(data)

client.callback("message", handle_message)
```

最后，你可以通过`client.stop`方法断开连接：

```py
client.stop()
```

### 附录

您可以查看对应文件的 docstring 以获取更多信息， IDE 的 IntelliSense 也可以帮助您快速了解如何使用。

您必须实现 `conflict_handler` 回调，否则将无法正常工作。