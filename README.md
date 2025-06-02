# <center> T2TChat </center>

<center> 一个端到端的即时通信核心实现 </center>

## 目录

- [项目架构](#项目架构)

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