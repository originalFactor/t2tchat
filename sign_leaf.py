from utils import CryptoUtils as crypto
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

with open('root_private.pem', 'rb') as f:
    priv = crypto.rsa_import(f.read())
    logger.debug("已加载CA私钥")

with open('leaf_public.pem', 'rb') as f:
    leaf = f.read()
    logger.debug(f"待签名的叶子证书公钥(PEM格式):\n{leaf.decode()}")

signature = crypto.rsa_sign(priv, leaf)
logger.debug(f"生成的签名大小: {len(signature)} 字节")

with open('leaf_sign.pem', 'wb') as f:
    f.write(signature)
