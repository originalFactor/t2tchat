"""
加密工具库

Classes:
    CryptoUtils: 加密工具类
"""

import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

class CryptoUtils:
    """
    加密工具类

    Constants:
        RsaKey: RSA密钥类型

    Methods:
        b64encode(data: bytes): 对数据进行Base64编码
        b64decode(data: str): 对Base64编码的数据进行解码
        rsa_generate(): 生成RSA密钥对
        rsa_derive(private_key: RsaKey): 从私钥导出公钥
        rsa_encrypt(public_key: RsaKey, data: bytes): 使用RSA公钥加密数据
        rsa_decrypt(private_key: RsaKey, encrypted_data: bytes): 使用RSA私钥解密数据
        rsa_sign(private_key: RsaKey, data: bytes): 使用私钥对数据进行签名
        rsa_verify(public_key: RsaKey, data: bytes, signature: bytes): 使用公钥验证签名
        aes_generate(): 生成随机AES密钥
        aes_encrypt(key: bytes, data: bytes): 使用AES密钥加密数据
        aes_decrypt(key: bytes, encrypted_data: bytes): 使用AES密钥解密数据
        rsa_export(key: RsaKey): 导出RSA密钥为PEM格式
        rsa_import(pem: bytes): 从PEM格式导入RSA密钥
    """
    RsaKey = RSA.RsaKey

    @staticmethod
    def b64encode(data: bytes):
        '''对数据进行Base64编码

        Args:
            data (bytes): 要编码的数据
        
        Returns:
            str: Base64编码后的字符串
        '''
        return base64.b64encode(data).decode()
    
    @staticmethod
    def b64decode(data: str):
        '''对Base64编码的数据进行解码

        Args:
            data (str): Base64编码的字符串

        Returns:
            bytes: 解码后的原始数据
        '''
        return base64.b64decode(data)

    @staticmethod
    def rsa_generate():
        """生成RSA密钥对
        
        Returns:
            tuple[RsaKey, RsaKey]: 私钥, 公钥
        """
        private = RSA.generate(2048)
        return private, CryptoUtils.rsa_derive(private)
    
    @staticmethod
    def rsa_derive(private_key: RSA.RsaKey):
        '''从私钥导出公钥

        Args:
            private_key (RsaKey): 私钥

        Returns:
            RsaKey: 公钥
        '''
        return private_key.publickey()

    @staticmethod
    def rsa_encrypt(public_key: RSA.RsaKey, data: bytes):
        """使用RSA公钥加密数据
        
        Args:
            public_key (RsaKey): 公钥
            data (bytes): 要加密的数据
            
        Returns:
            bytes: 加密后的数据
        """
        if len(data) > public_key.size_in_bytes() - 42:  # RSA加密的最大数据长度
            raise ValueError("Data too large for RSA encryption")
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)
    
    @staticmethod
    def rsa_decrypt(private_key: RSA.RsaKey, encrypted_data: bytes):
        """使用RSA私钥解密数据
        
        Args:
            private_key (RsaKey): 私钥
            encrypted_data (bytes): 要解密的数据
        
        Returns:
            bytes: 解密后的数据
        """
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_data)
    
    @staticmethod
    def aes_generate():
        """生成随机AES密钥
        
        Returns:
            bytes: 256位的AES密钥
        """
        return os.urandom(32)  # 256位密钥
    
    @staticmethod
    def aes_encrypt(key: bytes, data: bytes):
        """使用AES密钥加密数据
        
        Args:
            key (bytes): 256位的AES密钥
            data (bytes): 要加密的数据
        
        Returns:
            bytes: 加密后的数据
        """
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv) # type: ignore
        padded_data = pad(data, AES.block_size)
        return iv + cipher.encrypt(padded_data)
    
    @staticmethod
    def aes_decrypt(key: bytes, encrypted_data: bytes):
        """使用AES密钥解密数据
        
        Args:
            key (bytes): 256位的AES密钥
            encrypted_data (bytes): 要解密的数据
        
        Returns:
            bytes: 解密后的数据
        """
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv) # type: ignore
        padded_plaintext = cipher.decrypt(ciphertext)
        return unpad(padded_plaintext, AES.block_size)
    
    @staticmethod
    def rsa_export(key: RSA.RsaKey):
        '''导出RSA密钥为PEM格式
        
        Args:
            key (RsaKey): 要导出的密钥
            
        Returns:
            bytes: PEM格式的密钥
        '''
        return key.export_key('PEM')
    
    @staticmethod
    def rsa_import(pem: bytes):
        '''从PEM格式导入RSA密钥

        Args:
            pem (bytes): PEM格式的密钥

        Returns:
            RsaKey: 导入的密钥
        '''
        return RSA.import_key(pem)

    @staticmethod
    def rsa_sign(key: RSA.RsaKey, data: bytes):
        """使用私钥对数据进行签名
        
        Args:
            key (RsaKey): 私钥
            data (bytes): 要签名的数据
        
        Returns:
            bytes: 签名结果
        """
        h = SHA256.new(data)
        return pkcs1_15.new(key).sign(h)

    @staticmethod
    def rsa_verify(key: RSA.RsaKey, data: bytes, signature: bytes):
        """使用公钥验证签名
        
        Args:
            key (RsaKey): 公钥
            data (bytes): 要验证的数据
            signature (bytes): 签名结果
        
        Returns:
            bool: 验证通过返回True，否则返回False
        """
        h = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
