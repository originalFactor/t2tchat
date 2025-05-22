import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CryptoUtils:
    @staticmethod
    def encode(data: bytes):
        return base64.b64encode(data).decode()
    
    @staticmethod
    def decode(data: str):
        return base64.b64decode(data)

    @staticmethod
    def generate_private():
        """生成RSA密钥对"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    @staticmethod
    def rsa_encrypt(public_key: rsa.RSAPublicKey, data: str | bytes):
        """使用RSA公钥加密数据"""
        if isinstance(data, str):
            data = data.encode()
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def rsa_decrypt(private_key: rsa.RSAPrivateKey, encrypted_data: str | bytes):
        """使用RSA私钥解密数据"""
        if isinstance(encrypted_data, str):
            encrypted_data = CryptoUtils.decode(encrypted_data)
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def generate_aes_key():
        """生成随机AES密钥"""
        return os.urandom(32)  # 256位密钥
    
    @staticmethod
    def aes_encrypt(key: bytes, data: str | bytes):
        """使用AES密钥加密数据"""
        if isinstance(data, str):
            data = data.encode()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # 添加PKCS7填充
        pad_length = 16 - (len(data) % 16)
        padded_data = bytes(data) + bytes([pad_length] * pad_length)
        
        return iv + encryptor.update(padded_data) + encryptor.finalize()
    
    @staticmethod
    def aes_decrypt(key: bytes, encrypted_data: bytes | str):
        """使用AES密钥解密数据"""
        if isinstance(encrypted_data, str):
            encrypted_data = CryptoUtils.decode(encrypted_data)
        
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        pad_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_length]
        
        return plaintext
    
    @staticmethod
    def serialize_private(key: rsa.RSAPrivateKey):
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    
    @staticmethod
    def serialize_public(key: rsa.RSAPublicKey):
        return key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_private(pem: bytes):
        return _ if (isinstance(_:=serialization.load_pem_private_key(pem, None), rsa.RSAPrivateKey)) else None

    @staticmethod
    def deserialize_public(pem: bytes):
        return (
            _ if isinstance((_ := serialization.load_pem_public_key(pem)), rsa.RSAPublicKey) else None
        )
