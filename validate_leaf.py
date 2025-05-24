from utils import CryptoUtils as crypto

with open('leaf_sign.pem', 'rb') as f:
    sign = f.read()

with open('leaf_public.pem', 'rb') as f:
    leaf = f.read()

with open('root_public.pem', 'rb') as f:
    root = crypto.rsa_import(f.read())

assert crypto.rsa_verify(root, leaf, sign)

print('OK')