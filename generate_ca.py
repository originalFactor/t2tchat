from utils import CryptoUtils as crypto

priv, pub = crypto.rsa_generate()

with open('root_private.pem', 'wb') as f:
    f.write(crypto.rsa_export(priv))

with open('root_public.pem', 'wb') as f:
    f.write(crypto.rsa_export(pub))

