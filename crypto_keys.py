from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Tạo khóa RSA 2048-bit
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Xuất khóa private
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Xuất khóa public
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Lưu vào file
with open("private_key.pem", "wb") as f:
    f.write(private_pem)

with open("public_key.pem", "wb") as f:
    f.write(public_pem)

print("Keys generated and saved as PEM files!")







from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
import base64
import os

# Đọc private key từ file
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Mật khẩu để mã hóa
password = b"my_secure_password"
salt = os.urandom(16)  # Tạo salt ngẫu nhiên

# Tạo khóa từ password
kdf = PBKDF2HMAC(
    algorithm=SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# Mã hóa private key
encrypted_private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password)
)

# Lưu khóa đã mã hóa
with open("encrypted_private_key.pem", "wb") as f:
    f.write(encrypted_private_pem)

print("Private key encrypted and saved!")


import bitcoin

# Tạo private key mới
private_key = bitcoin.random_key()
print("Private Key:", private_key)

# Tạo public key từ private key
public_key = bitcoin.privtopub(private_key)
print("Public Key:", public_key)

# Tạo địa chỉ Bitcoin từ public key
bitcoin_address = bitcoin.pubtoaddr(public_key)
print("Bitcoin Address:", bitcoin_address)

import bitcoin

wif_key = "5HueCGU8rMjxEXxiPuD5BDuVJPiZRYPmu6BToW8fGN5XQdF2Tbb"
hex_key = bitcoin.decode_privkey(wif_key, 'wif')
print("Hex Private Key:", hex_key)


import ecdsa
import hashlib

# Tạo private key
sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

# Tạo public key từ private key
vk = sk.get_verifying_key()

# Tin nhắn cần ký
message = b"Hello, this is a signed message!"
message_hash = hashlib.sha256(message).digest()

# Ký tin nhắn
signature = sk.sign(message_hash)

# Xác minh chữ ký
is_valid = vk.verify(signature, message_hash)
print("Signature valid:", is_valid)



