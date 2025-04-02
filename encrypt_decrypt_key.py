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

print(" Private key encrypted and saved!")

