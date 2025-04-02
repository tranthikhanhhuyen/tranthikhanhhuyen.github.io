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
