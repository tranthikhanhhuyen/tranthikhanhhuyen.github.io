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
print(" Signature valid:", is_valid)
