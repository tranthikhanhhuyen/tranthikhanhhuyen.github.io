import bitcoin

# Tạo private key mới
private_key = bitcoin.random_key()
print(" Private Key:", private_key)

# Tạo public key từ private key
public_key = bitcoin.privtopub(private_key)
print(" Public Key:", public_key)

# Tạo địa chỉ Bitcoin từ public key
bitcoin_address = bitcoin.pubtoaddr(public_key)
print(" Bitcoin Address:", bitcoin_address)
