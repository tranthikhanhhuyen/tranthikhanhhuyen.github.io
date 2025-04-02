import bitcoin

wif_key = "5HueCGU8rMjxEXxiPuD5BDuVJPiZRYPmu6BToW8fGN5XQdF2Tbb"
hex_key = bitcoin.decode_privkey(wif_key, 'wif')
print("🔷 Hex Private Key:", hex_key)
