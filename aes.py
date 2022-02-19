from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher.DES3 import MODE_CBC

def pad(text):
    while len(text)%16 != 0:
        text += ' '
    return text

iv = Random.new().read(AES.block_size)
print(iv)
key = Random.new().read(AES.key_size[-1])
print(key)
print(len(key))
aes=AES.new(key,MODE_CBC,iv)
text="12345678"
res=aes.encrypt(pad(text).encode())
print(res)
aes=AES.new(key,MODE_CBC,iv)
a=aes.decrypt(res)
print(a)
print(str(a,encoding='utf-8'))