from os import terminal_size
from Crypto.Cipher import DES3
from Crypto import Random

def pad(text):
    while len(text)%8 != 0:
        text += ' '
    return text

iv = Random.new().read(DES3.block_size)
print(iv)
key = Random.new().read(DES3.key_size[-1])
print(key)
des3 = DES3.new(key, DES3.MODE_CBC, iv)
text=Random.new().read(16)
text="123456"
print(text)
#print(len(str(text)))
res=des3.encrypt(pad(text).encode())
print(res)
des1=DES3.new(key, DES3.MODE_CBC, iv)
m=des1.decrypt(res)
print(str(m,encoding='utf-8'))