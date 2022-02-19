from socket import*
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Cipher import DES3
from Crypto.Hash import SHA
import json
import time
import sys
import base64

def pad(text):#如果数据长度不是8的倍数，将数据填充到16的倍数，用于des加密。
    while len(text)%8 != 0:
        text += ' '
    return text

server_ip=input("输入服务器IP地址：\n")#服务器IP地址
server_port=5050#服务器端口号
client_socket=socket(AF_INET,SOCK_STREAM)#创建TCP套接字
client_socket.connect((server_ip,server_port))#用tcp套接字连接服务器
ran_1=Random.new().read(256)#生成第一个随机数
#加密算法组合的集合
cipher_suites=['TLS_RSA_WITH_SDES_EDE_CBC_SHA (0x000a)','TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)','TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)',
               'TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)','TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)',
               'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)','TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)','TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)']
#client hello包
client_hello={'Content Type':'Handshake (22)','Handshake Type':'Client Hello (1)','Version':'TLS 1.2 (0x0303)',
                'Random':base64.b64encode(ran_1).decode(),'Cipher Suites':cipher_suites}
client_hello_message=json.dumps(client_hello)
client_socket.send(client_hello_message.encode())
cipher_suite=""#选择的加密算法组合
while True:#接受从服务器发来的证书、公钥等信息
    receive=client_socket.recvfrom(1024)
    receive_content=json.loads(receive[0])
    print(receive[0])
    if receive_content['Handshake Type']=='Server Hello Done (14)':
        break#如果是Server Hello Done包，结束等待，进入下一个阶段
    elif receive_content['Handshake Type']=='Server Key Exchange (12)':
        #如果是Server Key Exchange包，保存收到的公钥
        if cipher_suites.index(cipher_suite)<5:#如果采用RSA算法，保存公钥即可，客户端不用发送Server Key Exchange包。
            server_pem=base64.b64decode(receive_content['Pubkey'].encode())
            with open('D:\\recv-server-public.pem','wb') as f:
                f.write(server_pem)
        #其他情况
    elif receive_content['Handshake Type']=='Server Hello (2)':#如果是Server Hello包，保存相应信息
        cipher_suite=receive_content['Cipher Suite']#保存服务器选择的加密算法组合
        ran_2=base64.b64decode(receive_content['Random'].encode())#保存第二个随机数
#Change Cipher Spec包
change_cipher_spec={'Content Type':'Change Cipher Spec (20)','Version':'TLS 1.2 (0x0303)'}
change_cipher_spec_message=json.dumps(change_cipher_spec)
client_socket.send(change_cipher_spec_message.encode())
if cipher_suites.index(cipher_suite)==0:#采用RSA算法和3DES算法，CBC模式
    des_key=Random.new().read(DES3.key_size[-1])#生成密钥
    iv = Random.new().read(DES3.block_size)#生成偏移量，用于CBC模式
    des3 = DES3.new(des_key, DES3.MODE_CBC, iv)
    with open('D:\\recv-server-public.pem') as f:
        key=f.read()#利用收到的RSA公钥加密3DES算法的密钥和CBC模式的偏移量
        rsakey=RSA.importKey(key)
        cipher=Cipher_pkcs1_v1_5.new(rsakey)
        cipher_key=cipher.encrypt(des_key)
        cipher_iv=cipher.encrypt(iv)
    #encrypted handshake message包
    finished={'Content Type':'Handshake (22)','Handshake Type':'Encrypted Handshake Message (20)','Version':'TLS 1.2 (0x0303)',
                'Encrypted Message 1':base64.b64encode(cipher_key).decode(),'Encrypted Message 2':base64.b64encode(cipher_iv).decode()}
    finished_message=json.dumps(finished)
    client_socket.send(finished_message.encode())
if cipher_suites.index(cipher_suite)==0:#采用3DES算法和CBC模式
    while True:
        receive=client_socket.recvfrom(1024)
        print(receive[0])
        recv_content_2=json.loads(receive[0])
        if recv_content_2['Content Type']=='Change Cipher Spec (20)':
            continue
        elif recv_content_2['Handshake Type']=='Encrypted Handshake Message (20)':
            #获取服务器发来的加密信息并解密
            en_ran_1=base64.b64decode(recv_content_2['Encrypted Message 1'].encode())
            en_ran_2=base64.b64decode(recv_content_2['Encrypted Message 2'].encode())
            recv_ran_1=des3.decrypt(en_ran_1)
            recv_ran_2=des3.decrypt(en_ran_2)
            break
#其他情况
#判断服务器发来的加密信息是否为之前的两个随机数，不是则说明不是之前的服务器或出现其他问题，断开连接
if (ran_1!=recv_ran_1)|(ran_2!=recv_ran_2):
    print("The server is invalid.")
    client_socket.close()
    sys.exit(0)
f=open('D:\\msg.txt','r')#打开需要传输的文件内容
content=""
isend=0#判断是否为传输的最后一个数据包的信号量
if cipher_suites.index(cipher_suite)==0:#采用3DES和SHA算法
    des3 = DES3.new(des_key, DES3.MODE_CBC, iv)
    sha=SHA.new()
    while isend==0:
        content=f.read(216)#获取216字节的数据
        if len(content)!=216:#如果不足216字节，则需校准，并且说明这说要发送的最后一个数据包
            content=pad(content)
            isend=1
        sha.update(content.encode())
        mac=sha.hexdigest()#生成hash值，长度为40个字节
        content+=mac#将hash值放到数据后面，总长度为256字节
        en_content=des3.encrypt(pad(content).encode())#将数据和hash值一块用3DES算法加密
        #发送Application data包
        send={'Content Type':'Application data (23)','Version':'TLS 1.2 (0x0303)','isend':isend,
                'Encrypted Application Data':base64.b64encode(en_content).decode()}
        send_message=json.dumps(send)
        client_socket.send(send_message.encode())
        time.sleep(0.1)#等待0.1秒，否则发送速度太快，会发生tcp包合并
        content=""#重置数据
#其他情况
f.close()
client_socket.close()