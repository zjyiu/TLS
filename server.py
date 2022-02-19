from socket import*
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Cipher import DES3
from Crypto.Hash import SHA
import json
#import time
import base64

#加密算法组合的集合
cipher_suites=['TLS_RSA_WITH_SDES_EDE_CBC_SHA (0x000a)','TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)','TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)',
               'TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)','TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)',
               'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)','TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)','TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)']

#发送sever hello包
def send_sever_hello(connection_socket,recv_content,temp,ran_2):
    server_hello={'Content Type':'Handshake (22)','Handshake Type':'Server Hello (2)','Version':'TLS 1.2 (0x0303)',
                'Random':base64.b64encode(ran_2).decode(),'Cipher Suite':recv_content['Cipher Suites'][temp]}
    server_hello_message=json.dumps(server_hello)
    connection_socket.send(server_hello_message.encode())

#发送server hello done包
def send_server_hello_done(connection_socket):
    server_hello_done={'Content Type':'Handshake (22)','Handshake Type':'Server Hello Done (14)','Version':'TLS 1.2 (0x0303)'}
    server_hello_done_message=json.dumps(server_hello_done)
    connection_socket.send(server_hello_done_message.encode())

#发送change cipher spec包
def send_change_cipher_spec(connection_socket):
    change_cipher_spec={'Content Type':'Change Cipher Spec (20)','Version':'TLS 1.2 (0x0303)'}
    change_cipher_spec_message=json.dumps(change_cipher_spec)
    connection_socket.send(change_cipher_spec_message.encode())

#发送使用RSA算法时的server key exchange包
def send_rsa_server_key_exchange(connection_socket):
    random_generator=Random.new().read
    rsa=RSA.generate(1024,random_generator)
    private_pem=rsa.exportKey()#生成RSA私钥并保存
    with open('D:\\server-private.pem','wb') as f:
        f.write(private_pem)
    public_pem=rsa.publickey().exportKey()#生成RSA公钥并保存
    with open('D:\\server-public.pem','wb') as f:
        f.write(public_pem)
    server_key_exchange={'Content Type':'Handshake (22)','Handshake Type':'Server Key Exchange (12)','Version':'TLS 1.2 (0x0303)',
                        'Pubkey':base64.b64encode(public_pem).decode()}#发送RSA公钥
    server_key_exchange_message=json.dumps(server_key_exchange)
    connection_socket.send(server_key_exchange_message.encode())
    #time.sleep(0.1)

#发送使用CBC模式下的3DES算法时的encrypted handshake message包
def send_finished(connection_socket,des3,ran_1,ran_2):
    #将之前的两个随机数用客户端发来的密钥和偏移量进行CBC模式下的3DES加密
    en_ran_1=des3.encrypt(ran_1)
    en_ran_2=des3.encrypt(ran_2)
    finished={'Content Type':'Handshake (22)','Handshake Type':'Encrypted Handshake Message (20)','Version':'TLS 1.2 (0x0303)',
                'Encrypted Message 1':base64.b64encode(en_ran_1).decode(),'Encrypted Message 2':base64.b64encode(en_ran_2).decode()}
    finished_message=json.dumps(finished)
    connection_socket.send(finished_message.encode())

server_port=5050#端口号
server_socket=socket(AF_INET,SOCK_STREAM)
server_socket.bind(("",server_port))#监听端口
server_socket.listen(1)#限制同时只能有一个客户连接
while True:
    connection_socket,addr=server_socket.accept()#与客户端建立连接
    print("Accept new connection from %s:%s\n"%addr)
    receive=connection_socket.recv(1024)#接受客户端发来的信息
    recv_content_1=json.loads(receive.decode())
    print(recv_content_1)
    if recv_content_1['Content Type']=='Handshake (22)':
        if recv_content_1['Handshake Type']=='Client Hello (1)':#判断客户端想进行TLS握手
            ran_1=base64.b64decode(recv_content_1['Random'].encode())#获取客户端生成的第一个随机数
            temp=0#选择一种加密算法组合，这里只实现了第一种，所以直接选第一种
            ran_2=Random.new().read(256)#生成第二个随机数
            send_sever_hello(connection_socket,recv_content_1,temp,ran_2)#发送server hello包
            cipher_suite=recv_content_1['Cipher Suites'][temp]#获取加密算法组合
            if cipher_suites.index(cipher_suite)<5:#采用RSA算法
                send_rsa_server_key_exchange(connection_socket)#发送server key exchange包
            send_server_hello_done(connection_socket)#发送server hello done包
    while True:#接收从客户端发来的信息
        receive=connection_socket.recvfrom(1024)
        print(receive[0])
        recv_content_2=json.loads(receive[0])
        #如果是Change Cipher Spec包，那同样发送Change Cipher Spec包给客户端
        if recv_content_2['Content Type']=='Change Cipher Spec (20)':
            send_change_cipher_spec(connection_socket)
            #time.sleep(1)
        #如果是encrypted handshake message包
        elif recv_content_2['Handshake Type']=='Encrypted Handshake Message (20)':
            if cipher_suites.index(cipher_suite)==0:#如果采用RSA和CBC模式下的3DES算法
                #获取加密后的密钥和偏移量
                en_des_key=base64.b64decode(recv_content_2['Encrypted Message 1'].encode())
                en_iv=base64.b64decode(recv_content_2['Encrypted Message 2'].encode())
                #将密钥和偏移量用RSA私钥解密
                with open('D:\\server-private.pem') as f:
                    key=f.read()
                    rsakey=RSA.importKey(key)
                    cipher=Cipher_pkcs1_v1_5.new(rsakey)
                    des_key=cipher.decrypt(en_des_key,"ERROR")
                    iv=cipher.decrypt(en_iv,"ERROR")
                des3 = DES3.new(des_key, DES3.MODE_CBC, iv)
                #发送encrypted handshake message包
                send_finished(connection_socket,des3,ran_1,ran_2)
                break
    if cipher_suites.index(cipher_suite)==0:#用CBC模式下的3DES算法和SHA算法
        des3 = DES3.new(des_key, DES3.MODE_CBC, iv)
        sha=SHA.new()
        contents=[]#缓冲区
        while True:
            recv=connection_socket.recvfrom(1024)
            print(recv[0])
            recv_content=json.loads(recv[0])
            if(recv_content['Content Type']!='Application data (23)'):
                continue#如果不是Application data包，忽略
            isend=recv_content['isend']#判断是否为最后一个数据包
            en_content=base64.b64decode(recv_content['Encrypted Application Data'].encode())
            content=des3.decrypt(en_content)#对数据进行解密
            content=str(content,encoding='utf-8')#转码
            mac_1=content[-40:]#获取MAC
            content=content[:-40]#获取数据
            sha.update(content.encode())
            mac_2=sha.hexdigest()#利用数据计算MAC
            if mac_1!=mac_2:#验证MAC，不对则停止接受文件
                break
            contents.append(content)#缓存收到的数据
            if isend==1:#如果是最后一个包则停止接收
                break
    f=open('D:\\get.txt','a')#保存收到的数据
    for i in range(0,len(contents)):
        f.write(contents[i])
    f.close()
    connection_socket.close()