- 使用语言：python3.7

- 运行环境：win10

- 源代码：source code目录下的client.py和server.py

- 可执行文件：\dist\client\client.exe

  ​	  				 \dist\server\server.exe

- server.exe会在5050端口监听，client.exe会连接服务器的5050端口

- 在运行client.exe后，需要输入服务器的IP地址。

- 运行client.exe之前，先将名为msg.txt文件放到D盘根目录下，可采用我提供的msg.txt进行验证。

- 服务器收到的数据会存在D盘根目录下的get.txt文件中。

- 服务器生成的RSA公钥和私钥会分别存在D盘根目录下的server-private.pem和server-public.pem文件里。客户端收到的RSA公钥会存到D盘根目录下的recv-server-public.pem文件里。

- 服务器和客户端会打印出收到的数据内容。

- 所使用的python库：socket、pycryptodome、json、time、sys、base64。

- 如果可执行文件运行不成功，可以利用两个源代码，使用pyinstaller生成可执行文件，具体命令为：

  pyinstaller+文件.py

  pyinstaller安装命令为：pip install pyinstaller

- server.exe正常运行的界面为：
  ![image-20211115214943508](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20211115214943508.png)
  
  ![image-20211115221305982](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20211115221305982.png)
  
- client.exe正常运行的界面为：

  ![image-20211115221240430](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20211115221240430.png)

然后服务器应该就能在D盘根目录下的get.txt文件中看到接收的数据。
