---
title: NTLM学习笔记
tags: 内网
---

### 0x01 LM Hash & NTLM Hash

windows内部是不保存明文密码的，只保存密码的hash。

其中本机用户的密码hash是放在 本地的`SAM`文件 里面，域内用户的密码hash是存在域控的`NTDS.DIT`文件里面

在Windows系统导出密码的时候，经常看到这样的密码格式

`Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0:::`

其中的`AAD3B435B51404EEAAD3B435B51404EE`是`LM Hash`

`31D6CFE0D16AE931B73C59D7E0C089C0`是`NTLM Hash`

#### 1. LM Hash

全称是LAN Manager Hash, windows最早用的加密算法，由IBM设计。

LM Hash的计算:

1. 用户的密码转换为大写，密码转换为16进制字符串，不足14字节将会用0来再后面补全。
2. 密码的16进制字符串被分成两个7byte部分。每部分转换成比特流，并且长度位56bit，长度不足使用0在左边补齐长度
3. 再分7bit为一组,每组末尾加0，再组成一组
4. 上步骤得到的二组，分别作为key 为 `KGS!@#$%`进行DES加密。
5. 将加密后的两组拼接在一起，得到最终LM HASH值。
{% raw %}
```python
#coding=utf-8
import re
import binascii
from pyDes import *
def DesEncrypt(str, Des_Key):
    k = des(binascii.a2b_hex(Des_Key), ECB, pad=None)
    EncryptStr = k.encrypt(str)
    return binascii.b2a_hex(EncryptStr)

def group_just(length,text):
    # text 00110001001100100011001100110100001101010011011000000000
    text_area = re.findall(r'.{%d}' % int(length), text) # ['0011000', '1001100', '1000110', '0110011', '0100001', '1010100', '1101100', '0000000']
    text_area_padding = [i + '0' for i in text_area] #['00110000', '10011000', '10001100', '01100110', '01000010', '10101000', '11011000', '00000000']
    hex_str = ''.join(text_area_padding) # 0011000010011000100011000110011001000010101010001101100000000000
    hex_int = hex(int(hex_str, 2))[2:].rstrip("L") #30988c6642a8d800
    if hex_int == '0':
        hex_int = '0000000000000000'
    return hex_int

def lm_hash(password):
    # 1. 用户的密码转换为大写，密码转换为16进制字符串，不足14字节将会用0来再后面补全。
    pass_hex = password.upper().encode("hex").ljust(28,'0') #3132333435360000000000000000
    print(pass_hex) 
    # 2. 密码的16进制字符串被分成两个7byte部分。每部分转换成比特流，并且长度位56bit，长度不足使用0在左边补齐长度
    left_str = pass_hex[:14] #31323334353600
    right_str = pass_hex[14:] #00000000000000
    left_stream = bin(int(left_str, 16)).lstrip('0b').rjust(56, '0') # 00110001001100100011001100110100001101010011011000000000
    right_stream = bin(int(right_str, 16)).lstrip('0b').rjust(56, '0') # 00000000000000000000000000000000000000000000000000000000
    # 3. 再分7bit为一组,每组末尾加0，再组成一组
    left_stream = group_just(7,left_stream) # 30988c6642a8d800
    right_stream = group_just(7,right_stream) # 0000000000000000
    # 4. 上步骤得到的二组，分别作为key 为 "KGS!@#$%"进行DES加密。
    left_lm = DesEncrypt('KGS!@#$%',left_stream) #44efce164ab921ca
    right_lm = DesEncrypt('KGS!@#$%',right_stream) # aad3b435b51404ee
    # 5. 将加密后的两组拼接在一起，得到最终LM HASH值。
    return left_lm + right_lm

if __name__ == '__main__':
    hash = lm_hash("123456")
```
{% endraw %}
LM加密算法存在一些固有的漏洞

1. 首先，密码长度最大只能为14个字符
2. 密码不区分大小写。在生成哈希值之前，所有密码都将转换为大写
3. 查看我们的加密过程，就可以看到使用的是分组的DES，如果密码强度是小于7位，那么第二个分组加密后的结果肯定是aad3b435b51404ee，如果我们看到lm hash的结尾是aad3b435b51404ee，就可以很轻易的发现密码强度少于7位
4. 一个14个字符的密码分成7 + 7个字符，并且分别为这两个半部分计算哈希值。这种计算哈希值的方式使破解难度成倍增加，因为攻击者需要将7个字符（而不是14个字符）强制暴力破解。这使得14个字符的密码的有效强度等于，或者是7个字符的密码的两倍，该密码的复杂度明显低于[![img](https://p0.ssl.qhimg.com/t01f87ddf44d540f820.png)](https://p0.ssl.qhimg.com/t01f87ddf44d540f820.png)14个字符的密码的理论强度。
5. Des密码强度不高

#### 2. NTLM Hash

为了解决LM加密和身份验证方案中固有的安全弱点，Microsoft 于1993年在Windows NT 3.1中引入了NTLM协议。下面是各个版本对LM和NTLM的支持。

[![img](https://p0.ssl.qhimg.com/t01a757a68445cea7e0.png)](https://p0.ssl.qhimg.com/t01a757a68445cea7e0.png)

其中

[![img](https://p5.ssl.qhimg.com/t016342a0c8ac5deb12.png)](https://p5.ssl.qhimg.com/t016342a0c8ac5deb12.png)

也就是说从Windows Vista 和 Windows Server 2008开始，默认情况下只存储NTLM Hash，LM Hash将不再存在。(因此后面我们介绍身份认证的时候只介绍Net-ntlm，不再介绍net-lm)如果空密码或者不储蓄LM Hash的话，我们抓到的LM Hash是AAD3B435B51404EEAAD3B435B51404EE。

所以在win7 中我们看到抓到LM Hash都是AAD3B435B51404EEAAD3B435B51404EE，这里的LM Hash并没有价值。

[![img](https://p5.ssl.qhimg.com/t0113a4184680657402.png)](https://p5.ssl.qhimg.com/t0113a4184680657402.png)

但某些工具的参数需要填写固定格式LM hash:NT hash，可以将LM hash填0(LM hash可以为任意值)，即00000000000000000000000000000000:NT hash。

接下来讲下NTLM Hash的计算

1.先将用户密码转换为十六进制格式。

2.将十六进制格式的密码进行Unicode编码。

3.使用MD4摘要算法对Unicode编码数据进行Hash计算

```python
python2 -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "p@Assword!123".encode("utf-16le")).digest())'
```

### 0x02 NTLM身份验证

NTLM验证是一种Challenge/Response 验证机制，由三种消息组成:通常称为type 1(协商)，类型type 2(质询)和type 3(身份验证)。

它基本上是这样工作的:

[![img](https://p5.ssl.qhimg.com/t01652f775797dd2789.png)](https://p5.ssl.qhimg.com/t01652f775797dd2789.png)

1. 用户登录客户端电脑
2. (type 1)客户端向服务器发送type 1(协商)消息,它主要包含客户端支持和服务器请求的功能列表。
3. (type 2)服务器用type 2消息(质询)进行响应，这包含服务器支持和同意的功能列表。但是，最重要的是，它包含服务器产生的Challenge。NTLMv2协议下会生成一个16位的随机数（这个随机数称为Challenge），使用存储的登录用户名密码hash加密Challenge，获得challenge1
4. (type 3)客户端用type 3消息(身份验证)回复质询。用户接收到步骤3中的challenge之后，使用用户hash与challenge进行加密运算得到response，将response,username,challenge发给服务器。消息中的response是最关键的部分，因为它们**向服务器证明客户端用户已经知道帐户密码**。
5. 服务器拿到type 3之后比较比较response和Challenge1，如果相同，验证成功



如果是在域环境的话，用户的hash是存在域控的`NTDS.dit`，服务器拿到客户端发的response(使用用户的hash和challenge加密得到)后，自己本地没有用户hash，所以这时候服务器端就会通过Netlogon协议联系域控，建立一个安全通道，然后将type 1,type 2，type3 全部发给域控(这个过程也叫作Pass Through Authentication认证流程)，域控使用challenge和用户hash进行加密得到response2，与type 3的response进行比较。

### 0x03 Net-ntlm hash

在type3中的响应，有六种类型的响应

1. LM(LAN Manager)响应 – 由大多数较早的客户端发送，这是“原始”响应类型。
2. NTLM v1响应 – 这是由基于NT的客户端发送的，包括Windows 2000和XP。
3. NTLMv2响应 – 在Windows NT Service Pack 4中引入的一种较新的响应类型。它替换启用了 NTLM版本2的系统上的NTLM响应。
4. LMv2响应 – 替代NTLM版本2系统上的LM响应。
5. NTLM2会话响应 – 用于在没有NTLMv2身份验证的情况下协商NTLM2会话安全性时，此方案会更改LM NTLM响应的语义。
6. 匿名响应 – 当匿名上下文正在建立时使用; 没有提供实际的证书，也没有真正的身份验证。“存 根”字段显示在类型3消息中。

这六种使用的加密流程一样，都是前面我们说的Challenge/Response 验证机制,区别在Challenge和加密算法不同。

### 0x04 SSP & SSPI

 

[![img](https://p3.ssl.qhimg.com/t011196a61b6f4e8bd8.png)](https://p3.ssl.qhimg.com/t011196a61b6f4e8bd8.png)

- SSPI(Security Support Provider Interface)

这是 Windows 定义的一套接口，此接口定义了与安全有关的功能函数， 用来获得验证、信息完整性、信息隐私等安全功能，就是定义了一套接口函数用来身份验证，签名等，但是没有具体的实现。

- SSP(Security Support Provider)

SSPI 的实现者，对SSPI相关功能函数的具体实现。微软自己实现了如下的 SSP，用于提供安全功能：

1. NTLM SSP
2. Kerberos
3. Cred SSP
4. Digest SSP
5. Negotiate SSP
6. Schannel SSP
7. Negotiate Extensions SSP
8. PKU2U SSP

在系统层面，SSP就是一个dll，来实现身份验证等安全功能，实现的身份验证机制是不一样的。比如 NTLM SSP 实现的就是一种 Challenge/Response 验证机制。而 Kerberos 实现的就是基于 ticket 的身份验证机制。我们可以编写自己的 SSP，然后注册到操作系统中，让操作系统支持更多的自定义的身份验证方法。

这个地方可以用于留作后门。



抓包分析的时候会发现，NTLM相关的东西是放在GSS-API里面。

![屏幕快照 2020-12-01 18.26.12](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201201182646.png)

`通用安全服务应用程序接口(GSSAPI)·`是为了让程序能够访问安全服务的一个应用程序接口。他是一个通用的安全接口，程序员不必关心各种平台，各种保护网络数据方面的各种细节。

SSPI是GSSAPI的一个专有变体，进行了扩展并具有许多特定于Windows的数据类型。

SSPI生成和接受的令牌大多与GSS-API兼容。所以这里出现GSSAPI只是为了兼容，我们可以不必理会。

可以直接从NTLM SSP开始看起。**注册为SSP的一个好处就是，SSP实现了了与安全有关的功能函数**，那上层协议(比如SMB)在进行身份认证等功能的时候，就可以不用考虑协议细节，只需要调用相关的函数即可。

而认证过程中的流量嵌入在上层协议里面。**不像kerbreos，既可以镶嵌在上层协议里面，也可以作为独立的应用层协议。**ntlm是只能镶嵌在上层协议里面，消息的传输依赖于使用ntlm的上层协议。比如镶嵌在SMB协议里面是这样。

![屏幕快照 2020-12-01 18.33.03](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201201183314.png)

镶嵌在HTTP协议里面是这样:

![屏幕快照 2020-12-01 18.32.49](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201201183328.png)

### 0x05 LmCompatibilityLevel

此安全设置确定网络登录使用的质询/响应身份验证协议。此选项会影响客户端使用的身份验证协议的等级、协商的会话安全的等级以及服务器接受的身份验证的等级，其设置值如下:

- `发送 LM NTLM 响应`: 客户端使用 LM 和 NTLM 身份验证，而决不会使用 NTLMv2 会话安全；域控制器接受 LM、NTLM 和 NTLMv2 身份验证。
- `发送 LM & NTLM – 如果协商一致，则使用 NTLMv2 会话安全`: 客户端使用 LM 和 NTLM 身份验证，并且在服务器支持时使用 NTLMv2 会话安全；域控制器接受 LM、NTLM 和 NTLMv2 身份验证。
- `仅发送 NTLM 响应`: 客户端仅使用 NTLM 身份验证，并且在服务器支持时使用 NTLMv2 会话安全；域控制器接受 LM、NTLM 和 NTLMv2 身份验证。
- `仅发送 NTLMv2 响应`: 客户端仅使用 NTLMv2 身份验证，并且在服务器支持时使用 NTLMv2 会话安全；域控制器接受 LM、NTLM 和 NTLMv2 身份验证。
- `仅发送 NTLMv2 响应\拒绝 LM`: 客户端仅使用 NTLMv2 身份验证，并且在服务器支持时使用 NTLMv2 会话安全；域控制器拒绝 LM (仅接受 NTLM 和 NTLMv2 身份验证)。
- `仅发送 NTLMv2 响应\拒绝 LM & NTLM`: 客户端仅使用 NTLMv2 身份验证，并且在服务器支持时使用 NTLMv2 会话安全；域控制器拒绝 LM 和 NTLM (仅接受 NTLMv2 身份验证)。

##### 默认值:

- `Windows 2000 以及 Windows XP`: 发送 LM & NTLM 响应
- `Windows Server 2003`: 仅发送 NTLM 响应
- `Windows Vista、Windows Server 2008、Windows 7 以及 Windows Server 2008 R2及以上`: 仅发送 NTLMv2 响应

### 0x06 相关的安全问题

#### 1. pass the hash





#### 2.NTML Relay

进行中继前提：目标SMB签名需要关闭，在SMB连接中，需要使用安全机制来保护服务器和客户端之间传输数据的完整性，而这种安全机制就是SMB签名和加密，如果关闭SMB签名，会允许攻击者拦截认证过程，并且将获得hash在其他机器上进行重放，从而获得权限。