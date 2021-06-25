---
title: Printer Spooler 配置基于资源的约束委派利用记录
tags: 域渗透
---
首先通过impacket套件中的addcomputer.py 添加机器用户

![image-20210625150535338](/Users/ayaozpy/Library/Application Support/typora-user-images/image-20210625150535338.png)

注：添加机器用户是为了配置完RBCD之后利用这个具有SPN的账户去通过S4U协议申请到目标机器(也就是NTLM请求发出的机器)的TGS Ticket，或者配合`CVE-2019-1040`去中继一个域内机器也可以添加机器账户(因为LDAP不允许非加密连接添加账户，这个漏洞正是绕过了NTLM中验证消息完整性的标识位)



为了配合SpoolSample使用，还需要将中继机器添加至域内DNS，这里可以使用powermad工具中的`Invoke-DNSUpdate`，以及`printerbug.py`等等

![image-20210625150651467](/Users/ayaozpy/Library/Application Support/typora-user-images/image-20210625150651467.png)

通过PrintSpoofer强制主机向test主机发起认证

![image-20210625063836924](/Users/ayaozpy/Library/Application Support/typora-user-images/image-20210625063836924.png)

中继机器收到认证，中继至LDAP配置基于资源的约束性委派(evilpc$->DUCK$)

![image-20210625150353267](/Users/ayaozpy/Library/Application Support/typora-user-images/image-20210625150353267.png)

然后利用S4U协议申请到`DUCK.pig.com`的Ticket

![image-20210625152608116](/Users/ayaozpy/Library/Application Support/typora-user-images/image-20210625152608116.png)

最后，可以成功访问

![image-20210625073550559](/Users/ayaozpy/Library/Application Support/typora-user-images/image-20210625073550559.png)

总结，其实就是如果存在`CVE-2019-1040`这个漏洞的话，那么这个利用讲非常灵活，可以不用考虑触发的NTLM请求是否携带签名，goodgood晚安