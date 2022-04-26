---
title: nopac在MAQ=0时的利用
tags: 域渗透
---

### 0x00 前言

​	最近还看到有人发关于`CVE-2021-42278`和`CVE-2021-42287`的分析利用文章，也就是nopac这个漏洞，漏洞都补完了怎么含在说啊；对于利用来看这些文章都提及到了MAQ为0的情况，对于这个情况的利用也都介绍了但是不太全面，我之前的文章也是简单提了一嘴，在早些在星球内也拓展过利用思路。

​	所以干脆今天就来帮大家总结一下MAQ=0时的利用方式，小菊花妈妈课堂开课啦！

### 0x01 原理

​	MAQ，`MS-DS-Machine-Account-Quota`，此属性为允许用户在域中创建的计算机帐户数。

![image-20220304180732006](https://images-1258433570.cos.ap-beijing.myqcloud.com/imagesimage-20220304180732006.png)

​	许多域内为了缓解一些委派、Relay攻击都将此属性设置为0，那么代表着攻击者没办法在没有已控制机器账户的情况下去申请票据了，所以可以缓解一下此类攻击。

### 0x02 利用	

​	得知是否限制了MAQ可以使用LDAP查询工具去查询`ms-DSMachineAccountQuota`这个属性即可

```
ldapsearch -x -h 10.0.1.1 -b "DC=test,DC=com" -D "CN=duck,CN=Users,DC=test,DC=com"
-W -s sub "(objectclass=domain)" | grep "ms-ds-machineaccountquota" -i
```

#### 1. MAQ>0的情况

​	如果不是只傻狗应该直接打就可以了，具体打的命令操作等就不赘述了，参考之前的文章。



#### 2. MAQ=0的情况

​	如果在限制了MAQ属性的情况下，**攻击的核⼼就是需要对⼀个账⼾有写权限**

##### 2.2 Creater-SID

​	机器账户被拉入域的用户账户对这个机器账户有`GenericAll`的权限，意味着可以更改其属性；对应机器账户中的`creater-sid`这个属性的sid就为拉它入域的用户账户。

​	所以我们存在用户凭据的情况下可以查看是否有机器账户可以写的。



​	然后就可以利用当前账户去做攻击：

1. 清除此机器账户的SPN
2. 更改此机器账户密码
3. 攻击过程
4. 恢复密码
5. 恢复此账户的SPN(重要)

更改密码就利用`SAMR协议`去更改即可。

##### 2.3 用户组

​	还可以查一下对某些**机器、或是用户**有写权限的组:

```
Get-DomainObjectAcl duck -ResolveGUIDs | ?{$_.SecurityIdentifier -eq (Get-DomainUser dog).objectsid}
```

​	可能会有一些特殊的用户组，这样可以有针对性的寻找该用户继而修改对应的机器账户。

​	接着和上述流程一样。

##### 2.4 加域账号

​	这里说的是MAQ限制情况下所存在的加域账户，有可能限制了MAQ，但是企业肯定要加机器到域⾥的，对应的组策略

privilege就是`SeMachineAccountPrivilege`

```
adfind -b CN=Computers,DC=test,DC=com -sddl+++ -s base -sdna -sddlfilter ;;"CR
CHILD";;;
```

​	找到这个⽤⼾的话，再⽤他来添加机器账⼾即可。

#### 3.域外无凭据

​	在域外没有凭据的情况下，就是要搞⼀个机器账⼾或是用户账户先入域再说，可以配合webdav、rbcd等等思路拿到一个机器账户接着去按以上思路搜集信息，然后就是MAQ限制和不限制两种情况了。

### 0x03 总结

​	其实总的思路就是想办法找A对B有`WriteProperty`即可