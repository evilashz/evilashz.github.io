---
title: 记一次.NET程序的数据库密码解密
tags: 杂
---

简单的.NET程序的数据库解密流程的练习

-----
PS:
MAC反编译.NET的DLL可以直接在`VSCODE`下载插件`ILSPY`，然后打开`VSCODE`的命令行输入`>Decompile`，即可选择DLL反编译。

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211030043646.png)

### 程序一

进入正题，打开webshell管理工具，连接小伙伴给的shell，切换至根目录查看到存在文件`ClientService.svc`

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211102221942.png)

	这里面有两个重要的参数：`Service`和`CodeBehind`。

- `Service`是属性值是WCF的服务实现类的完全限定名。

- `CodeBehind`是服务实现类所在的文件名。

在运行的时候，宿主程序从svc文件中的Service属性得到WCF服务的完全限定名，然后从配置文件中找到同名的servicce，进而找到所有的EndPoint，并根据其属性进行实例化。

这说明此WEB服务为WCF服务，直接进入/bin下打开`ClientService.svc.cs`，查看到存在UserLogin接口方法的实现

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211102223616.png)

可以看到会根据登陆类型的不同进入不同的处理，登陆类型为2时，进入`Business.AnonymousUsers.JudgeUserLogin()`方法处理；登陆类型为0时，进入`Business.AnonymousUsers.UserLogin()`处理，我们只关注第二个登陆类型就好。

`Business.AnonymousUsers.UserLogin()`在`XXX.ASystem.Business.dll`中实现，

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103204625.png)

发现其会实例化以下结构的user，这里不必关注，然后进入`GlobalParameters.PlatformUrl`中的UserLogin方法

<img src="https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103204709.png" alt="image-20211103204708152" style="zoom:67%;" />

接着查看`GlobalParameters.PlatformUrl`为

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103204913.png)

到Web.Config中查看，此配置为本地15801开启的WEB服务，

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211030202533.png)

发现上面实例化user的时候调用的DLL名字就与我们开始反编译的DLL不一样了，开始的为`XXX.ASystem.Business.dll`，而实例化user的时候声明的类型为`XXX.BSystem.SDK.dll`中实现的。

在这个WEB目录同级看到以BSystem命名的目录，那就是这个WEB又会去本地的`15801`端口进行进一步的登陆处理（套娃？）。

进入此目录再次查看`ClientService.svc`文件，bin目录又没有这个`ClientService.svc.cs`文件了，所以就直接打开Service参数指定的`XXX.BSystem.WEB.dll`文件，查看`UserLogin()`方法，发现明显处理逻辑有点不一样
![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103213638.png)

又进入了`AnonymousUsers.UserLogin()`，处理，虽然和上面第一层的名字一样，但这次是进入到`XXX.BSystem.Business.dll`中的`AnonymousUsers`类，继续跟过去看

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103210449.png)

我们关注的字符串`password`又进入了`globalParameters.UserLogin()`，再往上两行`globalParameters`是由`IGlobalCache`这个接口声明的，后面的`AccessFactory.GetGlobalParameters()`我也没找到在哪。

日了个DJ了，给爷整麻了，找不动了。

直接去`IGlobalCache`看发现确实有UserLogin方法，再去`XXX.BSystem.Cache.dll`中的`GlobalCache`类，发现确实是这个接口的实现，那就对了

<img src="https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103211611.png" alt="image-20211103211610653" style="zoom: 67%;" />

继续查看，发现终于找到了加密处理的地方

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103211833.png)

`Utility.GetMD5`在`XXX.common.dll`中实现，最终发现其会在md5处理前的数据加上一段估计字符

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103211956.png)

最后就可以指定这个盐让hashcat去跑密码了。

-----

### 程序二

大体也非常简单，也是有解密数据库密码的需求，随便翻目录翻到文件`AddUser.aspx`

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103212404.png)

直接打开看旁边的.cs源文件，这个一目了然，直接看`SecurityMgr`中的`CreateUser`方法就行

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211031215343.png)

找到对应的`BizEngine.Security.dll`，反编译

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103212644.png)

密码进入到`Encryption.Encrypt()`，然后找到对应的DLL跟过去就看到了

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211103212906.png)

进行了DES，我们只需要把这个方法原模原样拿出来就行。

编写解密程序：

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20211031221144.png)

成功解开密码

-----

  两个案例是这两天项目中遇到的，比较简单