---
title: FrpMoModify--免配置文件版frp
tags: Tools
---

*渗透中常用的配置全部写入代码，可变的配置(如IP PORT) 改为指定参数*

*并且流量TLS加密无特征*

![111](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210107155546.png)

![1112](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210107155544.png)

​	思路是按照，之前的Uknow老哥的思路进行修改的，他改的写的工具都非常好，在这夸一波先

​	之前uknow老哥那个版本的，转发出来的端口没有加参数，一直是23333，我这个相当于也就是他那个版本的把这个给加入参数弄出来了，

​	前几天看到了老哥frp结合域前置，个人觉得没必要也就没有加



特征跟uknow老哥那个文章，去了一部分，所以他的叫FrpModify，我的叫FrpMoModify(**抄就完事了**)，然后把一些该写死的写进去了，然后也没啥了，没加认证



**Server:**

```
Frps -p 7777

> -p 为bind_port
```



**Client:**

```
Frpc -t 1.1.1.1 -p 7777 -f 9999
> -t 为Server的IP
> -p 为Server listen的port
> -f 为Server开启socks的端口
```



**文件压缩完大小为2.8m左右**



**用着挺好的 很方便 适合喜欢使用FRP的哥哥们**



链接：https://share.weiyun.com/LA68pYqM 密码：4xfqx2