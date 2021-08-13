---
title: 一次WEB渗透测试记录
tags: 渗透测试
---

​	文中所有图片已做脱敏处理，以下操作全部是本人梦中所见。



​	在一次针对WEB的渗透测试中，被测试目标存在双向认证，当然前提也有对应的客户端证书，常规操作就是将此客户端证书导入 User options 中 SSL选项 下 Client SSL Certificates 中，Burp就充当了被Server信任的角色，就可以重放数据包了。

​	但是实际测试当中，发现其数据包放到repeater模块中无法进行重放测试，如下图：

![image-20210812213817333](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210812213818.png)

​	进一步确定发现其中的参数token是控制访问有效性的，token解开URL以及base64后如下

<img src="/Users/ayaozpy/Library/Application Support/typora-user-images/image-20210812211608419.png" alt="image-20210812211608419" style="zoom:50%;" />

转换得到：

<img src="https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210812211844.png" alt="image-20210812211837617" style="zoom:50%;" />

​	发现其并没有用到别的算法生成，这是一个秒级时间戳进行编码得到的，但是发现Response中的返回服务器时间并不与刚刚我们获取的有效时间戳token相符，甚至并不是相差时区。

```
Date: Thu, 12 Aug 2021 07:47:06 GMT
```

​	进一步查看数据包，发现控制台中功能存在功能查看系统时间，抓包发现此时间正是其所用时间戳对应时间段

![image-20210812212427813](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210812212428.png)

​	经过手动测试确认发现转换过后的时间戳token可用，那么在被测试系统成百个功能点中，每一个功能点的每一个请求都要实现自己手动替换那将是非常痛苦的。

​	所以，在掌握了token的生成规则之后，接下来尝试将其自动化，首先的思路像上次解决通用前端加密时的思路一样，就是实现一个自己的代理，处理我们改包之后的请求，具体需求如下：

- 让被测试系统请求包通过Burp的代理之后接着进入自己的代理处理
- 请求上述时间接口获取时间，转换为时间戳格式
- 自动定位请求包中token参数并替换
- 将响应返回



 	当然也可以编写一个Burp插件来完成，但是由于本人没有相关开发经验，也没有找到现成的可以修改的插件，学习成本比较高，所以使用`mtimproxy`这一个工具就可以实现我们的部分需求，

​	`mtimproxy`，就是用于 MITM 的 proxy，MITM 即中间人攻击（Man-in-the-middle attack）。用于中间人攻击的代理首先会向正常的代理一样转发请求，保障服务端与客户端的通信，其次，会适时的查、记录其截获的数据，或篡改数据，引发服务端或客户端特定的行为。

​	`mitmproxy` 不仅可以截获请求帮助开发者查看、分析，更可以通过**自定义脚本**进行二次开发，还可以作为透明代理、反向代理、上游代理、SOCKS 代理等，但本文只讨论最常见的正向代理模式。

-----



​	我们只需使用pip就可以安装:

```
pip3 install mitmproxy
```

​	` mitmproxy `可以加载我们的自定义脚本，脚本编写规则定义了变量 addons，addons 是个数组，每个元素是一个类实例，这些类有若干方法，这些方法实现了某些事件，`mitmproxy` 会在某个事件发生时调用对应的方法。这些类称为 `addon`

​	其次，其中还有一个“事件”的概念，事件针对不同的生命周期分为5种，分别是：

1. 针对HTTP生命周期
2. 针对TCP生命周期
3. 针对Websocket生命周期
4. 针对网络连接生命周期
5. 通用生命周期



​	现在，我们想要做到的是，在请求经过Burp改包之后，进入mitmproxy之后，自动处理`HTTP_CONNECT`的事件，那我们就需要去使用“针对HTTP生命周期”这一事件，而事实上常用的也是这一事件，我们需要用到其中提供的request方法，以及response方法达到效果。

​	具体来说就是：

1. Burp处理后的请求包传递至mitmproxy，通过request方法阻断并且修改相应的token
2. 因为是双向认证，我们自己再另外编写一个脚本，再从mitmproxy提供的代理端口(不用考虑证书问题)走一遍，为的是请求时间戳
3. 然后再用其中的response方法去阻断我们去访问请求事件戳的响应，并取出次响应作出处理，把次时间戳转换为token写入文件
4. 最后，现在我们没有自动的请求去保证我们时刻有可用的token去生成，我们不可能每次改包后再去手动向时间戳的页面去申请时间戳，那么我们只需完成第二步提到的脚本，并指定每2s循环请求一个时间戳，这样就可以满足我们的需求。



​	接下来就是写一个循环脚本，每隔2s请求一次被测系统时间接口，并转换为需要的token格式，存入文件。

```python
#coding:UTF-8
import requests
import sys
import time

def sleep_time(hour, min, sec):
    return hour * 3600 + min * 60 + sec

#每隔2s请求一次生成token，写入文件
def GetServertime():
	proxies = {'https': 'http://127.0.0.1:6666'}
	url = "https://1.1.1.1/cgi-bin/read_time.cgi"
	res = requests.Session()
	second = sleep_time(0, 0, 2)

	while True:
		time.sleep(second)
		rep = res.get(url, proxies=proxies,verify='/xxxx/client.pem')
		print("[+]Get Token : " + rep.text)

GetServertime()
```

​	最后，我们开启mitmweb并指定我们编写的拦截脚本:

```python
import mitmproxy.http
from mitmproxy import ctx
from mitmproxy import flowfilter

import requests
import time
import base64
from urllib import parse

ParseUrl = "https://1.1.1.1"

class Interceptor:
    def __init__(self):
        # 添加网址过滤器
        self.filter = flowfilter.parse("~u "+ ParseUrl)

    def request(self, flow: mitmproxy.http.HTTPFlow):


        if flowfilter.match(self.filter, flow):  
            #ctx.log.info("[+]match request")
            # 替换
            fp = open('tmp.txt')
            token = fp.readline()

            #GET
            if '&token=' in flow.request.url:
                flow.request.query["token"] = token
            
            #POST
            flow.request.urlencoded_form["token"] = token
            ctx.log.info("[+]本次请求token: " + token + "\n")
            if 'login.html' in flow.request.url:
                pass

    def response(self, flow: mitmproxy.http.HTTPFlow):
        #定义生成token页面
        if '1b6e-a28c00000000-605ce54d00000000' in flow.response.headers['ETag']:
            #ctx.log.info("[+]获取token:" + flow.response.text)
            token = flow.response.text
            #这里再转换为响应的格式即可
            fp = open('tmp.txt', 'w')
            fp.write(token)
            fp.close()
            print("[+]写入文件Token: " + token)

        #if flowfilter.match(self.filter, flow):  
        #    test = 1
            # 添加/修改headers

addons = [
    Interceptor()

```

​	这样的话，效果如下：

​	![image-20210813095132535](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210813095133.png)

​	每一次截取request的时候，都会从文件中获取有效的token进行请求，这样即可实现自动替换token的需求，接下来就可以愉快的进行后续测试。



​	最后，测试此方法在数据包中存在`;`的时候，会自动将这个分号转换成`&`，不清楚为何，但着实是让我在测试命令注入的时候坑了好久才发现，真是自作孽啊...