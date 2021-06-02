---
title: 通过 WebVPN 扫描内网
tags: 渗透
---

​	经过@尼克的信息搜集，获取到一位人员的工号并且成功重置其密码，登陆其统一认证系统，以及VPN，发现此VPN不是彼VPN，访问资源都是以他代理去访问的，而不是直接拨入内网。

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602182411.png)

访问任何资源都如此形式：

`https://webvpn.xxxxx.cn/http-8009/77726476706e697776646265737421a1ae13d27666301e2f5bdce2ca`

​	很明显URL路径中有HTTP协议，以及要访问资源的端口，而URL则被进行编码加密操作，此时想要批量探测内网变得有些困难，并且也通过href看到了几个内网IP段。

所以需要分析一下他做的加密操作：

查看JS发现点击“立即跳转”会调用go()

![image-20210602183237059](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602183238.png)

接着可以发现encrypUrl()函数为处理url函数，所以下断点查看调用方法

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602182650.png)

进入encrypUrl()函数发现又会调用encrypt函数，使用AES加密处理URL

![image-20210602182813999](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602182815.png)

至此已经确定是使用JS并且AES加密等编码来处理URL的，所以我们想使用这个“鸡肋”的VPN探测内网，并且批量可控的话，就要还原这个加密方式，可以考虑自己参照实现AES加密或者扒出来相关功能JS直接使用他的代码来进行处理自己的数据，事半功倍。



使用@c0ny1所写的`jsEncrypter`Burp插件，是用来爆破前端存在JS加密的登陆口使用的，原理一样，所以使用其中的`phantomjs_server.js`，使用phantomjs开启webserver并提供一个接口，并将自己的数据传入到要调用的代码中做处理。

```javascript
/**
 * author: c0ny1
 * date: 2017-12-16
 * last update: 2019-5-30 11:16
 */
 
var fs = require('fs');
var logfile = 'jsEncrypter.log';
var webserver = require('webserver');
server = webserver.create();

var host = '127.0.0.1';
var port = '1664';

// 加载实现加密算法的js脚本
var wasSuccessful = phantom.injectJs('xxxx.js');/*引入实现加密的js文件*/

// 处理函数
function js_encrypt(payload){
	var newpayload;
	/**********在这里编写调用加密函数进行加密的代码************/
	newpayload = encrypUrl("http",payload);
	/**********************************************************/
	return newpayload;
}

if(wasSuccessful){
	console.log("[*] load js successful");
	console.log("[!] ^_^");
	console.log("[*] jsEncrypterJS start!");
	console.log("[+] address: http://"+host+":"+port);
}else{
	console.log('[*] load js fail!');
}

var service = server.listen(1664, function(request, response){

 	try{
		if(request.method == 'POST'){
			var payload = request.post['payload'];
			var encrypt_payload = js_encrypt(payload); 
			var log = payload + ':' + encrypt_payload;
			console.log('[+] ' + log);
            fs.write(logfile,log + '\n', 'w+');
			response.statusCode = 200;
			response.write(encrypt_payload.toString());
			response.close();
		}else{
			  response.statusCode = 200;
			  response.write("^_^\n\rhello jsEncrypter!");
			  response.close();
		}
	}catch(e){
		//console.log('[Error]'+e.message+' happen '+e.line+'line');
		console.log('\n-----------------Error Info--------------------')
		var fullMessage = "Message: "+e.toString() + ':'+ e.line;
		for (var p in e) {
			fullMessage += "\n" + p.toUpperCase() + ": " + e[p];
		} 
		console.log(fullMessage);
		console.log('---------------------------------------------')
		console.log('[*] phantomJS exit!')
		phantom.exit();
    }	
});
```

我们使用这个脚本加载刚刚调试JS所用到的代码，把过程中所用到的`go()`、`encrypUrl()`等函数全部放进去，再用上面的JS代码去调用返回到WEB。

配置完成后，访问web传入数据：

![image-20210602185117501](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602185123.png)

<img src="https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602185230.png" alt="image-20210602185227840"  />

已经按照原网站的规则进行加密，之后我们就可以利用这个接口去探测内网了



最后使用python的requests库，编写一个扫描c段和常见端口的脚本进行内网探测：

![image-20210602180441569](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602185908.png)

可以成功探测内网，识别title：

![image-20210602180540583](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210602185911.png)

最后就解决了尴尬的问题，比较有意思。