---
title: 自定义跳转函数的unhook方法
tags: 免杀
---
### 0x00 前言

​	本文介绍一种比较有意思的unhook手法，来源于小伙伴发的一个GitHub的POC：https://github.com/trickster0/LdrLoadDll-Unhooking，本文讲参照此POC来一步步解读这个方法。

​	目前大家常用的经典手法大都是直接系统调用(Syscall)或是找到ntdll的地址并重新映射磁盘中的.text段，去获得一个干净的dll去寻找函数地址的方式。

​	下面介绍这种方式相当于我们自己去组装一个“跳转函数”，巧妙地规避了一些Hook，具有一定的参考以及学习价值。

### 0x01 流程分析

1. 首先，构造Nt函数参数的结构体

```c++
	UNICODE_STRING ldrldll;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	wchar_t ldrstring[] = L"Wininet.dll";
	RtlInitUnicodeString(&ldrldll, ldrstring);
	InitializeObjectAttributes(&objectAttributes, &ldrldll, OBJ_CASE_INSENSITIVE, NULL, NULL);
```

2. 接着定义和初始化要修补的指令的头部、地址、尾部

```c++
	unsigned char jumpPrelude[] = { 0x49, 0xBB }; 
	unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
	unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3, 0xC3 }; 
```

3. 新建一块内存页，属性为可读可写（`opsec`），这块内存页是为了保存最终要使用的`LdrLoadDll`的地址。

```c++
LPVOID trampoline = VirtualAlloc(NULL,19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
```

4.  获取ntdll内导出函数`LdrLoadDll`，原始的地址

```c++
LPVOID origLdrLoadDll = GetProcAddress(GetModuleHandleA("ntdll.dll"),"LdrLoadDll");
```

> ​	许多EDR去Hook API的方式就是去修改Windows DLL中的函数，通过在函数开头插入`JMP指令`来跳转到自己的检测函数；如果API被Hook了的话，一般前5个字节会变为`JMP xxxxh`，跳转到检测函数的地址，下方图片说明了这个流程。
>
> ![image-20220117134946650](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201171349713.png)

​	上述获取到的原始函数地址，放在内存窗口查看

![image-20220117132815195](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201171328267.png)

​	为了更方便查看，使用Windbg反汇编LdrLoadDll查看其结构，记录前五个字节，也就是`\x48\x89\x5c\x24\x10`，

![image-20220117005918587](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201170059450.png)

​	5.将原始的前5个字节，放入我们开始申请的地址中。

```c++
CCopyMemory(trampoline,(PVOID)"\x48\x89\x5c\x24\x10", 5);
```

​	这一步比较巧妙，即使是EDR修改了前5个字节为跳转指令，我们也不用在意，因为我们不会去使用原始的前5个字节，而是自己放进去。

6. 获取原始地址前5个字节后的`地址`，放入第2步申请的`jumpAddress`中

```c++
	LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x5);
	*(void**)(jumpAddress) = jmpAddr; //jmpaddr的地址
```

![image-20220117133552397](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201171335386.png)

​	查看`jumpAddress`的内存，发现也就是地址`7ff8d8ae6a15`

![image-20220117133636639](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201171336634.png)

7. 接着是3个拷贝操作

```C++
	CCopyMemory((PBYTE)trampoline+5, jumpPrelude, 2);
	CCopyMemory((PBYTE)trampoline + 5 + 2, jumpAddress, sizeof(jumpAddress)); 
	CCopyMemory((PBYTE)trampoline + 5 + 2 + 8, jumpEpilogue, 4);
```

​	首先将`jumpPrelude`拷贝到前5个字节后，然后拷贝原始函数5个字节后的`地址`，最后拷贝`jumpEpilogue`指令尾部

​	在第5步的时候`trampoline`事先写入了前5个字节，内存看起来是这样的

![image-20220117134129791](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201171341340.png)

​	经过3次内容的拷贝，最终指令为：

![image-20220117134431236](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201171344334.png)

8. 修改这个最终要使用的“自定义跳转函数”的内存空间为可执行

```c++
VirtualProtect(trampoline,30,PAGE_EXECUTE_READ,&oldProtect);
```

9. 最后，将地址赋给事先定义的函数结构，并且调用

```c++
	LdrLoadrDll = (pNewLdrLoadDll)trampoline;
	HANDLE wininetmodule = NULL;
	LdrLoadrDll(NULL, 0 , &ldrldll, &wininetmodule);
```

​	开启VS的汇编窗口，到了函数调用时，步入进去即可更清晰的看到最终`trampoline`中所做的操作，右边蓝框

![image-20220117005309923](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201170053036.png)

### 0x02 总结

​	这样就构建了一个完整的自定义的跳转函数，这个函数实际上的功能还是跳转回原始的`LdrLoadDll`的前5个字节后的地址去执行，相当于避免了修改前5个字节`JMP`到检测函数的这种Hook方法。

​	我们自定义的跳转函数不受其影响，并且调用也是从NTDLL发出的，以一张图来说明流程：

![image-20220117143938358](https://images-1258433570.cos.ap-beijing.myqcloud.com/images202201171439302.png)