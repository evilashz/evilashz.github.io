---
title: Windows API Hooking Learn Note
tags: 免杀
---


实验去Hook以及Unhook`MessageBoxA`，来了解WindowsAPI的Hooking技术，当然也可以尝试实验任意函数

**API hooking** 是一种让我们监测和修改API调用的技术,Windows API hooking也是AV/EDR用来确定代码是否恶意的技术之一。

**本文参照链接：**https://resources.infosecinstitute.com/topic/api-hooking/**的实验去理解**



#### **实验：**

编写一个C++程序，整体的工作方式如下：

1. Get memory address of the `MessageBoxA` function

2. Read the first 6 bytes of the `MessageBoxA` - (will need these bytes for unhooking the function)

3. Create a `HookedMessageBox` function (that will be executed when the original `MessageBoxA` is called)

4. Get memory address of the `HookedMessageBox`

5. Patch / redirect `MessageBoxA` to `HookedMessageBox`

6. Call `MessageBoxA`Code gets redirected to `HookedMessageBox`
7. `HookedMessageBox` executes its code, prints the supplied arguments, unhooks the`MessageBoxA` and transfers the code control to the actual `MessageBoxA`

#### 调试学习：

代码放入VS设为x86（代码下面提供），下好断点

![屏幕快照 2020-12-09 16.53.08](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201209165431.png)

首先弹一个正常消息框，然后往下走，

`messageBoxAddress = GetProcAddress(library, "MessageBoxA");`获取`MessageBoxA`的地址 ，可以在反汇编窗口看到。(`7518EEA0处`)

![屏幕快照 2020-12-09 17.00.29](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201209170042.png)



前六个字节为`8b ff 55 8b ec 83`，然后下一句

```c++
	ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, messageBoxOriginalBytes, 6, &bytesRead);
```

把它存到`messageBoxOriginalBytes`，相当于保存原来的正常`MessageBoxA`的内存地址，为了我们待会实验unhook用。



创建一个patch，相当于去hook`MessageBoxA`

```c++
	// create a patch "push <address of new MessageBoxA); ret"
	void* hookedMessageBoxAddress = &HookedMessageBox;
	char patch[6] = { 0 };
	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);
	memcpy_s(patch + 5, 1, "\xC3", 1);
	
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, patch, sizeof(patch), &bytesWritten);

```

还记得我们的`messageBoxAddress`变量是存的原`MessageBoxA`函数的地址

经过如上代码，调用`WriteProcessMemory`，将前六位换为了`68 00 10 D6 00 C3`再写入`messageBoxAddress`



这里代码很清晰，前一位后一位对应两个指令，中间的`void* hookedMessageBoxAddress = &HookedMessageBox;`为`HookedMessageBox`的地址

![屏幕快照 2020-12-09 17.53.31](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201209190553.png)

查看地址，可以看到，指令相当于：

```c++
// push HookedMessageBox memory address onto the stack
push HookedMessageBox
// jump to HookedMessageBox
ret
```

我们这里为` push 0D6100h`，可以验证一下：

![屏幕快照 2020-12-09 19.08.47](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201209190859.png)

是`HookedMessageBox`function



然后最后的一个`MessageBoxA(NULL, "hi", "hi", MB_OK);`是我们hooking完之后执行的，那么执行后会进入`HookedMessageBox`，因为已经修改了内存中前六字节的值。通过`WriteProcessMemory`

![屏幕快照 2020-12-09 19.21.08](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201209192114.png)

可以看到首先是定义好的去输出`MessageBoxA`的参数，然后下一步就是Unhook了，把我们之前最开始存到`messageBoxOriginalBytes`的原地址换回到`messageBoxAddress`，如下图 查看地址时已经变为原地址`8b ff 55 8b ec 83`，成功`unhook`

![屏幕快照 2020-12-09 19.22.45](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201209192349.png)

最后调用`MessageBoxA`

![屏幕快照 2020-12-09 19.25.09](https://gitee.com/evilashz/MyIMGs/raw/master/img/20201209192546.png)

#### Code

```c++
#include "pch.h"
#include <iostream>
#include <Windows.h>

FARPROC messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};

int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	
	// print intercepted values from the MessageBoxA function
	std::cout << "Ohai from the hooked function\n";
	std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;
	
	// unpatch MessageBoxA
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
	
	// call the original MessageBoxA
	return MessageBoxA(NULL, lpText, lpCaption, uType);
}

int main()
{
	// show messagebox before hooking
	MessageBoxA(NULL, "hi", "hi", MB_OK);

	HINSTANCE library = LoadLibraryA("user32.dll");
	SIZE_T bytesRead = 0;
	
	// get address of the MessageBox function in memory
	messageBoxAddress = GetProcAddress(library, "MessageBoxA");

	// save the first 6 bytes of the original MessageBoxA function - will need for unhooking
	ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, messageBoxOriginalBytes, 6, &bytesRead);
	
	// create a patch "push <address of new MessageBoxA); ret"
	void *hookedMessageBoxAddress = &HookedMessageBox;
	char patch[6] = { 0 };
	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);
	memcpy_s(patch + 5, 1, "\xC3", 1);

	// patch the MessageBoxA
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, patch, sizeof(patch), &bytesWritten);

	// show messagebox after hooking
	MessageBoxA(NULL, "hi", "hi", MB_OK);

	return 0;
}
```

#### 总结

整个过程去Hook，`MessageBoxA`这个API，了解了怎么样去Hook Windows API的流程，以及原理。简单来说也可以理解为一种劫持。我们首先要做的是：获取要劫持函数的地址，然后我们在自己组装一个数据结构，数据结构的内容是 执行汇编：把新函数地址拷到寄存器里，然后再jmp到新函数地址位置执行新函数，然后我们把自己组装这个数据结构拷贝到之前获取的需要劫持的函数地址指向的内存的位置，这样当我们再次调用该函数的时候，程序走到函数地址处发现是执行我们刚刚写好的汇编命令，直接jmp到了我们自己定义的函数地址的位置，也就相当于直接运行了我们自己写好的函数地址

，许多AV/EDR也是这样去Hook敏感的API的，这样的话，我们可以用windbg去调试AV程序是怎么注入到我们的程序中检测我们的API调用的，然后找到API的原地址去修改。



二进制小白，哪里写的有问题还请斧正！