---
title: PE结构-导出表函数定位学习
tags: 免杀
---

​	QAX群内看到有师傅说到对于导出函数是序号的DLL，要怎么去做DLL劫持中转，或者说`DLL Proxy`，然后之前做DLL劫持也没考虑过这个问题，不过话说回来我觉得也碰不到这种情况，比较好奇，所以写个测试程序理解一遍。

​	尝试实现自动化生成DLL劫持模板，同时支持劫持DLL导出函数名称已经导出序号两类，主要做的其实就是从PE结构中的`IMAGE_EXPORT_DIRECTORY`结构找到这两种导出函数，平常找的方法可能都是通过`NumberOfNames`循环，然后使用`AddressOfNamesOrdinals`结构中的索引到`AddressOfFunctions`函数地址表中找到函数的RVA。

### C/C++导出DLL函数的常见方法

通常项目中导出DLL的函数有两种方式：

1. __declspec(dllexport) 导出

2. *.def 文件导出

#### 1.1 __declspec(dllexport) 导出

如下代码，这个非常常见

```c++
extern "C" __declspec(dllexport) int TestFuction()
{
    MessageBoxA(NULL, "TestFuction()", "alert", MB_OK);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
       
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

#### 1.2 def 文件导出

def文件导出相对简单，只需要在项目中添加`模块定义文件(*.def)`，比如我们写好一个小功能

```c++
void fun() {
    MessageBoxA(NULL, "Function FUN()！", "alert", MB_OK);
}
```

def文件导出只需这样即可

```c++
LIBRARY "DLL1"
EXPORTS
	fun @1
```

上述两种存在的问题是：

1. 可以用一些PE解析工具查看到DLL的导出函数名字，比如dumpbin、CFF_Explorer等。
2. 导出的函数名可以任意被访问和使用，外部接口是公开的可能会造成一些不必要的事情

所以DLL的导出接口保护也叫做序号导出，可以隐藏导出函数的名字，匿名导出接口只需要在 `def文件` 的导出接口名称增加 `NONAME` 关键字即可，如下：

```c++
LIBRARY "DLL1"
EXPORTS
	fun @1 NONAME
```

使用dumpbin查看如下：

![image-20210922165057021](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210923142128.png)

其实直接可以使用GetProcAddress()按照序号找到对应的地址，如下：

```c++

typedef void(*MYFUN)();

int main()
{
    HMODULE handle;
    handle = LoadLibrary(L"DLL1.dll");

    MYFUN fun = (MYFUN)GetProcAddress(handle, (char*)1);
    fun();

    FreeLibrary(handle);

	return 0;
}
```

也可以成功加载DLL1.dll中序号导出的功能。

我们常用的DLL Proxy会在DLL中再把原名字的DLL导出一遍，函数内会将正常功能代理过去原DLL，可以使用`#pragma`指令转发也可以自己写代码，通常都是自动化工具，这样才可以做到无感，同样按序号导出的修改第8行即可，比如：

```c++
void qt_plugin_instance()
{
    HINSTANCE hDllInst = LoadLibrary(L"qsvg1.dll");
    if (hDllInst)
    {   
        typedef DWORD(WINAPI* EXPFUNC)();
        EXPFUNC exportFunc = NULL;
        exportFunc = (EXPFUNC)GetProcAddress(hDllInst, "qt_plugin_instance");
        if (exportFunc)
        {
            exportFunc();
        }
        FreeLibrary(hDllInst);
    }
    return;
}
```

-----

但是，如果想将这个过程自动化，这样还是不太优雅，现实中我们需要维权时使用的DLL可能都是很多个导出函数，或者说其中也存在一部分按序号导出的函数，那么我们解析名称导出之后，还剩下序号分散的按序号导出的函数，所以说尝试直接解析PE结构中的`IMAGE_EXPORT_DIRECTORY`，来同时获取两种导出方式的函数。

关于什么是导出表，这个问题不多说，完全可以百度得到答案。

导出表的结构如下：

```c++
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;					// 文件创建时间戳
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;										// 函数的起始序号
    DWORD   NumberOfFunctions;			// 导出函数的总数
    DWORD   NumberOfNames;					// 以名称方式导出的函数的总数
    DWORD   AddressOfFunctions;     // 指向导出函数地址表的RVA
    DWORD   AddressOfNames;         // 指向导出函数名地址表的RVA
    DWORD   AddressOfNameOrdinals;  // 指向函数名序号表的RVA
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

主要有两种方式，如下流程（我直接摘抄的）

#### A. 从序号查找函数入口地址

1. 定位到PE 文件头
2. 从PE 文件头中的 IMAGE_OPTIONAL_HEADER32 结构中取出数据目录表，并从第一个数据目录中得到导出表的RVA
3. 从导出表的 Base 字段得到起始序号
4. 将需要查找的导出序号减去起始序号Base，得到函数在入口地址表中的索引，检测索引值是否大于导出表的 NumberOfFunctions 字段的值，如果大于后者的话，说明输入的序号是无效的
5. 用这个索引值在 AddressOfFunctions 字段指向的导出函数入口地址表中取出相应的项目，这就是函数入口地址的RVA 值，当函数被装入内存的时候，这个RVA 值加上模块实际装入的基地址，就得到了函数真正的入口地址

#### B. 从函数名称查找入口地址

1. 首先得到导出表的地址
2. 从导出表的 NumberOfNames 字段得到已命名函数的总数，并以这个数字作为循环的次数来构造一个循环，从 AddressOfNames 字段指向得到的函数名称地址表的第一项开始，在循环中将每一项定义的函数名与要查找的函数名相比较，如果没有任何一个函数名是符合的，表示文件中没有指定名称的函数。
3. 如果某一项定义的函数名与要查找的函数名符合，那么记下这个函数名在字符串地址表中的索引值，然后在AddressOfNamesOrdinals 指向的数组中以同样的索引值取出数组项的值，我们这里假设这个值是 x
4. 最后，以 x 的值作为索引值在 AddressOfFunctions 字段指向的函数入口地址表中获取 RVA 。此 RVA 就是函数的入口地址。



我们要劫持的话就是遍历，而不是查找，具体流程大致就是这样，不多说比如代码：

第一种通过函数名称来找到函数地址，代码如下

```c++
PVOID GetAddressFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName)
{
	PVOID get_address = 0;
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// 有名称的导出函数个数
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// 导出函数名称地址表
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	// 开始遍历导出表
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// 判断是否查找的函数
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// 获取导出函数地址
			USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			get_address = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			break;
		}
    return get_address;
	}
```

第二种通过序号遍历，我直接在第一段的代码基础上改进，使其支持两种遍历：

```c++
PVOID GetAddressFromExportTable(PVOID pBaseAddress)
{
	PVOID get_address = 0;
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// 有名称的导出函数个数
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	//导出函数总数
	ULONG ulNumberOfFunctions = pExportTable->NumberOfFunctions;
	//函数名序号表
	PWORD ulAddressOfNameOrdinals = (PWORD)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals);
	// 导出函数名称地址表
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	char* lpName = NULL;
	// 序号
	WORD wBase = pExportTable->Base;
	// 开始遍历导出表
	for (int i = 0; i < ulNumberOfFunctions; i++)
	{

		int j = 0;
		for (j = 0; j < ulNumberOfNames; j++)
		{
			lpName = (char*)pDosHeader + lpNameArray[j];
			if (ulAddressOfNameOrdinals[j] == i)
			{
				//USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
				ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * i);
				get_address = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
				printf("ordinary: %d ", wBase+i);
				printf("name: %s ", lpName);
				printf("RVA address:%8X ", get_address);
				printf("FOA address:%4X\n", ulFuncAddr);
			}
			else {
				ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * i);
				get_address = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
				printf("ordinary: %d ", wBase + i);
				printf("name: NULL ");
				printf("RVA address:%8X ", get_address);
				printf("FOA address:%4X\n", ulFuncAddr);
			}
		}
			
	}

	return get_address;
}
```

如上代码可以自动遍历DLL文件的导出表，无论是从名称导出还是从序号导出，实验在DLL中添加一个按名称导出函数，三个序号导出，运行结果如下：

![image-20210923142102477](https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210923142122.png)

然后的实现逻辑就是将这个FOA保存起来，copy到预先定义的模板DLL文件，dll文件中

```c++
#include <windows.h>

struct Dll1_dll { 
    HMODULE dll;
    FARPROC OrignalTestFuction1;
    FARPROC OrignalTestFuction2;
  ...
} Dll1;


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    char path[MAX_PATH];
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        Dll1.dll = LoadLibrary("\\Dll1.dll");
        Dll1.OrignalTestFuction1 = (FARPROC)((PUCHAR)pBaseAddress + {FOA1}); //fill in
				Dll1.OrignalTestFuction2 = (FARPROC)((PUCHAR)pBaseAddress + {FOA2}); //fill in
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        FreeLibrary(Dll1.dll);
    }
    break;
    }
    return TRUE;
}

void {NAME}() { _asm { jmp[Dll1.OrignalTestFuction1] } }
void {NAME2}() { _asm { jmp[Dll1.OrignalTestFuction2] } }
...
```

模板大致如上，多个函数控制结构体还有`DLL_PROCESS_ATTACH`中以及导出时def文件即可实现自动化，这个留到下篇文章。

欢迎加入知识星球，一起学习

<img src="https://images-1258433570.cos.ap-beijing.myqcloud.com/images/20210923143720.png" alt="海报" style="zoom:67%;" />

