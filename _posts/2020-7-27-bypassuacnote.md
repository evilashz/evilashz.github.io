---
title: BypassUAC笔记
tags: BypassUAC 
---

**what is `cmlua.dll`?**

The **cmlua.dll** is a **Connection Manager Admin API Helper**. 

This file is part of Microsoft(R) Connection Manager. Cmlua.dll is developed by Microsoft Corporation. It’s a system and hidden file. **Cmlua.dll** is usually located in the %SYSTEM% folder and its usual size is 34,304 bytes.



**tools:** IDA OleView



### COM组件接口BypassUAC



#### ICMLuaUtil BypassUAC note:

原理：COM提升名称（COM Elevation Moniker）技术允许运行在用户账户控制下的应用程序用提升权限的方法来激活COM类，以提升COM接口权限。同时，ICMLuaUtil接口提供了ShellExec方法来执行命令，创建指定进程。因此，我们可以利用COM提升名称来对ICMLuaUtil接口提权，之后通过接口调用ShellExec方法来创建指定进程，实现BypassUAC。