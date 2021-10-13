---
title: 权限维持之「计划任务」
tags: 免杀
---
今天分享一个权限维持程序的实现思路，使用c++调用COM组件`ITaskService`，来实现一个免杀权限维持功能。

### 实现原理

程序功能分为三部分，首先是初始化，其次是添加计划任务，最后添加了删除计划任务功能。

以下只展示思路与代码demo

#### 1.Initialization

为了获取到获取 ITaskService 对象以及 ITaskFolder 对象

首先初始化COM接口

```c++
	//  初始化 COM
	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

  //  设置 COM security levels.
  hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);

  //  创建Task Service对象
  hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
  //  连接到Task Service
  hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

  hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
```

#### 2.CreateTask

首先创建任务定义对象，进行任务创建操作

```c++
 	hr = pService->NewTask(0, &pTask);
```

接着设置注册信息

```c++
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	//作者
	hr = pRegInfo->put_Author(_bstr_t(wszAuthor));
	//描述
	hr = pRegInfo->put_Description(_bstr_t(wszDescription));
```

设置主体信息

```c++
	hr = pTask->get_Principal(&pPrincipal);
  //  设置登陆类型
	hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);

  // 设置运行权限
	hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
```

设置任务相关信息

```c++
	hr = pTask->get_Settings(&pSettings);

	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	hr = pSettings->get_IdleSettings(&pIdleSettings);
```

创建触发器

```c++
	hr = pTask->get_Triggers(&pTriggerCollection);
	hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
```

设置执行操作

```c++
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	//设置程序路径等信息
	hr = pExecAction->put_Path(_bstr_t(wszProgramPath));
	......
```

在ITaskFolder对象注册

```c++
    hr = pRootFolder->RegisterTaskDefinition(_bstr_t(wszTaskName), pTask, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &pRegisteredTask);
```

#### 3.DeleteTask

直接根据事先写好的名字删除即可

```c++
	hr = pRootFolder->DeleteTask(_bstr_t(TaskName), 0);
```

#### 效果

只测试了几个常见国内以及Defender，更多的没有测试

上述成品已分享至知识星球
