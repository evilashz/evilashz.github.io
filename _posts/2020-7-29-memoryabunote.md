---
title: 内存A.B.U.笔记
tags: 免杀
---

#### #pragma编译指令

\#pragma指令是每个编译器在保留C和C++语言的整体兼容性时，提供不同机器和操作系统特定的功能。编译指令是机器或操作系统特有的，并且不同的编译器通常存在差异。

官方文档：https://docs.microsoft.com/en-us/cpp/preprocessor/pragma-directives-and-the-pragma-keyword?redirectedfrom=MSDN&view=vs-2019

语法如下：

`\#pragma token_string // token_string为参数`



“#”必须是编译指令的第一个非空白字符；而“#”和“pragma”之间可以存在任意个数的空白符。在#pragma后面，写任何编译器能够作为预处理符号分析的文本。#pragma的参数类似于宏扩展。如果参数无法识别，编译器会抛出一个警告后继续编译。示例代码如下：

```c++
#pragma once    // 正确
  #pragma once  // 正确
# pragma once   // 正确
;#pragma once   // 错误 
ps: error C2014: preprocessor command must start as first nonwhite space
```



C和C++编译器可以识别下列编译指令。

| row1              | row2                | row3        | row4            |
| ----------------- | ------------------- | ----------- | --------------- |
| alloc_text        | auto_inline         | bss_seg     | check_stack     |
| **code_seg**      | comment             | component   | conform         |
| const_seg         | **data_seg**        | deprecated  | detect_mismatch |
| fenv_access       | float_control       | fp_contract | function        |
| hdrstop           | include_alias       | init_seg    | inline_depth    |
| inline_recursion  | intrinsic           | loop        | make_public     |
| managed message   | omp                 | once        | optimize        |
| pack              | pointers_to_members | pop_macro   | push_macro      |
| region, endregion | runtime_checks      | **section** | setlocale       |
| strict_gs_check   | unmanaged           | vtordisp    | warning         |



