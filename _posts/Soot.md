# Soot

## what is Soot

1. 免费的Java编译框架
2. 设计目的：分析和转换Java bytecode
3. 用于指向分析研究

## Overview

![overview](/img/soot/overview.PNG)

## Soot IRs

Soot包括四种IR（中间码-表示形式），分别代表了四种对Java Sourcode或者bytecode的不同程度的抽象。

1. **Baf - 基于栈的bytecode**

   传统的JVM bytebode是基于栈操作的指令集（Dalvik 基于寄存器操作），与之对应的Baf同样如此。那Baf抽象了什么呢？两个，忽略了constant pool(常量池)和bytecode指令中的type依赖。在bytecode中对不同保留类型，如int和float，的同一操作（如add），有不同的指令。这是因为在计算机中整形和浮点型的表达方式是不一样的，在底层实现时无法让两个操作符分属于这两种不同类型，也就是需要不同的指令对应不同的数据类型的操作。我们做分析时不用在意它到底调用的什么类型的指令，不对int还是float做细致区分，只要知道它是个数且知道是对这数的什么样的操作就行了。Baf因此用于在bytecode层面上的分析。

2. **Jimple - typed, 3-addresses, statement based。**

   Jimple是Soot的核心，是四种IR中最重要的。Soot能直接创建Jimple码，也可由Java sourcecode或者bytecode转化翻译而来。bytecode会被翻译成untyped Jimple，再通过type inference 方法对局部变量加上类型。翻译的重要一步是对表达式作线性化使得每个statement只能最多refernce 3个局部变量或者常量（没懂。。）。相对于bytecode的200多种指令，Jimple只有15条，分别对应着核心指令的 NopStmt, IdentityStmt, AssignStmt；函数内控制流指令的IfStmt, GotoStt, TableSwitchStmt和LookUpSwitchStmt，函数间控制流的InvoeStmt, ReturnStmt, ReturnVoidStmt, 监视器指令EnterMonitorStmt和ExitMonitorStmt，最后处理异常ThrowStmt和退出的RetStmt。

3. **Shimple -- Static Single Assignment 版的Jimple**

   和Jimple基本一样，只有两点不同: SSA 和phi-node。SSA保证了每个局部变量都有一个静态定义。

   目前还没有看到用SSA的可能，先暂时略过。

4. **Grimp -- 更适合人读的**

   和Jimple类似，多了允许树形表达和new指令。相比于Jimple，更贴近Java code，所以更适合人来读。