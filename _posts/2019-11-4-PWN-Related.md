# PWN Related 

## PLT and GOT

### 1. 定义

PLT(Procedure Linkage Table, 过程链接表)：是 Linux ELF文件中用于延迟绑定的表，即函数第一次被调用的时候才进行绑定。

GOT(Global Offset Table, 全局偏移表)：是Linux ELF文件中用于定位全局变量和函数的一个表。

### 2. PLT 简介

为了更好的用户体验和内存CPUCPU的利用率，程序编译时会采用两种表进行辅助，一个为PLTPLT表，一个为GOTGOT表，PLTPLT表可以称为内部函数表，GOTGOT表为全局函数表（也可以说是动态函数表这是个人自称），这两个表是相对应的，什么叫做相对应呢，PLTPLT表中的数据就是GOTGOT表中的一个地址，可以理解为一定是一一对应的，如下图：

![plt](/img/PWN/plt.jpg)

当然这个原理图并不是Linux下的PLT/GOT真实过程，Linux下的PLT/GOT还有更多细节要考虑了。这个图只是将这些躁声全部消除，让大家明确看到PLT/GOT是如何穿针引线的。

PLT 位于.plt section中。

![puts](/img/PWN/puts_plt.PNG)

### 3. GOT简介

表中每一项都是本运行模块要引用的一个全局变量或函数的地址。可以用GOT表来间接引用全局变量、函数，也可以把GOT表的首地址作为一个基 准，用相对于该基准的偏移量来引用静态变量、静态函数。由于加载器不会把运行模块加载到固定地址，在不同进程的地址空间中，各运行模块的绝对地址、相对位 置都不同。**这种不同反映到GOT表上，就是每个进程的每个运行模块都有独立的GOT表，所以进程间不能共享GOT表。**

![puts got](/img/PWN/puts_got.PNG)

### 4. CCTF_PWN3 CTF 题目分析

#### 静态分析：

![decompile_main](/img/PWN/decompile_main.PNG)

可以看出用户输入会进入两个流程：ask_username以及ask_password。

![decompile_username](/img/PWN/decompile_username.PNG)

可以看出在此阶段，用户名做了一系列的变换。循环每个字节，每个字节+1。

![decompile_password](/img/PWN/decompile_password.PNG)

变换过的用户名会进入password方法中，和“sysbdmin”进行对比。由此我们可以反向推测用户名。

```python
def getUserName():
    secret = "sysbdmin"
    username = ''
    for i in secret:
        username=username + chr(ord(i)-1)
    print username
    return username 
```

在file_get 函数中有一处格式化字符串漏洞。

![decompile_getfile](/img/PWN/decompile_fileget.PNG)

