# Linux 学习

## 1. 寻找Syscall 

### 定义syscall的宏

1. **unisted.h**

   ./include/uapi/asm-generic/unistd.h

   unistd.h 是 [C](https://zh.wikipedia.org/wiki/C语言) 和 [C++](https://zh.wikipedia.org/wiki/C%2B%2B) 程序设计语言中提供对 [POSIX](https://zh.wikipedia.org/wiki/POSIX) 操作系统 [API](https://zh.wikipedia.org/wiki/API) 的访问功能的[标头档](https://zh.wikipedia.org/wiki/標頭檔)的名称。是**Uni**x **St**an**d**ard的缩写。该头文件由 POSIX.1 标准（[单一UNIX规范](https://zh.wikipedia.org/wiki/单一UNIX规范)的基础）提出，故所有遵循该标准的操作系统和[编译器](https://zh.wikipedia.org/wiki/编译器)均应提供该头文件（如 Unix 的所有官方版本，包括 [Mac OS X](https://zh.wikipedia.org/wiki/Mac_OS_X)、[Linux](https://zh.wikipedia.org/wiki/Linux) 等）。

   对于[类 Unix 系统](https://zh.wikipedia.org/wiki/类Unix系统)，`unistd.h` 中所定义的接口通常都是大量针对[系统调用](https://zh.wikipedia.org/wiki/系统调用)的封装（英语：wrapper functions），如 `fork`、`pipe` 以及各种 [I/O](https://zh.wikipedia.org/wiki/I/O) 原语（`read`、`write`、`close` 等等）。

2. **kill的调用号**

   ./include/uapi/asm-generic/unistd.h 

   ```c++
   /* kernel/signal.c */
   #define __NR_restart_syscall 128
   __SYSCALL(__NR_restart_syscall, sys_restart_syscall)
   #define __NR_kill 129
   __SYSCALL(__NR_kill, sys_kill)
   #define __NR_tkill 130
   __SYSCALL(__NR_tkill, sys_tkill)
   #define __NR_tgkill 131
   __SYSCALL(__NR_tgkill, sys_tgkill)
   ```

   可以看见 #define __NR_kill 129调用号wei129。并且方法可在 kernel/signal.c中找到。

3. **kill 方法**

   ./kernel/signal.c

   ```c++
   /**
    *  sys_kill - send a signal to a process
    *  @pid: the PID of the process
    *  @sig: signal to be sent
    */
   SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
   {
           struct kernel_siginfo info;
   
           prepare_kill_siginfo(sig, &info);
   
           return kill_something_info(sig, &info, pid);
   }
   ```

   SYSCALL_DEFINE2(kill, pid_t, pid, int, sign)：名字为kill的系统调用接收了pid,sign两个参数。

   SYSCALL_DEFINEx的定义：

   

   ./include/linux/syscalls.h

   *SYSCALL_DEFINE:*

   ```C++
   #ifndef SYSCALL_DEFINE0
   #define SYSCALL_DEFINE0(sname)                                  \
           SYSCALL_METADATA(_##sname, 0);                          \
           asmlinkage long sys_##sname(void);                      \
           ALLOW_ERROR_INJECTION(sys_##sname, ERRNO);              \
           asmlinkage long sys_##sname(void)
   #endif /* SYSCALL_DEFINE0 */
   
   #define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
   #define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
   #define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
   #define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
   #define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
   #define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)
   
   #define SYSCALL_DEFINE_MAXARGS  6
   
   #define SYSCALL_DEFINEx(x, sname, ...)                          \
           SYSCALL_METADATA(sname, x, __VA_ARGS__)                 \
           __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
   ```

   

   *__SYSCALL_DEFINEx:*

   ```c++
   /*
    * The asmlinkage stub is aliased to a function named __se_sys_*() which
    * sign-extends 32-bit ints to longs whenever needed. The actual work is
    * done within __do_sys_*().
    */
   #ifndef __SYSCALL_DEFINEx
   #define __SYSCALL_DEFINEx(x, name, ...)                                 \
           __diag_push();                                                  \
           __diag_ignore(GCC, 8, "-Wattribute-alias",                      \
                         "Type aliasing is used to sanitize syscall arguments");\
           asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))       \
                   __attribute__((alias(__stringify(__se_sys##name))));    \
           ALLOW_ERROR_INJECTION(sys##name, ERRNO);                        \
           static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
           asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__)); \
           asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))  \
           {                                                               \
                   long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
                   __MAP(x,__SC_TEST,__VA_ARGS__);                         \
                   __PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));       \
                   return ret;                                             \
           }                                                               \
           __diag_pop();                                                   \
           static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
   #endif /* __SYSCALL_DEFINEx */
   ```

   ```c++
   asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__)) 
   //##’为连接符：
   __SYSCALL_DEFINEx(x, abc, ...)
   asmlinkage long sys##abc(__MAP(x,__SC_DECL,__VA_ARGS__))   
   ```

   

   __MAP:

   ```c++
   /*
    * __MAP - apply a macro to syscall arguments
    * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
    *    m(t1, a1), m(t2, a2), ..., m(tn, an)
    * The first argument must be equal to the amount of type/name
    * pairs given.  Note that this list of pairs (i.e. the arguments
    * of __MAP starting at the third one) is in the same format as
    * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
    */
   #define __MAP0(m,...)
   #define __MAP1(m,t,a,...) m(t,a)
   #define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
   #define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
   #define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
   #define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
   #define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
   #define __MAP(n,...) __MAP##n(__VA_ARGS__)
   ```

   __SC_DECL:

   ```c
   #define __SC_DECL(t, a) t a
   #define __TYPE_AS(t, v) __same_type((__force t)0, v)
   #define __TYPE_IS_L(t)  (__TYPE_AS(t, 0L))
   #define __TYPE_IS_UL(t) (__TYPE_AS(t, 0UL))
   #define __TYPE_IS_LL(t) (__TYPE_AS(t, 0LL) || __TYPE_AS(t, 0ULL))
   #define __SC_LONG(t, a) __typeof(__builtin_choose_expr(__TYPE_IS_LL(t), 0LL, 0L)) a
   #define __SC_CAST(t, a) (__force t) a
   #define __SC_ARGS(t, a) a
   #define __SC_TEST(t, a) (void)BUILD_BUG_ON_ZERO(!__TYPE_IS_LL(t) && sizeof(t) > sizeof(long))
   ```

   

   可以反推**SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)**的实际调用：

   ```c++
   SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
   //===>
   SYSCALL_DEFINEx(2, _kill, pid_t, pid, int, sig)
   //===>
   __SYSCALL_DEFINEx(2, _kill, pid_t, pid, int, sig)
   //===>
   asmlinkage long sys_kill(__MAP(2,__SC_DECL,pid_t, pid, int, sig))
   //===>
   asmlinkage long sys_kill(__MAP2(__SC_DECL,pid_t, pid, int, sig))
   //===>
   asmlinkage long sys_kill(__SC_DECL(pid_t, pid), __MAP1(int, sig))
   //===>
   asmlinkage long sys_kill(pid_t pid, __MAP1(int, sig))  
   //===>
   asmlinkage long sys_kill(pid_t pid, __SC_DECL(int, sig))  
   //===>
   asmlinkage long sys_kill(pid_t pid,int sig)
   ```

## 2. 内核学习

### 开启电源按键后，会发生什么

主板在开启电源按键后，开始尝试启动CPU，CPU复位寄存器的素有数据，并设置每个寄存器的预定值。[80386](https://en.wikipedia.org/wiki/Intel_80386) 以及后来的 CPUs 在电脑复位后，在 CPU 寄存器中定义了如下预定义数据：

```
IP          0xfff0 #指令指针寄存器 
CS selector 0xf000
CS base     0xffff0000
```

CS:IP 两个寄存器指示了 CPU 当前将要读取的指令的地址，其中  CS  为代码段寄存器，而   IP  为指令指针寄存器 。

X86和ARM都有程序寄存器，X86的程序寄存器其实就是指令指针寄存器ip，而ARM的程序寄存器是一个通用寄存器r15。MIPS没有程序寄存器。

程序寄存器pc就是用来指示程序执行的位置，具体来说，就是当前执行指令的下一条指令的地址，告诉CPU要到哪里去取下一条指令。

8086寄存器架构如下 ：

![8r](/img/linux/8086.PNG)

ARM寄存器架构如下：

![ar](/img/linux/arm.PNG)

举个例子：

8086是一个16位系统，寄存器是16位的，但是他的地址总线却有20位，那么两个16位寄存器怎么表示20位的地址？段地址*16+偏移地址，这就是段地址+偏移地址的真实含义，为什么要乘以16？这就是把段地址左移4位，加上原来的16位偏移地址，就可以得到一个20位的地址。

若CS:IP为0x1000:x0010, 则实际物理地址为：PhysicalAddress = Segment * 16 + Offset, 即 hex((0x1000 << 4) + 0x0010)=0x10010。

那么看来，开机的第一个逻辑地址为：

1. 0xffff0000: 0xfff0
2. 0xfffffff0

## 3. 引导程序

在现实世界中，要启动 Linux 系统，有多种引导程序可以选择。比如 [GRUB 2](https://www.gnu.org/software/grub/) 和 [syslinux](http://www.syslinux.org/wiki/index.php/The_Syslinux_Project)。