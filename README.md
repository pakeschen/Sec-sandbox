# Sec-sandbox


# 基于Seccomp的程序监测沙盒

### 构建

​    由于需要引入seccomp头文件，因此构建时需要使用libseccomp作为静态库使用，在github找了一个满足使用要求的包，下载并构建

​    Makefile会在libseccomp目录中查找有效的libseccomp树和构建，因此满足依赖项的最简单方法是在项目目录中执行以下操作：

```bash
user@dev:~/sandbox$ curl -L -O -k https://github.com/seccomp/libseccomp/releases/download/v2.4.3/libseccomp-2.4.3.tar.gz
user@dev:~/sandbox$ tar xf libseccomp-2.4.3.tar.gz && mv libseccomp-2.4.3 libseccomp
user@dev:~/sandbox$ cd libseccomp && ./configure --enable-shared=no && make
```

然后使用make命令构建沙盒，并放到/usr/lib动态库的环境下：

```bash
user@dev:~/sandbox$ make
cc -c -fPIC -Ilibseccomp/include -o sandbox.o sandbox.c
cc -c -fPIC -Ilibseccomp/include -o preload.o preload.c
cc -shared -Wl,--version-script=libsandbox.version -o libsandbox.so sandbox.o preload.o libseccomp/src/.libs/libseccomp.a
cc -c -fPIC -Ilibseccomp/include -o sandboxing.o sandboxing.c
cc -o sandboxing.a sandboxing.o sandbox.o libseccomp/src/.libs/libseccomp.a
user@dev:~/sandbox$ cp -r libsandbox.so /usr/lib/x86_64-linux-gnu/
```

### 规则添加

​    本项目为动态链接的可执行文件提供了一个动态链接的库libsandbox.so和一个用于静态链接的可执行文件的命令行实用程序沙箱化。系统调用过滤器规则可以使用以下环境变量定义，分为白名单和黑名单模式：

* 【白名单模式】定义Whitelist_mode，列表中列出的所有系统调用都将被允许，调用列表外的系统调用的进程将会被系统杀死
  * example: `Whitelist_mode="fstat write exit_group"`
* 【黑名单模式】定义Blacklist_mode，列表中列出的所有系统调用都将被拒绝，调用列表内的系统调用的进程将会被系统杀死，只允许调用列表外的系统调用
  * example: `Blacklist_mode="execve mprotect"`

#### 动态链接可执行文件

​    对于动态链接的可执行文件，使用LD_PRELOAD动态链接器选项注入沙箱代码。

helloworld测试：

```C
#include<stdio.h>

int main()
{
        printf("hello,world!\n");
        return 0;
}
```

无沙箱化：

```bash
$ ./helloworld
Hello, world!
```

沙箱化：

```bash
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so Whitelist_mode="fstat write exit_group" ./helloworld
 Initializing Seccomp Rules......
【Success】Adding <fstat> to the Seccomp Filter [ALLOW]
【Success】Adding <write> to the Seccomp Filter [ALLOW]
【Success】Adding <exit_group> to the Seccomp Filter [ALLOW]
Hello, world!
```

如果进程使用未明确列出的系统调用：

```bash
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so Whitelist_mode="fstat exit_group" ./helloworld
 Initializing Seccomp Rules......
【Success】Adding <fstat> to the Seccomp Filter [ALLOW]
【Success】Adding <exit_group> to the Seccomp Filter [ALLOW]
 Bad system call
```

并生成审计事件，查看audit.log文件(audit工具Cent OS默认安装，ubantu安装方式：apt install auditd)：

```bash
$ grep helloworld /var/log/audit/audit.log
type=SECCOMP msg=audit(1650345103.252:844): auid=0 uid=0 gid=0 ses=114 pid=1978 comm="helloworld" exe="/root/seccomp-sandbox/helloworld" sig=31 arch=c000003e syscall=1 compat=0 ip=0x7f32ba2e2104 code=0x80000000
type=ANOM_ABEND msg=audit(1650345103.252:845): auid=0 uid=0 gid=0 ses=114 pid=1978 comm="helloworld" exe="/root/seccomp-sandbox/helloworld" sig=31 res=1
```

##### 永久链接

可以在不重新编译代码的情况下将可执行文件永久链接到libsandbox.so，可以避免定义LD_PRELOAD环境变量，直接添加规则即可。

例如：

添加前:

```bash
$ ldd helloworld
	linux-vdso.so.1 (0x00007fffe3bf6000)
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5a2e189000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f5a2e77d000)
```

添加libsandbox.so作为运行依赖项（patchelf需要下载包）：

```bash
$ patchelf --add-needed /usr/lib/x86_64-linux-gnu/libsandbox.so ./helloworld
$ ldd helloworld
	linux-vdso.so.1 (0x00007ffc01575000)
  /usr/lib/x86_64-linux-gnu/libsandbox.so (0x00007f05db85b000)
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f05db46a000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f05dbcab000)
$ Whitelist_mode="fstat write exit_group" ./helloworld
 Initializing Seccomp Rules......
【Success】Adding <fstat> to the Seccomp Filter [ALLOW]
【Success】Adding <write> to the Seccomp Filter [ALLOW]
【Success】Adding <exit_group> to the Seccomp Filter [ALLOW]
Hello, world!
```

#### 静态链接可执行文件

对于静态链接的可执行文件，通过使用沙盒化命令行实用程序启动应用程序来注入沙盒化代码。执行需要把当前目录放到PATH环境下，否则会显示command not found。因为静态链接可执行文件相当于把沙盒化的代码和用户执行代码合并起来，所以seccomp规则必须允许沙盒化代码所需的所有系统调用，否则加载规则后沙盒化代码触犯seccomp规则一样会被内核发送SIGKILL信号杀死进程

```bash
$ export PATH="$PATH:."
$ Whitelist_mode="brk arch_prctl fstat openat close access read mmap mprotect munmap write exit_group" sandboxing.a ./helloworld
 Initializing Seccomp Rules......
【Success】Adding <brk> to the Seccomp Filter [ALLOW]
【Success】Adding <arch_prctl> to the Seccomp Filter [ALLOW]
【Success】Adding <fstat> to the Seccomp Filter [ALLOW]
【Success】Adding <openat> to the Seccomp Filter [ALLOW]
【Success】Adding <close> to the Seccomp Filter [ALLOW]
【Success】Adding <access> to the Seccomp Filter [ALLOW]
【Success】Adding <read> to the Seccomp Filter [ALLOW]
【Success】Adding <mmap> to the Seccomp Filter [ALLOW]
【Success】Adding <mprotect> to the Seccomp Filter [ALLOW]
【Success】Adding <munmap> to the Seccomp Filter [ALLOW]
【Success】Adding <write> to the Seccomp Filter [ALLOW]
【Success】Adding <exit_group> to the Seccomp Filter [ALLOW]
Hello, world!
```



#### 记录模式Log_mode

​    不确定程序执行需要哪些必备的系统调用或者不确定使用什么安全规则的时候，可以使用记录模式。记录模式基于你当前的规则可以将沙盒配置为记录过滤器违规行为，而不是立即终止进程。当设置白名单为空的时候（表示禁止所有系统调用），在记录模式下，会记录程序所有的系统调用，可以得到程序整个运行过程中系统调用情况（由于此模式下触犯规则的进程不会被杀死，因此要确保程序是安全的再使用）

```bash
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so Whitelist_mode="" Log_mode=log ./helloworld
Hello, world!
```

上述过滤器不允许对helloworld应用程序进行任何系统调用，但会记录违规行为，而不是扼杀过程。违规行为可以通过audit监控或审计：

```bash
type=SECCOMP msg=audit(1650348391.617:939): auid=0 uid=0 gid=0 ses=123 pid=2208 comm="helloworld" exe="/root/seccomp-sandbox/helloworld" sig=0 arch=c000003e syscall=5 compat=0 ip=0x7f6955afc773 code=0x7ffc0000
type=SECCOMP msg=audit(1650348391.617:940): auid=0 uid=0 gid=0 ses=123 pid=2208 comm="helloworld" exe="/root/seccomp-sandbox/helloworld" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f6955afd104 code=0x7ffc0000
type=SECCOMP msg=audit(1650348391.617:941): auid=0 uid=0 gid=0 ses=123 pid=2208 comm="helloworld" exe="/root/seccomp-sandbox/helloworld" sig=0 arch=c000003e syscall=231 compat=0 ip=0x7f6955ad1ab6 code=0x7ffc0000
```

上面的示例显示了helloworld文件使用了系统调用5、1和231。通过系统调用号查看系统调用名，可以将数字分别转换为系统调用名称：fstat、write和exit_group。

附系统调用号名查询：

https://www.cnblogs.com/gavanwanggw/p/6920826.html



#### 查看是否启用seccomp规则

可以使用/proc/[pid]/status通过检查输出中的Seccomp字段来验证目标进程是否应用了seccomp策略（0代表没有启用seccomp规则，1代表使用了seccomp_strict模式，2代表使用了seccomp_filter模式，本项目中使用的是filter模式的规则）

```bash
规则加载前：
$ grep Seccomp /proc/self/status
Seccomp:	0

规则加载后：
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so Whitelist_mode="fstat write exit_group" Log_mode=log grep Seccomp /proc/self/status
 Initializing Seccomp Rules......
【Success】Adding <fstat> to the Seccomp Filter [ALLOW]
【Success】Adding <write> to the Seccomp Filter [ALLOW]
【Success】Adding <exit_group> to the Seccomp Filter [ALLOW]
Seccomp:        2
```



#### 参考资料：

http://man7.org/linux/man-pages/man2/seccomp.2.html

https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=

http://man7.org/linux/man-pages/man8/ld.so.8.html

https://man7.org/linux/man-pages/man5/proc.5.html

https://man7.org/linux/man-pages/man2/ptrace.2.html

https://man7.org/linux/man-pages/man2/ptrace.2.html

https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html

https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

https://man7.org/linux/man-pages/man3/seccomp_syscall_resolve_name_rewrite.3.html
