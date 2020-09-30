
code = "cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ"
flag = ''
for i in code:
	flag += chr(ord(i) ^ 0x37)

print(flag)
