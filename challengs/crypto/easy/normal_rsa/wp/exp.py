import libnum
from Crypto.Util.number import long_to_bytes
from Crypto.Util.number import bytes_to_long


fd = open('./flag.enc', 'rb')
m = fd.read()
c = bytes_to_long(m)
# http://tool.chacuo.net/cryptrsakeyparse
n = 0xC2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
e = 65537
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239

d = libnum.invmod(e, (p - 1) * (q - 1))
s = pow(c, d, n)

print('n: ' + str(n))
print(hex(c))
print(hex(s))

s = hex(s)[3:]
flag = ''
i = 0
for _ in range(int(len(s) / 2)):
	n  = int(s[i + 0], 16) * 0x10
	n += int(s[i + 1], 16)
	flag += chr(n)
	print(hex(n))
	i += 2
print(flag)
