import libnum
c = 0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35 # result
n = 103461035900816914121390101299049044413950405173712170434161686539878160984549 # 
e = 65537
p = 282164587459512124844245113950593348271
q = 366669102002966856876605669837014229419

# http://www.factordb.com/index.php
d = libnum.invmod(e, (p - 1) * (q - 1))
m = pow(c, d, n)

s = hex(m)[2:]
i = 0
t = ''
for _ in range(int(len(s) / 2)):
	n  = int(s[i + 0], 16) * 0x10
	n += int(s[i + 1], 16)
	t += chr(n)
	i += 2

print(t)

