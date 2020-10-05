import libnum

p = 473398607161
q = 4511491
e = 17

d = libnum.invmod(e, (p - 1) * (q - 1))
print(d)
