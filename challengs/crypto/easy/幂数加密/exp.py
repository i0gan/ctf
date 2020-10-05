
code = '8842101220480224404014224202480122'

cs = code.split('0')
flag = ''
s = 0
for i in cs:
	sum = 0
	for j in i:
		sum += int(j, 10)
	flag += chr(sum + 64)

print(flag)
