from pwn import *
# 逆序数
def getInversion(numlist):
	count = 0
	for i in range(1,len(numlist)):
		subscript = numlist[i]
		for j in range(i):
			if subscript < numlist[j]:
				count += 1
	return count
# 全排列，求每项的积
def permutation(dd,ilist,jlist,index):
	#global D
	D = 0
	term = 0
	for i in range(index,len(jlist)):
		if index == len(jlist)-1:
			term = 1
			for ii in range(len(ilist)):
				i = ilist[ii]
				j = jlist[ii]
				term *= dd[i][j]
		if getInversion(jlist) % 2 == 0:
			D += term
		else:D -= term
		return
	tmp = jlist[index]
	jlist[index] = jlist[i]
	jlist[i] = tmp
	permutation(dd,ilist,jlist,index+1)
	tmp = jlist[index]
	jlist[index] = jlist[i]
	jlist[i] = tmp
	return D
        
r_1 = [0x4f17, 0x9cf6, 0x8ddb, 0x8ea6, 0x6929, 0x9911, 0x40a2]
r_2 = [0x2f3e, 0x62b6, 0x4b82, 0x486c, 0x4002, 0x52d7, 0x2def]
r_3 = [0x28dc, 0x640d, 0x528f, 0x613b, 0x4781, 0x6b17, 0x3237]
r_4 = [0x2a93, 0x615f, 0x50be, 0x598e, 0x4656, 0x5b31, 0x313a]
r_5 = [0x3010, 0x67fe, 0x4d5f, 0x58db, 0x3799, 0x60a0, 0x2750]
r_6 = [0x3759, 0x8953, 0x7122, 0x81f9, 0x5524, 0x8971, 0x3A1d]


v_46 = [12, 83, 78, 39, 23, 27, 4]
v_47 = [53, 85, 53, 78, 6, 85, 6]
v_48 = [6, 12, 24, 52, 14, 92, 3]
v_49 = [34, 73, 36, 9, 74, 42, 67]
v_50 = [58, 27, 86, 62, 48, 48, 0]
v_51 = [36, 96, 25, 37, 12, 15, 26]
v_52 = [1, 52, 46, 84, 83, 72, 68]
rv_1 = [v_46, v_47, v_48, v_49, v_50, v_51, v_52]

def calc(dd):
	jlist = []
	ilist = []
	for ii in range(len(dd)):
		ilist.append(ii)
		jlist.append(ii)
	return permutation(dd,ilist,jlist,0)
	
#flag{7e171d43-63b9-4e18-990e-6e14c2afe648}
if __name__ == '__main__':
	rv = rv_1
	rv [6] = r_6;
	print
	print(hex(calc(rv)));
