

def pr(n):
    if(n == 0):
        return 'i'
    elif(n == 1):
        return 'e'
    elif(n == 3):
        return 'n'
    elif(n == 4):
        return 'd'
    elif(n == 5):
        return 'a'
    elif(n == 6):
        return 'g'
    elif(n == 7):
        return 's'
    elif(n == 9):
        return 'r'
    return '  No'
num = []
def loop(n):
    global num
    if(n == 10):
        return 
    else:
        a = 7 * (n + 1) % 11
        num.append(a)
        loop(a)
loop(0)
flag = 'i'
for i in num:
    flag += pr(i)
print(flag)
