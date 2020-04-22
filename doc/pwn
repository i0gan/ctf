gcc 相关参数及意义:
-fstack-protector：启用堆栈保护，不过只为局部变量中含有 char 数组的函数插入保护代码
-fstack-protector-all：启用堆栈保护，为所有函数插入保护代码
-fno-stack-protector：禁用堆栈保护

编译:
命令：gcc -m32 -ggdb -z execstack -fstack-protector -no-pie -o pwnme Cannary.c
-m32 生成32位机器的汇编代码；
-m64则生成64位机器汇编代码；

objdump -d [file_name] | less
方便查看.plt 已存在函数

使用 ./exec_name & 获取进程ID
使用 cat /proc/[proc_ID]/maps 查看对应的内存区
也可以直接用odd 

readelf -s /lib32/libc.so.6 | grep 'gets@'
查看gets@里的地址

killall exec_name
pidof exec_name

gdb里
lay asm (列出汇编)


查找字符串命令
ROPgadget --binary [file_name] --string ['str']
strings -a -t x libc_32.so.6 | grep "/bin/sh"
搜索指令命令:
ROPgadget --binary [file_name] --only "pop|ret"

查看got表
readelf -r [file_name]

使用ldd pwnme,查看libc文件的加载位置是否会变
ldd pwnme
如果改变:
关掉地址随机化保护:
为了调试方便，可以使用：
echo 0 > /proc/sys/kernel/randomize_va_space

查看elf各个段:
	objdump -h [elf_file]
查看elf代码段:
		 [-xsd]
	objdump -x -s -d [elf_file]
查看elf文件elf头:
	readelf -h [elf_file]
查看elf文件程序头:
	readelf -l [elf_file]
查看elf文件中的段:
	readelf -S [elf_file]
查看elf文件中的字符串表:

通常在.strtab段或.shstrtab中:
	readelf -x .strtab [elf_file]

查看elf文件中的符号表: (相当于导入表)
	readelf -s [elf_file]

查看elf文件中的重定位表:
	readelf -r [elf_file]

----------------------------------------------------------------------------
		字符串漏洞:

顾名思义，直接参数访问允许通过使用美元符号$直接存取参数
例如：用%N$d可以访问第N个参数，并且把它以十进制输出
printf("7th:%7$d, 4th:%4$05d \n",10,20,30,40,50,60,70,80);
上述print调用的输出显示如下：
7th: 70, 4th:0040

32位：
读
'%{}$x'.format(index)           // 读4个字节
'%{}$p'.format(index)           // 同上面
'${}$s'.format(index)

写
'%{}$n'.format(index)           // 解引用，写入四个字节
'%{}$hn'.format(index)          // 解引用，写入两个字节
'%{}$hhn'.format(index)         // 解引用，写入一个字节
'%{}$lln'.format(index)         // 解引用，写入八个字节

64位：
读
'%{}$x'.format(index, num)      // 读4个字节
'%{}$lx'.format(index, num)     // 读8个字节
'%{}$p'.format(index)           // 读8个字节
'${}$s'.format(index)

写
'%{}$n'.format(index)           // 解引用，写入四个字节
'%{}$hn'.format(index)          // 解引用，写入两个字节
'%{}$hhn'.format(index)         // 解引用，写入一个字节
'%{}$lln'.format(index)         // 解引用，写入八个字节
 %1$lx: RSI
 %2$lx: RDX
 %3$lx: RCX
 %4$lx: R8
 %5$lx: R9
 %6$lx: 栈上的第一个QWORD
------------------------------------------------------------------------------

-------------------------------------------
Open canary protect:
gcc -fstack-protector-all ..

--------------------------------------------
	ROP呼叫函数
read @plt  |  function call #1
pop3-ret   |  gadget for flushing args
0          |  arg1
addr       |  arg2
length     |  arg3
system @plt|  function call #2
0xdeadbeef 
addr       | arg1

--------------------------------------------
	使用libc里的函数
printf,gets,puts等函数是放在libc.so.6里
可以直接用ROP呼叫libc里的system.即使方程本身没有用到
使用条件
1. libc版本或函数offset要已知
2. ASLR问题,不知道libc里的函数的地址
(ASLR -地址随机化)

-------------------------------------------
	Dynamically Linked ELF 相关操作
1. ldd ./binary   (得知使用的libc路径)
2. readelf -s /lib32/libc.so.6 (检查libc里的sysmbol)
3. LD_LIBRARY_PATH=./path/to/libc .. (指定要载入的libc路径)
注意: /lib/ld-linux.so.2的版本要与 libc.so.2 一样 

-------------------------------------------
	ASLR (Address Space Layout Randomization)
1. Library每次执行加载lib的位置不一样
2. Stack的位置也不一样
3. cat/proc/self/maps

-------------------------------------------
	Funcation Lazy Binding
1. library在binary执行时才会载入
2. 第一次呼叫函数时,解析函数的地址就填入.got.plt里
3. 因为ASLR每次的值会有所不同

-------------------------------------------
	推算Libc Base Address
1. 函数在libc中的相对位置不会变
2. 使用readelf得知__libc_stat_main和system在libc里的距离差
3. 使用任何输出函数印出__libc_start_main.got 里的内容,推算system在记忆里的地址
4. 用ROP叠出puts(__libc_stat_main@got)
5.要leak的got entry,对应的函数必须已被呼叫过
(前提:已有或已知道远程端libc.so.6的版本)

-------------------------------------------



