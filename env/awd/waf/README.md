# AWD PWN WAF



waf原理, 创建子进程打开目标elf, 然后父进程使用ptrace监测子进程的syscall调用,  若是标准io, 那么读取io中的数据, 记录在log里, 若是危险的syscall, 也记录在log里.



##  如何使用

目录:

src ------------------waf.c (waf程序源代码)

​     -------------------show_waf.c (打印waf程序源代码)

show_waf (将waf的二进制以c语言数组方式打印出来, 方便直接用waf再次攻打)

ch              (快速修改只运行脚本)

pwn           (编译好的64位 waf程序)



建议: 在上流量之前, 要得把原来的pwn文件命名为elf文件

在src/waf.c中

```
#define ELF_PATH "./elf" // trace elf path
#define LOG_PATH "./log" // path to log
#define ARCH 64          // 64 or 32
```

ELF_PATH: 是监测的elf文件

LOG_PATH: 写入log的路径

ARCH: 32为程序或64位程序

### 编译

进入src目录

```
make
```



## 实例

这里有个2020强网杯的easypwn作为例子:

exp已经打通, 

将easypwn 命名为elf, 将waf.c编译好的程序copy到easypwn中, 命名为pwn

那么打exp中, 打开的程序就为pwn, 接着就会有log生成

打的log如下(这里只贴一部分):

```
...
...
-------------------- write -----------------                                                                                            
done                                                                                                                                    
1.add                                                                                                                                   
2.edit                                                                                                                                  
3.delete                                                                                                                                
Your choice:                                                                                                                                                                                                                                                      
-------------------- read ------------------                                                                                            
1                                                                                                                                      
-------------------- write -----------------
size:

-------------------- read ------------------
16

!!!!!!!!!!!!! dangerous syscall !!!!!!!!!!!!

!!!!!!!!!!!!! dangerous syscall !!!!!!!!!!!!

!!!!!!!!!!!!! dangerous syscall !!!!!!!!!!!!


...
...

```

如果出现一串 !!!!!!!!!!!!! dangerous syscall !!!!!!!!!!!! 字样的话,  基本上你的服务器已经被打了...





