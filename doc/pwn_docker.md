---
title: pwn_docker
author: I0gan
date: 2020-09-11 00:15:05
tags: pwn-env
categories: pwn
---

 # Pwn Docker环境搭建



之前一直都是在ubuntu14 ~ ubuntu18虚拟机中进行调试, 若不是常见的libc就比较麻烦,而且虚拟机安装后比较占磁盘还有管理不太方便, 环境有时候崩溃的话,就比较再次难以搭建, 为了解决以上问题, pwn docker完美解决, 且提供了大量ctf pwn工具, 以python3来进行脚本编写, 更加符合目前的pwn演变趋势....



## 包含的软件

- pwntools —— CTF framework and exploit development library
- gdb-peda —— Python Exploit Development Assistance for GDB
- Pwngdb —— GDB for pwn
- ROPgadget —— facilitate ROP exploitation tool
- roputils —— A Return-oriented Programming toolkit
- linux_server[x64] —— IDA 6.8 debug server for linux
- tmux —— a terminal multiplexer
- ltrace —— trace library function call
- strace —— trace system call



## github

https://github.com/shenyuan123/pwndocker



## 拉取镜像

Docker hub地址：https://hub.docker.com/r/skysider/pwndocker/

```
docker pull skysider/pwndocker
```



## 创建docker 网络

```
sudo docker network create-subnet=192.168.222.0/24docker_net
```



## 运行

```
docker run -it --name=pwn --net docker_net skysider/pwndocker bash
```





## 编写docker pwn 启动管理脚本

```
#! /bin/bash
# author: i0gan
if [[ $1 == 'init' ]];then
	sudo docker run --network=host -d --name=pwn -v /home/logan/share:/ctf/work skysider/pwndocker
elif [[ $1 == 'exec' ]];then
	sudo docker exec -it pwn bash
elif [[ $1 == 'start' ]];then
	sudo docker start pwn
elif [[ $1 == 'stop' ]];then
	sudo docker stop pwn
else
	echo "nothing to do"
fi
```



## 配置源

备份源

```
cp /etc/apt/sources.list /etc/apt/sources.list.bk
```

将一下内容覆盖到/etc/apt/sources.list中

```
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-security main restricted universe multiverse
```

更新list

```
apt update
```





## 安装 tmux

```
apt install tmux
```

#### 会话外操作

​	 tmux new -s <name-of-my-session> 在会话外创建一个新的会话
​	tmux ls   在会话外获取会话列表
​	tmux a（attach） -t <name-of-my-session>   在会话外进入会话，不带名字进入第一个会话
​	tmux kill-session -t <name-of-my-session>  在会话外删除会话


上面的操作是在普通命令行下操作的，所以不用按前缀键。下面的都是在tmux中操作的，所以需要按前缀键，默认是ctrl-b；在tmux中，输入冒号是开启命令行

#### 基本操作

​	?	列出所有快捷键；按q返回
​	d	脱离当前会话,可暂时返回Shell界面，输入tmux attach能够重新进入之前会话
​	s	选择并切换会话；在同时开启了多个会话时使用
​	D	选择要脱离的会话；在同时开启了多个会话时使用
​	:	进入命令行模式；此时可输入支持的命令，例如kill-server所有tmux会话
​	[	复制模式，光标移动到复制内容位置，空格键开始，方向键选择复制，回车确认，q/Esc退出
​	]	进入粘贴模式，粘贴之前复制的内容，按q/Esc退出
​	~	列出提示信息缓存；其中包含了之前tmux返回的各种提示信息
​	t	显示当前的时间 

#### 会话操作

:new -s <name-of-my-new-session>    进入会话后创建新的会话
 	s   列出会话，进行选择
 	:kill-session    删除当前会话
 	:kill-server     删除所有会话

#### 窗口操作

​	c	创建新窗口
​	&	关闭当前窗口
​	数字键	切换到指定窗口
​	p	切换至上一窗口
​	n	切换至下一窗口
​	l	前后窗口间互相切换
​	w	通过窗口列表切换窗口
​	,	重命名当前窗口，便于识别
​	.	修改当前窗口编号，相当于重新排序
​	f	在所有窗口中查找关键词，便于窗口多了切换

#### 面板操作

​	“	将当前面板上下分屏
​	%	将当前面板左右分屏
​	x	关闭当前分屏
​	z	tmux 1.8新特性，最大化当前所在面板，重复一遍返回
​	!	将当前面板置于新窗口,即新建一个窗口,其中仅包含当前面板
​	Ctrl+方向键	以1个单元格为单位移动边缘以调整当前面板大小
​	Alt+方向键	以5个单元格为单位移动边缘以调整当前面板大小
​	空格键	可以在默认面板布局中切换，试试就知道了
​	q	显示面板编号
​	o	选择当前窗口中下一个面板
​	方向键	移动光标选择对应面板
​	{	向前置换当前面板
​	}	向后置换当前面板
​	Alt+o	逆时针旋转当前窗口的面板
​	Ctrl+o	顺时针旋转当前窗口的面板





## libc searcher 使用

./get 下载get工具, 若已下载请直接跳过

./add usr/lib/libc-2.21-so 向数据库中添加自定义 libc

./find __libc_start_main xxx 这里输入你要查找的函数的真实地址的后三位

./dump xxx 转储一些有用的偏移量，给出一个 libc id, 这里输入第三步得到的结果中id后的libc库

这样你就可以得到需要的文件中的偏移地址了

[网页libc searcher](https://libc.blukat.me/)







## exp预备脚本

```
#!/usr/bin/env python3
#-*- coding:utf-8 -*-
# author: i0gan
# env: pwndocker [skysider/pwndocker (v: 2020/09/09)]

from pwn import *

context.log_level='debug'

elf_path  = 'pwn'
ld_path   = '/glibc/' + '2.23/64/' + 'libld-2.23.so'
libc_path = '/glibc/' + '2.23/64/' + 'lib/libc-2.23.so'

# remote server ip and port
server_ip = "0.0.0.0"
server_port = 0

# if local debug
LOCAL = 1
LIBC  = 1

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)
#--------------------------func-----------------------------


#--------------------------exploit--------------------------
def exploit():
	li('exploit...')

def finish():
	ia()
	c()

#--------------------------main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		elf = ELF(elf_path)
		if LIBC:
			libc = ELF(libc_path)
			io = elf.process([ld_path, elf_path], env = {"LD_PRELOAD" : libc_path})
		else:
			io = elf.process()
	
	else:
		elf = ELF(elf_path)
		io = remote(server_ip, server_port)
		if LIBC:
			libc = ELF(libc_path)
	
	exploit()
	finish()
```





[pwn docker 环境参考](https://e3pem.github.io/2019/04/19/%E6%9D%82%E9%A1%B9/%E5%9C%A8docker%E4%B8%AD%E6%90%AD%E5%BB%BApwn%E7%8E%AF%E5%A2%83/)