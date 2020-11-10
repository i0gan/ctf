# CTF-LINUX-PWN基本环境搭建

由于libc版本问题, 建议使用docker来分别启动不同版本的libc, 虽然pwntools也能解决, 这需要找到对应libc的ld,才能使程序正常运行





## config ubuntu apt

```sh
vim /etc/apt/sources.list
```

### ubuntu16

```

```



### ubuntu18

```

```



## Install base env

```sh
apt install python
apt install python-pip
apt install vim
apt install tmux
```



## config pip

```sh
cd
mkdir .pip
vim .pip/pip.conf
```

输入

```
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
```



## Install pwntools

```sh
pip install pwntools
```



## Install pwndbg

```sh
cd
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
echo "source ~/pwndbg/gdbinit.py" > ~/.gdbinit
```

