 # Kernel pwn 环境搭建



## 编译内核

去官网下载一份kernel内核源码, 这里就采用[2.6.32](https://mirrors.edge.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.tar.gz)版本。我采用docker 下的ubuntu16.04进行编译内核, 编译内核前需要拥有特定的版本的make和gcc, g++

获取不同版本的内核:

[获取](https://mirrors.edge.kernel.org/pub/linux/kernel/)



### 安装特定的编译器

```
sudo apt install gcc-4.7 g++-4.7
sudo ln -s /usr/bin/gcc-4.7 /usr/bin/gcc
sudo ln -s /usr/bin/g++-4.7 /usr/bin/g++
```



### 安装必备依赖

```
sudo apt-get install build-essential libncurses5-dev
```



### 获取内核代码

```
mkdir kernel
cd kernel
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.tar.gz
tar xzvf linux-2.6.32.tar.gz
```



### 获取特定的make

```
wget https://mirrors.tuna.tsinghua.edu.cn/gnu/make/make-3.80.tar.gz
tar -xvf make-3.80.tar.gz
cd make-3.80/
./configure
make
```



### 修改三处 2.6 源码文件

* 1.arch/x86/vdso/Makefile 中第 28 行的 -m elf_x86_64 改成 -m64，第 72 行的-m elf_i386 改成-m32
* 2.drivers/net/igbvf/igbvf.h 中注释第 128 行
* 3.kernel/timeconst.pl 中第 373 行 defined(@val) 改成 @val
* 4.（可选）关闭 canary 保护需要编辑源码中的.config 文件 349 行，注释掉 CONFIG_CC_STACKPROTECTOR=y 这一项



### 配置kernel

进入 kernel hacking，勾选 Kernel debugging，Compile-time checks and  compiler options–>Compile the kernel with debug info，Compile the  kernel with frame pointers 和 KGDB



### 编译

```
../make-3.80/make bzImage
```



### 编译时遇到的问题

#### 问题1

```
fatal error: linux/compiler-gcc5.h: No such file or directory
```

解决:

```
拷贝一个自己目录下的compiler-gcc4.h到compiler-gcc5.h
```

#### 问题2

```
implicit declaration of function 'tty_port_users'
```

解决:

将所提示的该函数extern关键字去掉



### 编译成功

编译成功之后提示如下:

```
Root device is (0, 78)
Setup is 13688 bytes (padded to 13824 bytes).
System is 3961 kB
CRC e70b803a
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

vmlinux 在源码根目录下，bzImage 在arch/x86/boot/下



## 启动内核

### 获取busybox

```
wget https://busybox.net/downloads/busybox-1.27.2.tar.bz2
tar -jxvf busybox-1.27.2.tar.bz2
```



### 配置busybox

```
cd busybox-1.27.2
make menuconfig
```

勾选 Busybox Settings -> Build Options -> Build Busybox as a static binary



### 编译并安装busybox

```
make
make install
```



### 打包镜像

编译完成后源码目录下会有一个_install 文件夹

```
cd _install
mkdir -pv {bin,sbin,etc,proc,sys,usr/{bin,sbin}}
mkdir etc/init.d
touch etc/init.d/init
```

编辑 etc/inittab 文件，加入以下内容（这一步可以省略）

```
::sysinit:/etc/init.d/rcS
::askfirst:/bin/ash
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
```

编辑 etc/init.d/rcS 文件，加入以下内容

```
#!/bin/sh
mount -t proc none /proc
mount -t sys none /sys
/bin/mount -n -t sysfs none /sys
/bin/mount -t ramfs none /dev
/sbin/mdev -s
```

接着就可以打包成 rootfs.cpio

```
chmod +x ./etc/init.d/rcS
find . | cpio -o --format=newc > ../rootfs.cpio
```



## 运行镜像

### 安装qemu

```
apt install qemu
```



得到这三个vmlinux,bzImage,rootfs.cpio 文件后，可以利用 qemu 运行起来，启动脚本 boot

```
#!/bin/sh
qemu-system-x86_64 \
 -initrd rootfs.cpio \
 -kernel bzImage \
 -nographic \
 -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" \
 -m 64M \
 -monitor /dev/null \
```



启动成功如下

```
Please press Enter to activate this console. [    3.379764] async/1 used greatest stack depth: 5064 bytes left
/bin/ash: can't access tty; job control turned off
/ # ls
bin      etc      proc     sbin     usr
```



## 编写与打开内核驱动

### 内核驱动c代码编写

```
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
int hello_write(struct file *file, const char *buf, unsigned long len) {
    printk("You write something.");
    return len;
}
static int __init hello_init(void) {
    printk(KERN_ALERT "hello driver init!\n");
    create_proc_entry("hello", 0666, 0)->write_proc = hello_write;
    return 0;
}
static void __exit hello_exit(void) {
    printk(KERN_ALERT "hello driver exit\n");
}
module_init(hello_init);
module_exit(hello_exit);
```

保存为hello.c



### Makefile编写

注意, Makefile中 obj-m 中的名字要与保存c代码的文件名相同

```
obj-m := hello.o
KERNELDR := /home/kernel/linux-2.6.32
PWD := $(shell pwd)
modules:
        $(MAKE) -C $(KERNELDR) M=$(PWD) modules
modules_install:
        $(MAKE) -C $(KERNELDR) M=$(PWD) modules_install
clean:
        $(MAKE) -C $(KERNELDR) M=$(PWD) clean
```

make 出来后得到.ko 文件



### 编写打开程序

命名为call.c

```
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
int main() {
    int fd = open("/proc/hello", O_WRONLY);
    write(fd, "I0gan", 5);
    return 0;
}
```



### 编译

```
gcc --static call.c -o call
```

将hello.ko与call两个文件复制到busybox下的_install目录下重新打包得到rootfs.cpio, 把该文件复制到启动目录下, 重新运行./boot



### 启动自己的内核驱动

#### 挂载驱动

```
insmod hello.ko
```

输出如下

```
[   75.062554] hello: module license 'unspecified' taints kernel.
[   75.063843] Disabling lock debugging due to kernel taint
[   75.074570] hello driver init!
```



#### 调用打开自己的驱动

```
/ # ./call 
[   79.011811] You write something./ 
```

上面打印了You write somthing说明已经打开了我们的驱动, 那么到这基本上已经差不多了 ^_^