------------------------------------------------------------
安装libc.
从官网下载:
https://ftp.gnu.org/gnu/libc/
https://ftp.gnu.org/gnu/libc/glibc-2.19.tar.gz

# tar -xzvf glibc-2.19.tar.gz
# cd glibc-2.19

# pwd
/usr/lib-u/glibc-2.19

# mkdir build
# cd build

带debug sysmbols编译
# CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" ../configure --prefix=/usr/lib-u/glibc-2.19/64

# make -j8
# make install
# export LD_LIBRRARY_PATH=[your_libc_path]
必须保证ld(链接)的版本与libc的版本一致

------------------------------------------------------------
	Heap相关的漏洞:
	Use after free:
	Double free:
	Heap overflow:
gdb 中 lay src 查看源码

malloc源码: https://code.woboq.org/userspace/glibc/malloc/malloc.c.html
heap的资料记录在一个struct mallc_state中,称为main_arena
-----------------------------
在gdb中查看main_arena:
运行之后:
# p main_arena
查看bin中的第一个chunk
p &main_arena.bins [0]
查看局部变量:
info locals
查看top_chunk位置:
p mian_arena .top
里面的值就相当于剩余的空间大小

-----------------------------

malloc分配的记忆体称为chunk,会比要求的大小要大一点,因为需要记录一些维护heap用的额外信息
Arena与heap分配的chunk分开存放,heap overflow没办法直接去覆盖掉它的内容

回收的chunk用linked list 记录,称为bin
main_arena中会有很多个bin,每个bin里储存chunk size不同,目的时让malloc时可以最快找到适合大小的chunk
回收的chunk会以据size来决定应该放在哪个linked list(bin)中

-----------------------------
main_arena{
	bin[0] (size=16) -> chunk1 -> chunk5
	bin[1] (size=32) -> chunk2 -> chunk3 -> chunk4
	bin[2] (size=48) ->
}
-----------------------------

1. malloc时,事先对bin里面找出可以使用chunk,如果找不到才会真正分配新的chunk给程序使用
分配时可以去找到足够打的chunk只切出需要的部分,剩下的部分形成新的chunk(last_remainder).

2. 找不到可用空间时会对top chunk分配,top chunk是一个很大的chunk,代表可使用但未分配
chunk的内存,malloc分配时会对里面切一小块下来,剩下的部分重新设为top
main_arena{
	mchunkptr top -> top_chunk;
	mchunkptr last_remainder;
}

-----------------------------
	Chunk
存放chunk metadata的chunk节点(header)
struct malloc_chunk{
	size_t prev_size;
	size_t size;
	malloc_chunk* fd;
	malloc_chunk* bk;
	malloc_chunk* fd_nextsize;
	malloc_chunk* bk_nextsize;
}

(64bit): mem = malloc(size)
-> chunk = mem-0x10; chunksize = (mallocsize+8)#16 (对齐到16的倍数)
chunk的位置是malloc的地址- 0x10
chunksize是size + 8后向上对齐16的倍数
	
	Chunk Header
size:这个是chunk的真正大小,非malloc size
fd,bk:指向bin里的前一,后一个chunk
 一般来说bin是一个double linked list
prev_size:前一个chunk size,维护heap时可以得知前一个chunk的位置

gdb中转型查看chunk:
p/x *(struct malloc_chunk*)0xaddr

		Size(64bit)
size包含chunk size和flag bits
1.chunk size 会包含size和上一个的标志prev_inuse bits (3bits) (flag bits)
	fastbin <= 128
	smallbin < 1024
	largebin
	mmap >= 0x20000
最低bit为prev_inuse bit,用来表示[前一个]chunk是不是使用中
free会使下一个chunk的prev_inust bit 设为0

	
		Heap操作
p = malloc(size)
 找出一个可用的chunk,或者top chunk切一块来使用
 如果这个chunk是回收的,要先对bin里面unlink进行检查,即移除linkedlist
 填好,

free(p)
 检查一下该chunk地址前的chunk,是不是not inuse
 如果有,则这些回收的chunk可以被合并为一块
 合并后新的chunk,放回对应的bin中




