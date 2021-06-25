# 如何修改elf中段的权限

在ida中Edit->Segments->Edit Segments可以修改权限，但发现没有打patch，导出的程序与修改之前一样。

下面基于32为改段权限的一个工具代码改成了64位的，方便以后修洞时给.eh_frame段增加可执行权限。

测试 babyRe

这里以一个elf64位的程序为例

```
readelf -l babyRe 
```

输出

```
Elf file type is DYN (Shared object file)
Entry point 0x1090
There are 11 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x0000000000000268 0x0000000000000268  R      0x8
  INTERP         0x00000000000002a8 0x00000000000002a8 0x00000000000002a8
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000648 0x0000000000000648  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x000000000000051d 0x000000000000051d  RWE    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x0000000000000220 0x0000000000000220  R      0x1000
  LOAD           0x0000000000002de8 0x0000000000003de8 0x0000000000003de8
                 0x0000000000000268 0x0000000000000270  RW     0x1000
  DYNAMIC        0x0000000000002df8 0x0000000000003df8 0x0000000000003df8
                 0x00000000000001e0 0x00000000000001e0  RW     0x8
  NOTE           0x00000000000002c4 0x00000000000002c4 0x00000000000002c4
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x00000000000020b4 0x00000000000020b4 0x00000000000020b4
                 0x0000000000000044 0x0000000000000044  RW     0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002de8 0x0000000000003de8 0x0000000000003de8
                 0x0000000000000218 0x0000000000000218  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .plt.got .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame 
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss 
   06     .dynamic 
   07     .note.gnu.build-id .note.ABI-tag 
   08     .eh_frame_hdr 
   09     
   10     .init_array .fini_array .dynamic .got 
```

修改sn为8的段，也就是上面的 .eh_frame_hdr 段

```
./elfmsp babyRe 8 rwx
```



```
This file modified!
```



再次查看

```
readelf -l babyRe 
```



```
Elf file type is DYN (Shared object file)
Entry point 0x1090
There are 11 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x0000000000000268 0x0000000000000268  R      0x8
  INTERP         0x00000000000002a8 0x00000000000002a8 0x00000000000002a8
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000648 0x0000000000000648  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x000000000000051d 0x000000000000051d  RWE    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x0000000000000220 0x0000000000000220  R      0x1000
  LOAD           0x0000000000002de8 0x0000000000003de8 0x0000000000003de8
                 0x0000000000000268 0x0000000000000270  RW     0x1000
  DYNAMIC        0x0000000000002df8 0x0000000000003df8 0x0000000000003df8
                 0x00000000000001e0 0x00000000000001e0  RW     0x8
  NOTE           0x00000000000002c4 0x00000000000002c4 0x00000000000002c4
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x00000000000020b4 0x00000000000020b4 0x00000000000020b4
                 0x0000000000000044 0x0000000000000044  RWE    0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002de8 0x0000000000003de8 0x0000000000003de8
                 0x0000000000000218 0x0000000000000218  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .plt.got .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame 
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss 
   06     .dynamic 
   07     .note.gnu.build-id .note.ABI-tag 
   08     .eh_frame_hdr 
   09     
   10     .init_array .fini_array .dynamic .got 
```



GNU_EH_FRAME段有X权限。







通过调试发现，gdb中该段发现没有rwx，则是由于内存对齐造成的，我们只需要在0x1000倍数起始位置的段赋予权限即可。

```
./elfsmp babyRe 4 rwx
```




再次调试:
```

pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
            0x1000             0x3000 r-xp     2000 0      <explored>
    0x555555554000     0x555555555000 r--p     1000 0      /home/i0gan/Downloads/re/babyRe
    0x555555555000     0x555555557000 rwxp     2000 1000   /home/i0gan/Downloads/re/babyRe
    0x555555557000     0x555555558000 r--p     1000 2000   /home/i0gan/Downloads/re/babyRe
    0x555555558000     0x555555559000 rwxp     1000 3000   /home/i0gan/Downloads/re/babyRe
    0x7ffff7dc5000     0x7ffff7dc7000 rw-p     2000 0
    0x7ffff7dc7000     0x7ffff7ded000 r--p    26000 0      /usr/lib/libc-2.33.so
    0x7ffff7ded000     0x7ffff7f38000 r-xp   14b000 26000  /usr/lib/libc-2.33.so
    0x7ffff7f38000     0x7ffff7f84000 r--p    4c000 171000 /usr/lib/libc-2.33.so
    0x7ffff7f84000     0x7ffff7f87000 r--p     3000 1bc000 /usr/lib/libc-2.33.so
    0x7ffff7f87000     0x7ffff7f8a000 rw-p     3000 1bf000 /usr/lib/libc-2.33.so
    0x7ffff7f8a000     0x7ffff7f95000 rw-p     b000 0
    0x7ffff7fc7000     0x7ffff7fcb000 r--p     4000 0      [vvar]
    0x7ffff7fcb000     0x7ffff7fcd000 r-xp     2000 0      [vdso]
```


进入到了我们的段，这样就不会出现段错误了。
```

   0x5555555551a3 <main+46>                  lea    rax, [rip + 0xf0a] <0x5555555560b4>
   0x5555555551aa <main+53>                  jmp    rax
    ↓
   0x5555555560b4 <__GNU_EH_FRAME_HDR>       lea    rsi, [rip - 0x7e]
   0x5555555560bb <__GNU_EH_FRAME_HDR+7>     lea    rsi, [rip - 0x11]
   0x5555555560c2 <__GNU_EH_FRAME_HDR+14>    nop
 ► 0x5555555560c3 <__GNU_EH_FRAME_HDR+15>    ret    <0x7fffffffdef8>

   0x5555555560c4 <__GNU_EH_FRAME_HDR+16>    nop
   0x5555555560c5 <__GNU_EH_FRAME_HDR+17>    nop
   0x5555555560c6 <__GNU_EH_FRAME_HDR+18>    nop
   0x5555555560c7 <__GNU_EH_FRAME_HDR+19>    nop
   0x5555555560c8 <__GNU_EH_FRAME_HDR+20>    nop

```







## 源代码

elfmsp.c

```c
// ref: https://seclists.org/vuln-dev/2002/Jan/3
// Modify the segment's permission flag in elf, surport the arch 32 or 64
// Modified by i0gan
// Date: 2021-06-09
// Project Name: elfmsp
// gcc elfmsp.c -o elfmsp
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int mod_elf32(void *pcFileAddr, int iSegNo, unsigned long ulPerm) {
    char sElfMagic[] = "\x7f" "ELF";
    Elf32_Ehdr *ptElf32Hdr;
    Elf32_Phdr *ptElf32PHdr;
    ptElf32Hdr = (Elf32_Ehdr *) pcFileAddr;
    if (memcmp(&(ptElf32Hdr->e_ident), sElfMagic, sizeof(sElfMagic) - 1)) {
        fprintf(stderr, "This file does not appear to be an 64 ELF file\n");
        return 0;
    }

    /* Does this file have the segment they requested?                 */
    if ((iSegNo < 0) || (iSegNo >= ptElf32Hdr->e_phnum)) {
        printf("Segment %d does not exist in the executable, e_phnum: %d\n", iSegNo, ptElf32Hdr->e_phnum);
        return 0;
    }
    /* Get the segment header for the specified segment                */
    ptElf32PHdr = (Elf32_Phdr *) ((char *) pcFileAddr + ptElf32Hdr->e_phoff +
                                (ptElf32Hdr->e_phentsize * iSegNo));
    /* Set the permissions as specified                                */
    ptElf32PHdr->p_flags = ulPerm;
    return 1;
}

int mod_elf64(void *pcFileAddr, int iSegNo, unsigned long ulPerm) {
    char sElfMagic[] = "\x7f" "ELF";
    Elf64_Ehdr *ptElf64Hdr;
    Elf64_Phdr *ptElf64PHdr;
    ptElf64Hdr = (Elf64_Ehdr *) pcFileAddr;
    if (memcmp(&(ptElf64Hdr->e_ident), sElfMagic, sizeof(sElfMagic) - 1)) {
        fprintf(stderr, "This file does not appear to be an 64 ELF file\n");
        return 0;
    }

    /* Does this file have the segment they requested?                 */
    if ((iSegNo < 0) || (iSegNo >= ptElf64Hdr->e_phnum)) {
        printf("Segment %d does not exist in the executable, e_phnum: %d\n", iSegNo, ptElf64Hdr->e_phnum);
        return 0;
    }
    /* Get the segment header for the specified segment                */
    ptElf64PHdr = (Elf64_Phdr *) ((char *) pcFileAddr + ptElf64Hdr->e_phoff +
                                (ptElf64Hdr->e_phentsize * iSegNo));
    /* Set the permissions as specified                                */
    ptElf64PHdr->p_flags = ulPerm;
    return 1;
}

/* Change the permissions on a segment */
int main(int argc, char *argv[]) {
    char *sInFile;
    int iSegNo, iInFd, i;
    char *pcFileAddr;
    struct stat tStatBuf;
    off_t tMapSize;
    unsigned long ulPerm = 0;

    if (argc != 4) {
        fprintf(stderr, "Usage: elfmsp <elf file> <segment no> <segment permissions (e.g rwx)>\n", argv[0]);
        exit(1);
    }

    i = 0;

    while (argv[3][i]) {
       switch(argv[3][i]) {
          case 'x':
             ulPerm |= PF_X;
          case 'r':
             ulPerm |= PF_R;
          case 'w':
             ulPerm |= PF_W;
       }
       i++;
    }

    sInFile = argv[1];
    iSegNo = atoi(argv[2]);
    if (-1 == (iInFd = open(sInFile, O_RDWR))) {
        fprintf(stderr, "Could not open %s, %d %s\n", sInFile, errno, strerror(errno));
        exit(-1);
    }
    if (fstat(iInFd, &tStatBuf)) {
        fprintf(stderr, "Could not stat %s, %d %s\n", sInFile, errno, strerror(errno));
        close(iInFd);
        exit(-1);
    }
    tMapSize = tStatBuf.st_size;

    if (!(pcFileAddr = mmap(0, tMapSize, PROT_READ | PROT_WRITE, MAP_SHARED, iInFd, 0))) { fprintf(stderr, "Could not mmap %s, %d %s\n", sInFile, errno, strerror(errno));
        close(iInFd);
        exit(-1);
    }

    //printf("File %s mapped at %p for %lu bytes\n", sInFile, pcFileAddr, tMapSize);
 
    int ret = 0;
    // check arch is 32
    if(pcFileAddr[4] == 0x01) {
        ret = mod_elf32(pcFileAddr, iSegNo, ulPerm);
    }else if(pcFileAddr[4] == 0x02) { // 64
        ret = mod_elf64(pcFileAddr, iSegNo, ulPerm);
    }else {
        puts("arch error");
    }

    if(ret = 1) {
        puts("This file modified!");
    }

    munmap(pcFileAddr, tMapSize);
    close(iInFd);
    return (0);
}

```
