# rev100



```
00400080  68 66 6C 00 00 48 BF 01  00 00 00 00 00 00 00 48
00400090  8D 34 24 48 BA 02 00 00  00 00 00 00 00 48 B8 01
004000A0  00 00 00 00 00 00 00 0F  05 68 61 67 00 00 48 BF
004000B0  01 00 00 00 00 00 00 00  48 8D 34 24 48 BA 02 00
004000C0  00 00 00 00 00 00 48 B8  01 00 00 00 00 00 00 00
004000D0  0F 05 68 7B 70 00 00 48  BF 01 00 00 00 00 00 00
004000E0  00 48 8D 34 24 48 BA 02  00 00 00 00 00 00 00 48
004000F0  B8 01 00 00 00 00 00 00  00 0F 05 68 6F 70 00 00
00400100  48 BF 01 00 00 00 00 00  00 00 48 8D 34 24 48 BA
00400110  02 00 00 00 00 00 00 00  48 B8 01 00 00 00 00 00
00400120  00 00 0F 05 68 70 6F 00  00 48 BF 01 00 00 00 00
00400130  00 00 00 48 8D 34 24 48  BA 02 00 00 00 00 00 00
00400140  00 48 B8 01 00 00 00 00  00 00 00 0F 05 68 70 72
00400150  00 00 48 BF 01 00 00 00  00 00 00 00 48 8D 34 24
00400160  48 BA 02 00 00 00 00 00  00 00 48 B8 01 00 00 00
00400170  00 00 00 00 0F 05 68 65  74 00 00 48 BF 01 00 00
00400180  00 00 00 00 00 48 8D 34  24 48 BA 02 00 00 00 00
00400190  00 00 00 48 B8 01 00 00  00 00 00 00 00 0F 05 68
004001A0  7D 0A 00 00 48 BF 01 00  00 00 00 00 00 00 48 8D
004001B0  34 24 48 BA 02 00 00 00  00 00 00 00 48 B8 01 00
004001C0  00 00 00 00 00 00 0F 05  48 31 FF 48 B8 3C 00 00
004001D0  00 00 00 00 00 0F 05                            
```

Restore as c then write to bin

```c
#include <stdio.h> 

unsigned char buf[] = 
 {0x68 ,0x66 ,0x6C ,0x00 ,0x00 ,0x48 ,0xBF ,0x01  ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48
 ,0x8D ,0x34 ,0x24 ,0x48 ,0xBA ,0x02 ,0x00 ,0x00  ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0xB8 ,0x01
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0F  ,0x05 ,0x68 ,0x61 ,0x67 ,0x00 ,0x00 ,0x48 ,0xBF
 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,0x48 ,0x8D ,0x34 ,0x24 ,0x48 ,0xBA ,0x02 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0xB8  ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00
 ,0x0F ,0x05 ,0x68 ,0x7B ,0x70 ,0x00 ,0x00 ,0x48  ,0xBF ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00
 ,0x00 ,0x48 ,0x8D ,0x34 ,0x24 ,0x48 ,0xBA ,0x02  ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48
 ,0xB8 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,0x00 ,0x0F ,0x05 ,0x68 ,0x6F ,0x70 ,0x00 ,0x00
 ,0x48 ,0xBF ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x48 ,0x8D ,0x34 ,0x24 ,0x48 ,0xBA
 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,0x48 ,0xB8 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00
 ,0x00 ,0x00 ,0x0F ,0x05 ,0x68 ,0x70 ,0x6F ,0x00  ,0x00 ,0x48 ,0xBF ,0x01 ,0x00 ,0x00 ,0x00 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x48 ,0x8D ,0x34 ,0x24 ,0x48  ,0xBA ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00
 ,0x00 ,0x48 ,0xB8 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x00 ,0x0F ,0x05 ,0x68 ,0x70 ,0x72
 ,0x00 ,0x00 ,0x48 ,0xBF ,0x01 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0x8D ,0x34 ,0x24
 ,0x48 ,0xBA ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x48 ,0xB8 ,0x01 ,0x00 ,0x00 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0F ,0x05 ,0x68 ,0x65  ,0x74 ,0x00 ,0x00 ,0x48 ,0xBF ,0x01 ,0x00 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0x8D ,0x34  ,0x24 ,0x48 ,0xBA ,0x02 ,0x00 ,0x00 ,0x00 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x48 ,0xB8 ,0x01 ,0x00 ,0x00  ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0F ,0x05 ,0x68
 ,0x7D ,0x0A ,0x00 ,0x00 ,0x48 ,0xBF ,0x01 ,0x00  ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0x8D
 ,0x34 ,0x24 ,0x48 ,0xBA ,0x02 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0xB8 ,0x01 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0F ,0x05  ,0x48 ,0x31 ,0xFF ,0x48 ,0xB8 ,0x3C ,0x00 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0F ,0x05};

 int main() {
	FILE *fd = fopen("a.bin", "wb");
	fwrite(buf, 1, sizeof(buf), fd);
	fclose(fd);
	return 0;
 }
```



Open it whit ida64, we can found flag


```
seg000          segment byte public 'CODE' use64
seg000:0000000000000000                 assume cs:seg000
seg000:0000000000000000                 assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
seg000:0000000000000000                 push    'lf'
seg000:0000000000000005                 mov     rdi, 1
seg000:000000000000000F                 lea     rsi, [rsp]
seg000:0000000000000013                 mov     rdx, 2
seg000:000000000000001D                 mov     rax, 1
seg000:0000000000000027                 syscall                 ; Low latency system call
seg000:0000000000000029                 push    'ga'
seg000:000000000000002E                 mov     rdi, 1
seg000:0000000000000038                 lea     rsi, [rsp]
seg000:000000000000003C                 mov     rdx, 2
seg000:0000000000000046                 mov     rax, 1
seg000:0000000000000050                 syscall                 ; Low latency system call
seg000:0000000000000052                 push    'p{'
seg000:0000000000000057                 mov     rdi, 1
seg000:0000000000000061                 lea     rsi, [rsp]
seg000:0000000000000065                 mov     rdx, 2
seg000:000000000000006F                 mov     rax, 1
seg000:0000000000000079                 syscall                 ; Low latency system call
seg000:000000000000007B                 push    'po'
seg000:0000000000000080                 mov     rdi, 1
seg000:000000000000008A                 lea     rsi, [rsp]
seg000:000000000000008E                 mov     rdx, 2
seg000:0000000000000098                 mov     rax, 1
seg000:00000000000000A2                 syscall                 ; Low latency system call
seg000:00000000000000A4                 push    'op'
seg000:00000000000000A9                 mov     rdi, 1
seg000:00000000000000B3                 lea     rsi, [rsp]
seg000:00000000000000B7                 mov     rdx, 2
seg000:00000000000000C1                 mov     rax, 1
seg000:00000000000000CB                 syscall                 ; Low latency system call
seg000:00000000000000CD                 push    'rp'
seg000:00000000000000D2                 mov     rdi, 1
seg000:00000000000000DC                 lea     rsi, [rsp]
seg000:00000000000000E0                 mov     rdx, 2
seg000:00000000000000EA                 mov     rax, 1
seg000:00000000000000F4                 syscall                 ; Low latency system call
seg000:00000000000000F6                 push    'te'
seg000:00000000000000FB                 mov     rdi, 1
seg000:0000000000000105                 lea     rsi, [rsp]
seg000:0000000000000109                 mov     rdx, 2
seg000:0000000000000113                 mov     rax, 1
seg000:000000000000011D                 syscall                 ; Low latency system call
seg000:000000000000011F                 push    0A7Dh
seg000:0000000000000124                 mov     rdi, 1
seg000:000000000000012E                 lea     rsi, [rsp]
seg000:0000000000000132                 mov     rdx, 2
seg000:000000000000013C                 mov     rax, 1
seg000:0000000000000146                 syscall                 ; Low latency system call
seg000:0000000000000148                 xor     rdi, rdi
seg000:000000000000014B                 mov     rax, 3Ch
seg000:0000000000000155                 syscall                 ; Low latency system call
seg000:0000000000000155 seg000          ends
```



flag{poppopret}

